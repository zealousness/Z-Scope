import builtins
import os
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from zscope.retrieval.code_index import CodeIndex


class FakeBackend:
    def __init__(self, source_path: Path) -> None:
        self.source_path = source_path
        self.callee_calls = 0
        self.closed = False

    def build_function_index(self):
        return {
            "cached_api": {
                "file": str(self.source_path),
                "start_line": 3,
                "end_line": 5,
                "signature": "int cached_api(int value)",
            }
        }

    def get_method(self, name: str):
        return None

    def get_method_callees(self, name: str, limit: int = 30):
        self.callee_calls += 1
        return [{"name": "helper"}]

    def close(self) -> None:
        self.closed = True


class MultiFunctionBackend:
    def __init__(self, function_index):
        self.function_index = function_index

    def build_function_index(self):
        return self.function_index

    def get_method(self, name: str):
        return None

    def get_method_callees(self, name: str, limit: int = 30):
        return []

    def close(self) -> None:
        pass


class FailingAsyncBackend(MultiFunctionBackend):
    def __init__(self):
        super().__init__({})
        self.closed = False

    def wait_for_ready(self, timeout=None):
        return False

    def close(self) -> None:
        self.closed = True


class EmptyReadyBackend(MultiFunctionBackend):
    _status = "ready"

    def __init__(self):
        super().__init__({})


def _write_source(tmp_path: Path) -> Path:
    source_path = tmp_path / "demo.c"
    source_path.write_text(
        """int helper(void) { return 1; }

int cached_api(int value) {
    return helper() + value;
}
""",
        encoding="utf-8",
    )
    return source_path


def test_function_impl_cache_reuses_file_content_and_returns_isolated_results(
    tmp_path,
    monkeypatch,
) -> None:
    source_path = _write_source(tmp_path)
    backend = FakeBackend(source_path)
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    real_open = builtins.open
    source_abs = source_path.absolute()
    read_counts = {"source": 0}

    def counting_open(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        try:
            is_source = Path(path).absolute() == source_abs
        except TypeError:
            is_source = False
        if is_source and "r" in mode:
            read_counts["source"] += 1
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", counting_open)

    first = index.get_function_impl("cached_api", warn_missing=False)
    assert first is not None
    expected = deepcopy(first)

    first["callees"].append("polluted")
    first["comment_blocks"].append({"kind": "polluted"})

    second = index.get_function_impl("cached_api", warn_missing=True)

    assert second == expected
    assert second is not first
    assert read_counts["source"] == 1
    assert backend.callee_calls == 1

    snippet = index.get_file_snippet(str(source_path), 1, 1)
    assert snippet is not None
    assert read_counts["source"] == 1

    index.close()
    assert backend.closed is True


def test_source_cache_reloads_replacement_with_preserved_size_and_mtime(tmp_path) -> None:
    source_path = _write_source(tmp_path)
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=FakeBackend(source_path))
    try:
        first = index.get_function_impl("cached_api", warn_missing=False)
        assert first is not None
        original = source_path.stat()
        replacement = tmp_path / "replacement.c"
        replacement.write_text(
            source_path.read_text(encoding="utf-8").replace("helper() + value", "helper() - value"),
            encoding="utf-8",
        )
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(source_path)
        assert source_path.stat().st_size == original.st_size
        assert source_path.stat().st_mtime_ns == original.st_mtime_ns

        second = index.get_function_impl("cached_api", warn_missing=False)
        assert second is not None
        assert "helper() - value" in second["code"]
        snippet = index.get_file_snippet(str(source_path), 3, 5)
        assert snippet is not None
        assert "helper() - value" in snippet["code"]
    finally:
        index.close()


def test_shared_source_cache_is_bounded_by_bytes(tmp_path) -> None:
    source_path = _write_source(tmp_path)
    backend = FakeBackend(source_path)
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=backend,
        indexing_config=SimpleNamespace(
            backend="clang",
            shared_cache_max_bytes=64,
        ),
    )

    result = index.get_function_impl("cached_api", warn_missing=False)

    assert result is not None
    assert index._shared_cache_bytes <= 64
    assert len(index._file_lines_cache) + len(index._function_impl_cache) <= 1


def test_code_index_reports_regex_fallback_as_degraded(tmp_path) -> None:
    backend = FailingAsyncBackend()
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=backend,
        wait_for_cpg=False,
    )

    assert index.ensure_index_ready(timeout=1) is True

    capabilities = index.capability_status()
    assert capabilities["index"]["configured"] == "joern"
    assert capabilities["index"]["active"] == "regex"
    assert capabilities["index"]["status"] == "degraded"
    assert capabilities["index"]["reason"] == "configured_backend_unavailable_regex_fallback"
    assert backend.closed is True
    assert index._file_lines_cache == {}
    assert index._function_impl_cache == {}
    assert index._declaration_comment_index is None


def test_code_index_reports_empty_backend_index_fallback_as_degraded(tmp_path) -> None:
    source_path = tmp_path / "fallback.c"
    source_path.write_text("int fallback_entry(void) { return 0; }\n", encoding="utf-8")

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=EmptyReadyBackend(),
    )

    capabilities = index.capability_status()
    assert index.get_function_impl("fallback_entry", warn_missing=False) is not None
    assert capabilities["index"]["status"] == "degraded"
    assert capabilities["index"]["active"].endswith("+regex")
    assert (
        capabilities["index"]["reason"]
        == "configured_backend_index_empty_regex_fallback"
    )


def test_file_snippet_applies_explicit_and_implicit_line_limits(tmp_path) -> None:
    source_path = tmp_path / "snippet.c"
    source_path.write_text(
        "".join(f"line_{line}\n" for line in range(1, 601)),
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    omitted = index.get_file_snippet("snippet.c", 1, None)
    invalid = index.get_file_snippet("snippet.c", 1, 0)
    explicit = index.get_file_snippet("snippet.c", 1, 600)
    narrowed = index.get_file_snippet("snippet.c", 1, 300, max_lines=25)

    assert omitted is not None
    assert omitted["end_line"] == 50
    assert len(omitted["code"].splitlines()) == 50
    assert omitted["total_lines"] == 600
    assert omitted["truncated"] is False
    assert invalid is not None
    assert invalid["end_line"] == 50
    assert explicit is not None
    assert explicit["end_line"] == 500
    assert len(explicit["code"].splitlines()) == 500
    assert explicit["truncated"] is True
    assert narrowed is not None
    assert narrowed["end_line"] == 25
    assert narrowed["truncated"] is True


def test_file_snippet_end_line_past_eof_reads_to_eof(tmp_path) -> None:
    # An end_line beyond the file end is a "read to the end of the file"
    # request: it must clamp to EOF within the hard max_lines ceiling instead
    # of silently falling back to the short default window, and the result
    # must report total_lines plus a truncated flag.
    source_path = tmp_path / "eof.c"
    source_path.write_text(
        "".join(f"line_{line}\n" for line in range(1, 601)),
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    to_eof = index.get_file_snippet("eof.c", 100, 999999)

    assert to_eof is not None
    assert to_eof["total_lines"] == 600
    assert to_eof["end_line"] == 599  # start + max_lines - 1
    assert to_eof["truncated"] is True  # EOF still lies beyond the 500-line cap
    assert len(to_eof["code"].splitlines()) == 500
    assert to_eof["code"].splitlines()[0].startswith("100 |")

    exact = index.get_file_snippet("eof.c", 10, 20)
    assert exact is not None
    assert exact["end_line"] == 20
    assert exact["truncated"] is False
    assert len(exact["code"].splitlines()) == 11

    small_path = tmp_path / "small.c"
    small_path.write_text(
        "".join(f"s{line}\n" for line in range(1, 31)),
        encoding="utf-8",
    )
    tail = index.get_file_snippet("small.c", 25, 999999)
    assert tail is not None
    assert tail["total_lines"] == 30
    assert tail["end_line"] == 30
    assert tail["truncated"] is False


def test_function_impl_supports_unbounded_source_for_semantic_modeling(tmp_path) -> None:
    source_path = tmp_path / "long.c"
    body_lines = ["int long_function(void) {\n"]
    body_lines.extend(f"    int value_{line} = {line};\n" for line in range(1, 550))
    body_lines.extend(["    return semantic_modeler_tail_marker;\n", "}\n"])
    source_path.write_text("".join(body_lines), encoding="utf-8")

    backend = MultiFunctionBackend(
        {
            "long_function": {
                "file": str(source_path),
                "start_line": 1,
                "end_line": len(body_lines),
                "signature": "int long_function(void)",
            }
        }
    )
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    limited = index.get_function_impl("long_function", max_lines=500)
    complete = index.get_function_impl("long_function", max_lines=None)

    assert limited is not None
    assert limited["truncated"] is True
    assert "semantic_modeler_tail_marker" not in limited["code"]
    assert complete is not None
    assert complete["truncated"] is False
    assert complete["end_line"] == len(body_lines)
    assert "semantic_modeler_tail_marker" in complete["code"]


def test_code_index_ensures_linux_nofile_limit(tmp_path, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        "zscope.retrieval.code_index.ensure_linux_nofile_limit",
        lambda: calls.append("called"),
    )

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=MultiFunctionBackend({}),
        wait_for_cpg=False,
    )

    assert calls == ["called"]
    index.close()


def test_function_impl_without_context_skips_comment_scan_and_callee_query(
    tmp_path,
    monkeypatch,
) -> None:
    source_path = _write_source(tmp_path)
    backend = FakeBackend(source_path)
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    with_context = index.get_function_impl("cached_api", include_context=True)
    assert with_context is not None
    assert with_context["callees"] == ["helper"]

    def fail_comment_scan(*args, **kwargs):
        raise AssertionError("include_context=False should not scan declaration comments")

    def fail_callee_query(*args, **kwargs):
        raise AssertionError("include_context=False should not query callees")

    monkeypatch.setattr(index, "_find_function_declaration_comments", fail_comment_scan)
    monkeypatch.setattr(backend, "get_method_callees", fail_callee_query)

    result = index.get_function_impl("cached_api", include_context=False)

    assert result is not None
    assert result["callees"] == []
    assert result["comment_blocks"] == []


def test_function_impl_rejects_backend_header_prototype_without_body(tmp_path) -> None:
    header = tmp_path / "internal" / "plugin.ph"
    header.parent.mkdir(parents=True)
    header.write_text(
        "extern int _plugin_register(\n"
        "    PluginRegistry* registry,\n"
        "    const char* name\n"
        ");\n",
        encoding="utf-8",
    )
    backend = MultiFunctionBackend(
        {
            "_plugin_register": {
                "name": "_plugin_register",
                "file": "internal/plugin.ph",
                "start_line": 1,
                "end_line": 4,
                "signature": "extern int _plugin_register(...)",
            }
        }
    )
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    assert index.get_function_impl("_plugin_register", warn_missing=False) is None


def test_function_impl_prefers_backend_macro_definitions(tmp_path, monkeypatch) -> None:
    header = tmp_path / "include" / "macros.h"
    header.parent.mkdir(parents=True)
    header.write_text("#define DB_ALLOC(sz) alloc(sz)\n", encoding="utf-8")

    class MacroBackend(MultiFunctionBackend):
        def __init__(self):
            super().__init__({})
            self.macro_calls = 0

        def get_macro_definitions(self, name: str, limit: int = 20):
            self.macro_calls += 1
            if name != "DB_ALLOC":
                return []
            return [
                {
                    "name": "DB_ALLOC",
                    "file_path": "include/macros.h",
                    "line": 1,
                    "definition": "#define DB_ALLOC(sz) alloc(sz)\n",
                    "is_function_like": 1,
                }
            ]

    backend = MacroBackend()
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    def fail_fallback(*args, **kwargs):
        raise AssertionError("backend macro hit should not use regex fallback")

    monkeypatch.setattr(index, "_get_macro_definition_index", fail_fallback)

    result = index.get_function_impl("DB_ALLOC", warn_missing=False)

    assert result is not None
    assert result["is_macro"] is True
    assert result["signature"] == "#define DB_ALLOC(sz)"
    assert result["file"].replace("\\", "/") == "include/macros.h"
    assert result["callees"] == ["alloc"]
    assert backend.macro_calls == 1


def test_macro_fallback_negative_cache_avoids_repeated_index_lookup(
    tmp_path, monkeypatch
) -> None:
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )
    calls = {"count": 0}
    real_get_index = index._get_macro_definition_index

    def counting_get_index():
        calls["count"] += 1
        return real_get_index()

    monkeypatch.setattr(index, "_get_macro_definition_index", counting_get_index)

    assert index.get_function_impl("MISSING_MACRO", warn_missing=False) is None
    assert index.get_function_impl("MISSING_MACRO", warn_missing=False) is None
    assert calls["count"] == 1


def test_macro_fallback_respects_exclude_paths(tmp_path) -> None:
    include_dir = tmp_path / "include"
    excluded_dir = tmp_path / "excluded"
    include_dir.mkdir()
    excluded_dir.mkdir()
    (include_dir / "allowed.h").write_text("#define ALLOWED_MACRO 1\n", encoding="utf-8")
    (excluded_dir / "hidden.h").write_text("#define HIDDEN_MACRO 1\n", encoding="utf-8")

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
        include_paths=[include_dir, excluded_dir],
        exclude_paths=[excluded_dir],
    )

    allowed = index.get_function_impl("ALLOWED_MACRO", warn_missing=False)

    assert allowed is not None
    assert allowed["is_macro"] is True
    assert index.get_function_impl("HIDDEN_MACRO", warn_missing=False) is None


def test_find_all_files_scans_each_root_once_and_keeps_filtering(
    tmp_path,
    monkeypatch,
) -> None:
    src_dir = tmp_path / "src"
    nested_dir = src_dir / "nested"
    excluded_dir = src_dir / "excluded"
    nested_dir.mkdir(parents=True)
    excluded_dir.mkdir()
    allowed_source = src_dir / "allowed.c"
    allowed_header = nested_dir / "allowed.hpp"
    allowed_inc = nested_dir / "allowed.inc"
    ignored_text = nested_dir / "ignored.txt"
    hidden_source = excluded_dir / "hidden.c"
    for path in [allowed_source, allowed_header, allowed_inc, ignored_text, hidden_source]:
        path.write_text("int x;\n", encoding="utf-8")

    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
        include_paths=[src_dir, tmp_path],
        exclude_paths=[excluded_dir],
        wait_for_cpg=False,
    )

    path_type = type(tmp_path)
    original_rglob = path_type.rglob
    calls = []

    def counting_rglob(self, pattern):
        calls.append((Path(self).resolve(), pattern))
        yield from original_rglob(self, pattern)

    monkeypatch.setattr(path_type, "rglob", counting_rglob)

    files = {Path(path).resolve() for path in index._find_all_files()}

    assert files == {
        allowed_source.resolve(),
        allowed_header.resolve(),
        allowed_inc.resolve(),
    }
    # src_dir is nested inside tmp_path, so the contained root is dropped and
    # only the covering root is walked; files and filters are unaffected.
    assert [pattern for _, pattern in calls] == ["*"]


def test_macro_fallback_returns_multiline_function_like_macro(tmp_path) -> None:
    header = tmp_path / "include" / "macros.h"
    header.parent.mkdir()
    header.write_text(
        "#define ALLOC_WRAP(sz) \\\n"
        "    alloc(sz) \\\n"
        "    + 1\n",
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    result = index.get_function_impl("ALLOC_WRAP", warn_missing=False)

    assert result is not None
    assert result["is_macro"] is True
    assert result["signature"] == "#define ALLOC_WRAP(sz)"
    assert result["start_line"] == 1
    assert result["end_line"] == 3
    assert "1 | #define ALLOC_WRAP(sz)" in result["code"]
    assert "3 |     + 1" in result["code"]
    assert result["callees"] == ["alloc"]


def test_file_scoped_function_lookup_avoids_full_path_scan(tmp_path, monkeypatch) -> None:
    target_path = tmp_path / "src" / "target.c"
    target_path.parent.mkdir(parents=True)
    target_path.write_text("int Target(void) { return 7; }\n", encoding="utf-8")
    function_index = {
        f"Unrelated{idx}": {
            "name": f"Unrelated{idx}",
            "file": f"other/file_{idx}.c",
            "start_line": 1,
            "end_line": 1,
            "signature": f"int Unrelated{idx}(void)",
        }
        for idx in range(3000)
    }
    function_index["Target"] = {
        "name": "Target",
        "file": "src/target.c",
        "start_line": 1,
        "end_line": 1,
        "signature": "int Target(void)",
    }
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=MultiFunctionBackend(function_index))
    real_match = index._paths_match_hint
    calls = {"count": 0}

    def counting_match(stored_path, hint_path):
        calls["count"] += 1
        return real_match(stored_path, hint_path)

    monkeypatch.setattr(index, "_paths_match_hint", counting_match)

    result = index.get_function_impl(
        "Target",
        file_path="src/target.c",
        include_context=False,
    )

    assert result is not None
    assert result["file"].replace("\\", "/") == "src/target.c"
    assert calls["count"] < 20


def test_file_scoped_lookup_keeps_same_basename_paths_distinct(tmp_path) -> None:
    left_path = tmp_path / "src" / "a" / "shared.c"
    right_path = tmp_path / "src" / "b" / "shared.c"
    left_path.parent.mkdir(parents=True)
    right_path.parent.mkdir(parents=True)
    left_path.write_text("int Target(void) { return 1; }\n", encoding="utf-8")
    right_path.write_text("int Target(void) { return 2; }\n", encoding="utf-8")
    backend = MultiFunctionBackend(
        {
            "TargetLeft": {
                "name": "Target",
                "file": "src/a/shared.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            },
            "TargetRight": {
                "name": "Target",
                "file": "src/b/shared.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            },
        }
    )
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    result = index.get_function_impl(
        "Target",
        file_path="src/b/shared.c",
        include_context=False,
    )

    assert result is not None
    assert result["file"].replace("\\", "/") == "src/b/shared.c"
    assert "return 2" in result["code"]


def test_file_resolution_cache_clears_on_index_rebuild(tmp_path) -> None:
    first_path = tmp_path / "src" / "first.c"
    second_path = tmp_path / "src" / "second.c"
    first_path.parent.mkdir(parents=True)
    first_path.write_text("int Target(void) { return 1; }\n", encoding="utf-8")
    second_path.write_text("int Target(void) { return 2; }\n", encoding="utf-8")
    backend = MultiFunctionBackend(
        {
            "Target": {
                "name": "Target",
                "file": "src/first.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            },
        }
    )
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    first = index.get_function_impl(
        "Target",
        file_path="src/first.c",
        include_context=False,
    )
    assert first is not None
    assert index._function_file_resolution_cache

    backend.function_index = {
        "Target": {
            "name": "Target",
            "file": "src/second.c",
            "start_line": 1,
            "end_line": 1,
            "signature": "int Target(void)",
        },
    }
    index._build_index()

    assert index._function_file_resolution_cache == {}
    second = index.get_function_impl(
        "Target",
        file_path="src/second.c",
        include_context=False,
    )
    assert second is not None
    assert second["file"].replace("\\", "/") == "src/second.c"


def test_function_impl_uses_unique_fallback_and_reuses_canonical_cache(tmp_path) -> None:
    source = tmp_path / "src" / "target.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Target(int value) { return value; }\n", encoding="utf-8")
    backend = MultiFunctionBackend(
        {
            "Target": {
                "name": "Target",
                "file": "src/target.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(int value)",
            }
        }
    )
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    fallback = index.get_function_impl(
        "Target@src/target.c:10-20",
        include_context=False,
    )
    exact = index.get_function_impl(
        "Target@src/target.c:1-1",
        include_context=False,
    )

    assert fallback is not None
    assert exact == fallback
    assert fallback["index_name"] == "Target@src/target.c:1-1"
    assert len(index._function_impl_cache) == 1


def test_code_index_canonicalizes_windows_paths_to_project_relative_posix(tmp_path) -> None:
    project_root = tmp_path / "project"
    source_root = project_root / "src"
    source = source_root / "nested" / "target.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Target(void) { return 7; }\n", encoding="utf-8")
    windows_absolute_path = str(source).replace("/", "\\")
    backend = MultiFunctionBackend(
        {
            "Target": {
                "name": "Target",
                "file": windows_absolute_path,
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            }
        }
    )
    index = CodeIndex(project_root, source_root=source_root, backend=backend)

    info = index.find_function_infos("Target")[0]
    impl = index.get_function_impl("Target", include_context=False)
    snippet = index.get_file_snippet("src\\nested\\target.c", 1, 1)

    assert info["file_path"] == "src/nested/target.c"
    assert info["index_name"] == "Target@src/nested/target.c:1-1"
    assert impl is not None
    assert impl["file"] == "src/nested/target.c"
    assert snippet is not None
    assert snippet["file"] == "src/nested/target.c"
    assert index.get_function_location("Target") == "src/nested/target.c:1-1"
    assert "\\" not in info["index_name"]


def test_function_impl_rejects_ambiguous_derived_fallback(tmp_path) -> None:
    left = tmp_path / "src" / "a.c"
    right = tmp_path / "src" / "b.c"
    left.parent.mkdir(parents=True)
    left.write_text("int Target(int left) { return left; }\n", encoding="utf-8")
    right.write_text("int Target(int right) { return right; }\n", encoding="utf-8")
    backend = MultiFunctionBackend(
        {
            "TargetLeft": {
                "name": "Target",
                "file": "src/a.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(int left)",
            },
            "TargetRight": {
                "name": "Target",
                "file": "src/b.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(int right)",
            },
        }
    )
    index = CodeIndex(tmp_path, source_root=tmp_path, backend=backend)

    ambiguous = index.get_function_impl(
        "Target(int)",
        include_context=False,
        warn_missing=False,
    )
    simple = index.get_function_impl(
        "Target",
        include_context=False,
        warn_missing=False,
    )

    assert ambiguous is None
    assert simple is not None
    assert simple["index_name"] == "Target@src/a.c:1-1"


def test_function_impl_uses_fallback_name_for_backend_lookup(tmp_path) -> None:
    source = tmp_path / "src" / "target.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Target(int value) { return value; }\n", encoding="utf-8")

    class LazyBackend(MultiFunctionBackend):
        def __init__(self):
            super().__init__({})
            self.method_queries = []

        def get_method(self, name: str):
            self.method_queries.append(name)
            if name != "Target":
                return None
            return {
                "name": "Target",
                "filename": "src/target.c",
                "lineNumber": 1,
                "lineNumberEnd": 1,
                "signature": "int Target(int value)",
            }

    backend = LazyBackend()
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=backend,
        wait_for_cpg=False,
    )

    result = index.get_function_impl(
        "Target(int)",
        include_context=False,
        warn_missing=False,
    )

    assert result is not None
    assert result["index_name"] == "Target@src/target.c:1-1"
    assert backend.method_queries == ["Target(int)", "Target"]
