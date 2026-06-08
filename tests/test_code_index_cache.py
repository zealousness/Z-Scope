import builtins
from copy import deepcopy
from pathlib import Path

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
    assert index._file_lines_cache == {}
    assert index._function_impl_cache == {}
    assert index._declaration_comment_index is None


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
