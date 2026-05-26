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
