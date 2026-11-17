"""Regression coverage for public compatibility tools outside the six-tool registry."""

import sqlite3
from types import SimpleNamespace

import pytest

from zscope.tools.call_graph import GetCallGraphTool
from zscope.tools.deep_call_context import GetDeepCallContextTool
from zscope.tools.file_snippet import GetFileSnippetTool
from zscope.tools.function_info import GetFunctionInfoTool
from zscope.tools.list_functions import ListFunctionsTool
from zscope.tools.pointer_alias import QueryPointerAliasTool
from zscope.tools.security_semantics import GetSecuritySemanticsTool
from zscope.tools.snapshot_tool import GetFunctionSnapshotTool
from zscope.tools.taint_reachability import VerifyTaintReachabilityTool
from zscope.tools.taint_tool import FollowTaintTool
from zscope.retrieval.code_index import CodeIndex


def test_metadata_only_provider_does_not_require_the_older_info_method():
    class Index:
        def find_function_metadata(self, name, file_path=""):
            return [{"function_name": name, "file_path": file_path}]

    result = GetFunctionInfoTool(Index()).execute({"func_name": "ns::f(int)"})
    assert result["data"]["matches"] == [{"function_name": "ns::f(int)", "file_path": ""}]


def test_snapshot_resolver_receives_exact_overload_identity():
    queries = []

    def resolve(name, file):
        queries.append((name, file))
        return {"success": True, "data": None}

    tool = GetFunctionSnapshotTool(object(), resolver=resolve)
    tool.execute({"func_name": "ns::f(int)", "file_path": "src/a.cpp"})
    assert queries == [("ns::f(int)", "src/a.cpp")]


@pytest.mark.parametrize("arguments", [{"limit": 0}, {"limit": -1}, {"offset": -1}])
def test_function_listing_cannot_turn_invalid_pagination_into_an_unbounded_query(arguments):
    class Index:
        def list_functions(self, **kwargs):
            pytest.fail("Invalid pagination must not query the index")

    assert not ListFunctionsTool(Index()).execute(arguments)["success"]


def test_function_listing_probes_one_extra_row_in_one_query():
    calls = []

    class Index:
        def list_functions(self, pattern=None, limit=50, offset=0):
            calls.append((pattern, limit, offset))
            return [f"f{i}" for i in range(12)][offset : offset + limit]

    result = ListFunctionsTool(Index()).execute({"limit": 5, "offset": 2})
    assert calls == [(None, 6, 2)]
    assert result["data"]["functions"] == ["f2", "f3", "f4", "f5", "f6"]
    assert result["data"]["truncated"]


class GraphIndex:
    def get_callers(self, name, limit):
        return []

    def get_callees(self, name, limit):
        graph = {"root": ["a", "shared"], "a": ["shared"], "shared": ["tail"], "tail": ["leaf"]}
        return [{"name": value, "filename": "a.c"} for value in graph.get(name, [])][:limit]


def test_call_graph_revisits_a_node_when_a_shorter_path_leaves_more_depth():
    result = GetCallGraphTool(GraphIndex()).execute({"func_name": "root", "depth": 3})
    assert "leaf" in [row["name"] for row in result["data"]["callees"]]


def test_call_graph_distinguishes_an_exact_limit_from_actual_truncation():
    result = GetCallGraphTool(GraphIndex()).execute({"func_name": "tail", "limit": 1})
    assert result["data"]["callees"][0]["name"] == "leaf"
    assert "truncated" not in result["data"]


def test_call_graph_preserves_exact_query_and_bounds_recursion():
    queries = []

    class Index(GraphIndex):
        def get_callees(self, name, limit):
            queries.append(name)
            return []

    tool = GetCallGraphTool(Index())
    assert tool.execute({"func_name": "ns::f(int)"})["success"]
    assert queries == ["ns::f(int)"]
    assert not tool.execute({"func_name": "root", "depth": 10000})["success"]
    assert queries == ["ns::f(int)"]


def test_deep_context_queries_and_labels_taint_as_a_project_sample():
    queries = []

    class Backend:
        def get_taint_bugs(self, bug_type="", limit=50):
            queries.append((bug_type, limit))
            return [{"source_func": "other", "bug_type": "leak"}]

    index = GraphIndex()
    index.backend = Backend()
    result = GetDeepCallContextTool(index).execute({"func_name": "target"})
    assert queries == [("", 21)]
    assert result["data"]["taint_scope"] == "project"
    assert result["data"]["taint_bugs"][0]["source_func"] == "other"
    assert set(result["data"]["unavailable_sections"]) == {"indirect_callees", "method_info"}


@pytest.mark.parametrize("tool_class", [QueryPointerAliasTool, VerifyTaintReachabilityTool])
def test_missing_backend_capability_is_not_a_successful_empty_analysis(tool_class):
    result = tool_class(object()).execute({"func_name": "f"})
    assert result["success"] is False
    assert result["status"] == "unavailable"


def test_taint_placeholder_reports_unsupported_instead_of_a_result():
    result = FollowTaintTool(object()).execute({"variable": "x", "location": "a.c:1"})
    assert result["success"] is False
    assert result["status"] == "unavailable"


def test_empty_file_is_a_valid_first_line_snippet(tmp_path):
    path = tmp_path / "empty.c"
    path.touch()
    index = SimpleNamespace(
        resolve_existing_file=lambda name: path, get_file_line_count=lambda p: 0
    )
    tool = GetFileSnippetTool(index)
    assert tool.validate_arguments({"file_path": "empty.c", "start_line": 1}) is None
    assert tool.validate_arguments({"file_path": "empty.c", "start_line": 2})["success"] is False


def test_project_snippet_reads_only_allowed_source_with_secure_path_resolution(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "normal.c").write_text("first\nsecond\n", encoding="utf-8")
    (root / "empty.c").touch()
    excluded = root / "excluded"
    excluded.mkdir()
    (excluded / "skip.c").write_text("excluded source", encoding="utf-8")
    outside = tmp_path / "outside.c"
    outside.write_text("SYNTHETIC_PRIVATE_OUTSIDE", encoding="utf-8")
    (root / "link.c").symlink_to(outside)
    index = CodeIndex(root, exclude_paths=[excluded])
    try:
        tool = GetFileSnippetTool(index)
        for path in (str(outside), "../outside.c", "link.c", "excluded/skip.c"):
            arguments = {"file_path": path, "start_line": 1}
            assert tool.validate_arguments(arguments)["success"] is False
            result = tool.execute(arguments)
            assert result["success"] is False
            assert "SYNTHETIC_PRIVATE_OUTSIDE" not in str(result)
        arguments = {"file_path": "normal.c", "start_line": 1, "end_line": 2}
        assert tool.validate_arguments(arguments) is None
        assert tool.execute(arguments)["data"]["code"] == "1 | first\n2 | second\n"
        assert tool.execute({"file_path": "empty.c", "start_line": 1})["data"] == {
            "file": "empty.c",
            "start_line": 1,
            "end_line": 0,
            "code": "",
            "total_lines": 0,
            "truncated": False,
        }
    finally:
        index.close()


def test_snippet_without_a_project_root_retains_custom_provider_delegation():
    calls = []

    class Index:
        def get_file_snippet(self, path, start, end):
            calls.append((path, start, end))
            return {"code": "provider-owned source"}

    result = GetFileSnippetTool(Index()).execute({"file_path": "/provider/a.c", "start_line": 4})
    assert result["success"]
    assert calls == [("/provider/a.c", 4, None)]


def test_project_snippet_validation_does_not_read_or_format_source(tmp_path, monkeypatch):
    (tmp_path / "normal.c").write_text("source\n", encoding="utf-8")
    tool = GetFileSnippetTool(SimpleNamespace(project_root=tmp_path))
    reads = []
    original_read = tool.source_access.read

    def read(path):
        reads.append(path)
        return original_read(path)

    monkeypatch.setattr(tool.source_access, "read", read)
    arguments = {"file_path": "normal.c", "start_line": 1}
    assert tool.validate_arguments(arguments) is None
    assert reads == []
    assert tool.execute(arguments)["data"]["code"] == "1 | source\n"
    assert reads == ["normal.c"]
    for start in (-1, 0):
        invalid = {"file_path": "normal.c", "start_line": start}
        assert tool.validate_arguments(invalid)["success"] is False
        assert tool.execute(invalid)["success"] is False
    assert reads == ["normal.c"]


@pytest.mark.parametrize("separator", ["\u2028", "\v", "\f"])
def test_project_snippet_uses_physical_source_lines(tmp_path, separator):
    first_line = f"before{separator}after\r\n"
    (tmp_path / "normal.c").write_bytes((first_line + "second\n").encode("utf-8"))
    tool = GetFileSnippetTool(SimpleNamespace(project_root=tmp_path))
    first = tool.execute({"file_path": "normal.c", "start_line": 1, "end_line": 1})
    assert first["data"]["total_lines"] == 2
    assert first["data"]["code"] == f"1 | {first_line}"
    second = tool.execute({"file_path": "normal.c", "start_line": 2})
    assert second["data"]["code"] == "2 | second\n"


def test_private_security_map_loader_preserves_missing_database_semantics(tmp_path):
    tool = GetSecuritySemanticsTool(tmp_path / "missing.db")
    assert tool._load_latest_map(project_id="", revision="") is None


@pytest.mark.parametrize("payload", [None, "SYNTHETIC_PRIVATE_INVALID_JSON", "{}"])
def test_security_map_distinguishes_missing_from_corrupt_content(tmp_path, payload):
    path = tmp_path / "map.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE security_maps(payload_json TEXT, updated_at TEXT)")
        if payload is not None:
            conn.execute("INSERT INTO security_maps VALUES (?, 'today')", (payload,))
    result = GetSecuritySemanticsTool(path).execute({"kind": "summary"})
    if payload is None:
        assert result["success"] and result["status"] == "missing"
    else:
        assert not result["success"] and result["status"] == "error"
        assert "SYNTHETIC_PRIVATE" not in str(result)


def test_security_map_closes_connection_even_when_query_fails(tmp_path, monkeypatch):
    path = tmp_path / "map.db"
    path.touch()

    class Connection:
        closed = False

        def execute(self, *args):
            raise sqlite3.DatabaseError("SYNTHETIC_PRIVATE_DATABASE_BODY")

        def close(self):
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(
        "zscope.tools.security_semantics.sqlite3.connect", lambda *a, **k: connection
    )
    result = GetSecuritySemanticsTool(path).execute({"kind": "summary"})
    assert result["success"] is False and result["error_type"] == "DatabaseError"
    assert connection.closed
    assert "SYNTHETIC_PRIVATE" not in str(result)
