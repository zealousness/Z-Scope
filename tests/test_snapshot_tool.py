from zscope.snapshots.store import SnapshotStore
from zscope.tools.snapshot_tool import GetFunctionSnapshotTool


class FakeCodeIndex:
    def __init__(self, matches):
        self.matches = list(matches)

    def find_function_infos(self, func_name, file_path=""):
        candidates = [
            item
            for item in self.matches
            if func_name in {item["function_name"], item["index_name"]}
        ]
        if file_path:
            candidates = [item for item in candidates if item["file_path"] == file_path]
        return candidates

    def get_function_impl(self, func_name, **kwargs):
        file_path = str(kwargs.get("file_path") or "")
        for item in self.matches:
            if func_name not in {item["function_name"], item["index_name"]}:
                continue
            if file_path and item["file_path"] != file_path:
                continue
            return {
                "func_name": item["function_name"],
                "index_name": item["index_name"],
                "file": item["file_path"],
                "start_line": item["start_line"],
                "end_line": item["end_line"],
                "code": item["code"],
            }
        return None


def _info(index_name, file_path, code="int handle_request(void) { return 0; }"):
    return {
        "function_name": "handle_request",
        "index_name": index_name,
        "file_path": file_path,
        "start_line": 10,
        "end_line": 20,
        "signature": "int handle_request(void)",
        "is_static": False,
        "is_macro": False,
        "callees": [],
        "referenced_globals": [],
        "referenced_macros": [],
        "code": code,
    }


def _snapshot(info):
    return {
        "func_name": info["function_name"],
        "index_name": info["index_name"],
        "file_path": info["file_path"],
        "start_line": info["start_line"],
        "end_line": info["end_line"],
        "summary": info["index_name"],
        "referenced_globals": info["referenced_globals"],
        "referenced_macros": info["referenced_macros"],
    }


def _fallback_info(info):
    return {
        "function_name": info["function_name"],
        "index_name": info["index_name"],
        "file_path": info["file_path"],
        "start_line": info["start_line"],
        "end_line": info["end_line"],
        "signature": info["signature"],
        "is_static": info["is_static"],
        "is_macro": info["is_macro"],
        "callees": info["callees"],
        "referenced_globals": info["referenced_globals"],
        "referenced_macros": info["referenced_macros"],
    }


def test_snapshot_tool_resolves_function_info_before_loading(tmp_path) -> None:
    left = _info(
        "handle_request@src/a.c:10-20",
        "src/a.c",
        "int handle_request(void) { return 1; }",
    )
    right = _info(
        "handle_request@src/b.c:10-20",
        "src/b.c",
        "int handle_request(void) { return 2; }",
    )
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(left["index_name"], _snapshot(left), "int handle_request(void) { return 1; }")
    store.save_snapshot(right["index_name"], _snapshot(right), "int handle_request(void) { return 2; }")
    tool = GetFunctionSnapshotTool(store, code_index=FakeCodeIndex([left, right]))

    result = tool.execute({"func_name": "handle_request", "file_path": "src/b.c"})

    assert result["success"] is True
    assert result["data"]["index_name"] == right["index_name"]


def test_snapshot_tool_rejects_ambiguous_function_name(tmp_path) -> None:
    left = _info("handle_request@src/a.c:10-20", "src/a.c")
    right = _info("handle_request@src/b.c:10-20", "src/b.c")
    tool = GetFunctionSnapshotTool(
        SnapshotStore(tmp_path / "snapshots"),
        code_index=FakeCodeIndex([left, right]),
    )

    result = tool.execute({"func_name": "handle_request"})

    assert result["success"] is False
    assert result["reason"] == "function_info_ambiguous"


def test_snapshot_tool_returns_function_info_when_snapshot_is_missing(tmp_path) -> None:
    info = _info("handle_request@src/a.c:10-20", "src/a.c")
    info["callees_truncation"] = {
        "truncated": True,
        "returned": 30,
        "total": 31,
    }
    tool = GetFunctionSnapshotTool(
        SnapshotStore(tmp_path / "snapshots"),
        code_index=FakeCodeIndex([info]),
    )

    result = tool.execute(
        {"func_name": "handle_request", "file_path": "src/a.c"}
    )

    expected_info = _fallback_info(info)
    expected_info["callees_truncation"] = info["callees_truncation"]
    assert result == {
        "success": True,
        "data": None,
        "snapshot_status": "missing",
        "reason": "no_snapshot",
        "message": "No snapshot exists; canonical function info is provided as fallback",
        "function_info": expected_info,
    }
    assert "code" not in result["function_info"]


def test_snapshot_tool_does_not_return_stale_symbol_context(tmp_path) -> None:
    code = "int handle_request(void) { return LIMIT; }"
    info = _info("handle_request@src/a.c:10-20", "src/a.c", code)
    old_macro = {
        "name": "LIMIT",
        "file_path": "include/limits.h",
        "line": 3,
        "definition": "#define LIMIT 8",
        "is_function_like": False,
        "reference_lines": [10],
    }
    info["referenced_macros"] = [old_macro]
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(info["index_name"], _snapshot(info), code)

    current_info = dict(info)
    current_info["referenced_macros"] = [
        {**old_macro, "definition": "#define LIMIT 16"}
    ]
    tool = GetFunctionSnapshotTool(
        store,
        code_index=FakeCodeIndex([current_info]),
    )

    result = tool.execute({"func_name": "handle_request", "file_path": "src/a.c"})

    assert result == {
        "success": True,
        "data": None,
        "snapshot_status": "stale",
        "message": "Saved snapshot is stale and must be rebuilt",
        "reason": "symbol_context_changed",
        "function_info": _fallback_info(current_info),
    }


def test_snapshot_tool_does_not_return_legacy_deterministic_shape(tmp_path) -> None:
    code = "int handle_request(void) { return 0; }"
    info = _info("handle_request@src/a.c:10-20", "src/a.c", code)
    legacy = {
        **_snapshot(info),
        "signature": info["signature"],
        "snapshot_kind": "syntactic",
        "is_static": False,
        "is_macro": False,
        "code": code,
        "inputs": [],
        "outputs": [],
        "resources": {},
        "error_handling": {},
        "concurrency": {},
        "key_semantics": [],
        "callees": [],
        "suspicious_points": [],
    }
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_snapshot(info["index_name"], legacy, code)
    tool = GetFunctionSnapshotTool(store, code_index=FakeCodeIndex([info]))

    result = tool.execute(
        {"func_name": "handle_request", "file_path": "src/a.c"}
    )

    assert result == {
        "success": True,
        "data": None,
        "snapshot_status": "stale",
        "message": "Saved snapshot is stale and must be rebuilt",
        "reason": "snapshot_shape_changed",
        "function_info": _fallback_info(info),
    }
