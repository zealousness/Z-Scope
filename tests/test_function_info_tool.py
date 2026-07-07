from pathlib import Path
from types import SimpleNamespace

from zscope.retrieval.code_index import CodeIndex
from zscope.tools.function_info import GetFunctionInfoTool
from zscope.tools.policy import ToolPolicy
from zscope.tools.runtime import ToolsRuntime


class FunctionInfoBackend:
    def __init__(self, function_index, *, callers=None, callees=None):
        self.function_index = function_index
        self.callers = callers or []
        self.callees = callees or []

    def build_function_index(self):
        return self.function_index

    def get_callers(self, func_name: str, limit: int = 20, callee_file: str = ""):
        return list(self.callers)[:limit]

    def get_callees(self, func_name: str, limit: int = 30):
        return list(self.callees)[:limit]

    def get_method(self, name: str):
        return None

    def get_method_callees(self, name: str, limit: int = 30):
        return self.get_callees(name, limit=limit)

    def close(self) -> None:
        pass


class EmptySnapshotStore:
    pass


def _index(tmp_path: Path, backend: FunctionInfoBackend, backend_name: str) -> CodeIndex:
    return CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=backend,
        indexing_config=SimpleNamespace(backend=backend_name),
    )


def test_function_info_returns_all_same_name_matches_and_file_scopes(tmp_path) -> None:
    left = tmp_path / "src" / "a" / "shared.c"
    right = tmp_path / "src" / "b" / "shared.c"
    left.parent.mkdir(parents=True)
    right.parent.mkdir(parents=True)
    left.write_text("int Target(void) { return 1; }\n", encoding="utf-8")
    right.write_text("int Target(void) { return 2; }\n", encoding="utf-8")
    backend = FunctionInfoBackend(
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
    index = _index(tmp_path, backend, "unified")

    matches = index.find_function_infos("Target", callers_limit=0, callees_limit=0)
    scoped = index.find_function_infos(
        "Target",
        file_path="src/b/shared.c",
        callers_limit=0,
        callees_limit=0,
    )

    assert len(matches) == 2
    assert {match["file_path"].replace("\\", "/") for match in matches} == {
        "src/a/shared.c",
        "src/b/shared.c",
    }
    assert len({match["index_name"] for match in matches}) == 2
    assert scoped[0]["file_path"].replace("\\", "/") == "src/b/shared.c"
    assert scoped[0]["index_name"] in {match["index_name"] for match in matches}


def test_function_info_limits_call_relationships_and_preserves_svf_call_type(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
    for backend_name in ("svf", "unified"):
        backend = FunctionInfoBackend(
            {
                "Caller": {
                    "name": "Caller",
                    "file": "src/caller.c",
                    "start_line": 1,
                    "end_line": 1,
                    "signature": "int Caller(void)",
                }
            },
            callers=[
                {"name": "Up1", "filename": "src/up1.c", "lineNumber": 10},
                {"name": "Up2", "filename": "src/up2.c", "lineNumber": 20},
            ],
            callees=[
                {
                    "name": "DirectTarget",
                    "filename": "src/direct.c",
                    "lineNumber": 30,
                    "call_type": "direct",
                },
                {
                    "name": "IndirectTarget",
                    "call_file": "src/caller.c",
                    "call_line": 31,
                    "source": "svf",
                    "confidence": 0.9,
                },
            ],
        )
        index = _index(tmp_path, backend, backend_name)

        info = index.find_function_infos(
            "Caller",
            callers_limit=1,
            callees_limit=2,
        )[0]

        assert [caller["caller_name"] for caller in info["callers"]] == ["Up1"]
        assert [callee["call_type"] for callee in info["callees"]] == [
            "direct",
            "indirect",
        ]


def test_function_info_downgrades_call_type_to_direct_for_clang_backends(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
    for backend_name in ("clang", "clangd"):
        backend = FunctionInfoBackend(
            {
                "Caller": {
                    "name": "Caller",
                    "file": "src/caller.c",
                    "start_line": 1,
                    "end_line": 1,
                    "signature": "int Caller(void)",
                }
            },
            callees=[
                {
                    "name": "MaybeIndirect",
                    "call_file": "src/caller.c",
                    "call_line": 31,
                    "call_type": "indirect",
                    "source": "svf",
                }
            ],
        )
        index = _index(tmp_path, backend, backend_name)

        info = index.find_function_infos("Caller", callers_limit=0, callees_limit=1)[0]

        assert info["callees"][0]["call_type"] == "direct"


def test_get_function_info_tool_and_runtime_return_match_count(tmp_path) -> None:
    source = tmp_path / "src" / "target.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Target(void) { return 1; }\n", encoding="utf-8")
    backend = FunctionInfoBackend(
        {
            "Target": {
                "name": "Target",
                "file": "src/target.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            }
        }
    )
    index = _index(tmp_path, backend, "unified")

    tool_result = GetFunctionInfoTool(index).execute({"func_name": "Target"})
    runtime = ToolsRuntime(index, EmptySnapshotStore(), tool_policy=ToolPolicy.allow_all())
    runtime_result = runtime.execute_tool("get_function_info", {"func_name": "Target"})

    assert tool_result["success"] is True
    assert tool_result["data"]["match_count"] == 1
    assert runtime_result["success"] is True
    assert runtime_result["data"]["match_count"] == 1
