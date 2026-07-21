from pathlib import Path
from types import SimpleNamespace

from zscope.retrieval.code_index import CodeIndex
from zscope.tools.code_retrieval import GetFunctionImplTool
from zscope.tools.function_info import GetFunctionInfoTool
from zscope.tools.policy import ToolPolicy
from zscope.tools.runtime import ToolsRuntime


class FunctionInfoBackend:
    def __init__(self, function_index, *, callers=None, callees=None, symbol_context=None):
        self.function_index = function_index
        self.callers = callers or []
        self.callees = callees or []
        self.symbol_context = symbol_context or {
            "referenced_globals": [],
            "referenced_macros": [],
        }
        self.caller_calls = 0

    def build_function_index(self):
        return self.function_index

    def get_callers(self, func_name: str, limit: int = 20, callee_file: str = ""):
        self.caller_calls += 1
        return list(self.callers)[:limit]

    def get_callees(self, func_name: str, limit: int = 30):
        return list(self.callees)[:limit]

    def get_function_info_callees(self, func_name: str, file_path: str = ""):
        return list(self.callees)

    def get_function_symbol_context(self, func_name: str, file_path: str = ""):
        return {
            "referenced_globals": list(self.symbol_context.get("referenced_globals") or []),
            "referenced_macros": list(self.symbol_context.get("referenced_macros") or []),
        }

    def get_method(self, name: str):
        return None

    def get_method_callees(self, name: str, limit: int = 30):
        return self.get_callees(name, limit=limit)

    def close(self) -> None:
        pass


class EmptySnapshotStore:
    pass


class RecordingUserConfig:
    def __init__(self, external_functions=None):
        self.external_functions = external_functions or {}
        self.warnings = []

    def get_external_function(self, func_name: str):
        return self.external_functions.get(func_name)

    def add_config_warning(self, warning_type: str, subject: str, message: str) -> None:
        self.warnings.append((warning_type, subject, message))


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

    matches = index.find_function_infos("Target")
    scoped = index.find_function_infos(
        "Target",
        file_path="src/b/shared.c",
    )

    assert len(matches) == 2
    assert {match["file_path"].replace("\\", "/") for match in matches} == {
        "src/a/shared.c",
        "src/b/shared.c",
    }
    assert len({match["index_name"] for match in matches}) == 2
    assert {match["index_name"] for match in matches} == {
        "Target@src/a/shared.c:1-1",
        "Target@src/b/shared.c:1-1",
    }
    assert scoped[0]["file_path"].replace("\\", "/") == "src/b/shared.c"
    assert scoped[0]["index_name"] in {match["index_name"] for match in matches}


def test_function_info_preserves_svf_call_type_without_querying_callers(tmp_path) -> None:
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

        info = index.find_function_infos("Caller")[0]

        assert "callers" not in info
        assert backend.caller_calls == 0
        assert [callee["call_type"] for callee in info["callees"]] == [
            ["direct"],
            ["indirect"],
        ]


def test_function_info_aggregates_callee_callsites(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
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
            {"name": "Up1", "filename": "src/up.c", "lineNumber": 10},
            {"name": "Up1", "filename": "src/up.c", "lineNumber": 20},
            {"name": "Up2", "filename": "src/up2.c", "lineNumber": 30},
        ],
        callees=[
            {
                "name": "SharedTarget",
                "filename": "src/shared.c",
                "lineNumber": 40,
                "call_type": "direct",
            },
            {
                "name": "SharedTarget",
                "filename": "src/shared.c",
                "lineNumber": 50,
                "call_type": "direct",
            },
            {
                "name": "OtherTarget",
                "filename": "src/other.c",
                "lineNumber": 60,
                "call_type": "direct",
            },
        ],
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert "callers" not in info
    assert info["callees"] == [
        {
            "callee_index_name": "OtherTarget",
            "callsite_lines": [60],
            "call_type": ["direct"],
        },
        {
            "callee_index_name": "SharedTarget",
            "callsite_lines": [40, 50],
            "call_type": ["direct"],
        }
    ]


def test_function_info_aggregates_direct_and_indirect_types_by_callee(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    target = tmp_path / "src" / "target.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
    target.write_text("int Target(void) { return 0; }\n", encoding="utf-8")
    backend = FunctionInfoBackend(
        {
            "Caller": {
                "name": "Caller",
                "file": "src/caller.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Caller(void)",
            },
            "Target": {
                "name": "Target",
                "file": "src/target.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            },
        },
        callees=[
            {
                "name": "Target",
                "filename": "src/target.c",
                "lineNumber": 10,
                "call_type": "direct",
            },
            {
                "name": "Target",
                "call_file": "src/caller.c",
                "call_line": 20,
                "source": "svf",
                "confidence": 0.9,
            },
        ],
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert info["callees"] == [
        {
            "callee_index_name": "Target@src/target.c:1-1",
            "callsite_lines": [10, 20],
            "call_type": ["direct", "indirect"],
        }
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

        info = index.find_function_infos("Caller")[0]

        assert info["callees"][0]["call_type"] == ["direct"]


def test_function_info_applies_fixed_limits_and_independent_truncation(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
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
                "name": f"callee_{idx:02d}",
                "filename": f"src/callee_{idx:02d}.c",
                "lineNumber": idx + 1,
                "call_type": "direct",
            }
            for idx in range(35)
        ],
        symbol_context={
            "referenced_globals": [
                {
                    "name": f"global_{idx:02d}",
                    "type": "int",
                    "file_path": "src/globals.c",
                    "line": idx + 1,
                    "storage_class": "static",
                    "qualifiers": "volatile,const",
                    "access": "read",
                    "reference_lines": [idx + 10],
                }
                for idx in range(52)
            ],
            "referenced_macros": [
                {
                    "name": f"MACRO_{idx:02d}",
                    "file_path": "include/macros.h",
                    "line": idx + 1,
                    "definition": f"#define MACRO_{idx:02d} {idx}",
                    "is_function_like": False,
                    "reference_lines": [idx + 20],
                }
                for idx in range(31)
            ],
        },
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert len(info["callees"]) == 30
    assert info["callees_truncation"] == {
        "truncated": True,
        "returned": 30,
        "total": 35,
    }
    assert len(info["referenced_globals"]) == 50
    assert set(info["referenced_globals"][0]) == {
        "name",
        "type",
        "file_path",
        "line",
        "storage_class",
        "qualifiers",
        "initializer",
        "access",
        "reference_lines",
    }
    assert info["referenced_globals"][0]["storage_class"] == "static"
    assert info["referenced_globals"][0]["qualifiers"] == ["const", "volatile"]
    assert info["referenced_globals_truncation"] == {
        "truncated": True,
        "returned": 50,
        "total": 52,
    }
    assert len(info["referenced_macros"]) == 30
    assert info["referenced_macros_truncation"] == {
        "truncated": True,
        "returned": 30,
        "total": 31,
    }


def test_function_info_omits_truncation_for_untruncated_arrays(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
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
        symbol_context={
            "referenced_globals": [],
            "referenced_macros": [
                {
                    "name": "ONLY_MACRO",
                    "file_path": "include/macros.h",
                    "line": 1,
                    "definition": "#define ONLY_MACRO 1",
                    "is_function_like": False,
                    "reference_lines": [1],
                }
            ],
        },
    )
    index = _index(tmp_path, backend, "clang")

    info = index.find_function_infos("Caller")[0]

    assert "callees_truncation" not in info
    assert "referenced_globals_truncation" not in info
    assert "referenced_macros_truncation" not in info


def test_function_info_regex_backend_returns_exact_symbol_context(tmp_path) -> None:
    source = tmp_path / "demo.c"
    source.write_text(
        "#define ENABLED 1\n"
        "int g_state = 0;\n"
        "int helper(void) { return 1; }\n"
        "int update(void) {\n"
        "    if (ENABLED) {\n"
        "        g_state = helper();\n"
        "    }\n"
        "    return g_state;\n"
        "}\n",
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    info = index.find_function_infos("update")[0]

    assert info["callees"] == [
        {
            "callee_index_name": "helper@demo.c:3-3",
            "callsite_lines": [6],
            "call_type": ["direct"],
        }
    ]
    assert info["referenced_globals"][0]["name"] == "g_state"
    assert set(info["referenced_globals"][0]) == {
        "name",
        "type",
        "file_path",
        "line",
        "storage_class",
        "qualifiers",
        "initializer",
        "access",
        "reference_lines",
    }
    assert info["referenced_globals"][0]["access"] == "read_write"
    assert info["referenced_globals"][0]["reference_lines"] == [6, 8]
    assert info["referenced_macros"][0]["name"] == "ENABLED"
    assert info["referenced_macros"][0]["reference_lines"] == [5]


def test_function_tools_return_is_static_for_project_functions_only(tmp_path) -> None:
    source = tmp_path / "demo.c"
    source.write_text(
        "#define WRAP(x) ((x) + 1)\n"
        "static int hidden(void) { return 1; }\n"
        "int visible(void) { static int counter; return counter; }\n",
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    hidden_info = index.find_function_infos("hidden")[0]
    visible_info = index.find_function_infos("visible")[0]
    macro_info = index.find_function_infos("WRAP")[0]
    hidden_impl = index.get_function_impl("hidden", include_context=False)
    visible_impl = index.get_function_impl("visible", include_context=False)
    macro_impl = index.get_function_impl("WRAP", include_context=False)
    runtime = ToolsRuntime(index, EmptySnapshotStore(), tool_policy=ToolPolicy.allow_all())
    runtime_info = runtime.execute_tool("get_function_info", {"func_name": "hidden"})

    assert hidden_info["is_static"] is True
    assert visible_info["is_static"] is False
    assert hidden_impl is not None and hidden_impl["is_static"] is True
    assert visible_impl is not None and visible_impl["is_static"] is False
    assert runtime_info["data"]["matches"][0]["is_static"] is True
    assert hidden_info["is_macro"] is False
    assert visible_info["is_macro"] is False
    assert macro_info["is_static"] is False
    assert macro_info["is_macro"] is True
    assert macro_impl is not None and "is_static" not in macro_impl


def test_function_static_metadata_precedes_source_fallback(tmp_path) -> None:
    source = tmp_path / "src" / "static.c"
    source.parent.mkdir(parents=True)
    source.write_text(
        "static int explicit_false(void) { return 0; }\n"
        "static int inferred_true(void) { return 1; }\n"
        "int Widget_reset(void) { return 2; }\n",
        encoding="utf-8",
    )
    backend = FunctionInfoBackend(
        {
            "ExplicitFalse": {
                "name": "explicit_false",
                "file": "src/static.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "static int explicit_false(void)",
                "is_static": 0,
            },
            "InferredTrue": {
                "name": "inferred_true",
                "file": "src/static.c",
                "start_line": 2,
                "end_line": 2,
                "signature": "int inferred_true(void)",
            },
            "StructuredTrue": {
                "name": "Widget_reset",
                "file": "src/static.c",
                "start_line": 3,
                "end_line": 3,
                "signature": "int Widget_reset(void)",
                "is_static": 1,
            },
        }
    )
    index = _index(tmp_path, backend, "unified")

    explicit_false = index.find_function_infos("explicit_false")[0]
    inferred_true = index.find_function_infos("inferred_true")[0]
    structured_true = index.get_function_impl(
        "Widget_reset",
        include_context=False,
    )

    assert explicit_false["is_static"] is False
    assert inferred_true["is_static"] is True
    assert structured_true is not None and structured_true["is_static"] is True


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
    tool_schema = GetFunctionInfoTool(index).get_schema()["function"]
    properties = tool_schema["parameters"]["properties"]
    runtime_schema = next(
        schema["function"]
        for schema in runtime.get_tools_schema()
        if schema["function"]["name"] == "get_function_info"
    )

    assert tool_result["success"] is True
    assert tool_result["data"]["match_count"] == 1
    assert tool_result["data"]["matches"][0]["index_name"] == "Target@src/target.c:1-1"
    assert set(properties) == {"func_name", "file_path"}
    assert "not exhaustive" in tool_schema["description"]
    assert "not exhaustive" in runtime_schema["description"]
    assert "callers" not in tool_result["data"]["matches"][0]
    assert tool_result["data"]["matches"][0]["referenced_globals"] == []
    assert tool_result["data"]["matches"][0]["referenced_macros"] == []
    assert runtime_result["success"] is True
    assert runtime_result["data"]["match_count"] == 1


def test_get_function_info_returns_function_like_macro_context(tmp_path) -> None:
    header = tmp_path / "include" / "macros.h"
    header.parent.mkdir(parents=True)
    header.write_text(
        "#define ALLOC_WRAP(sz) \\\n"
        "    alloc(sz) \\\n"
        "    + GLOBAL_LIMIT\n"
        "#define GLOBAL_LIMIT 8\n",
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    result = GetFunctionInfoTool(index).execute({"func_name": "ALLOC_WRAP"})
    runtime = ToolsRuntime(index, EmptySnapshotStore(), tool_policy=ToolPolicy.allow_all())
    runtime_result = runtime.execute_tool(
        "get_function_info",
        {"func_name": "ALLOC_WRAP"},
    )

    assert result["success"] is True
    assert result["data"]["match_count"] == 1
    match = result["data"]["matches"][0]
    assert match == {
        "function_name": "ALLOC_WRAP",
        "file_path": "include/macros.h",
        "index_name": "ALLOC_WRAP@include/macros.h:1-3",
        "start_line": 1,
        "end_line": 3,
        "signature": "#define ALLOC_WRAP(sz)",
        "is_static": False,
        "is_macro": True,
        "code": (
            "1 | #define ALLOC_WRAP(sz) \\\n"
            "2 |     alloc(sz) \\\n"
            "3 |     + GLOBAL_LIMIT\n"
        ),
        "callees": [
            {
                "callee_index_name": "alloc",
                "callsite_lines": [2],
                "call_type": ["direct"],
            }
        ],
        "referenced_globals": [],
        "referenced_macros": [
            {
                "name": "GLOBAL_LIMIT",
                "file_path": "include/macros.h",
                "line": 4,
                "definition": "#define GLOBAL_LIMIT 8\n",
                "is_function_like": False,
                "reference_lines": [3],
            }
        ],
    }
    assert runtime_result == result
    assert index.find_function_infos(match["index_name"]) == [match]
    assert index.find_function_infos("GLOBAL_LIMIT") == []


def test_get_function_info_returns_all_macro_matches_and_file_scopes(tmp_path) -> None:
    left = tmp_path / "include" / "left.h"
    right = tmp_path / "include" / "right.h"
    left.parent.mkdir(parents=True)
    left.write_text("#define WRAP(x) left_call(x)\n", encoding="utf-8")
    right.write_text("#define WRAP(x) right_call(x)\n", encoding="utf-8")
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    matches = index.find_function_infos("WRAP")
    scoped = index.find_function_infos("WRAP", file_path="right.h")

    assert [match["file_path"] for match in matches] == [
        "include/left.h",
        "include/right.h",
    ]
    assert all(match["is_macro"] is True for match in matches)
    assert len(scoped) == 1
    assert scoped[0]["file_path"] == "include/right.h"


def test_get_function_info_prefers_function_unless_macro_file_is_requested(tmp_path) -> None:
    source = tmp_path / "src" / "wrap.c"
    header = tmp_path / "include" / "wrap.h"
    source.parent.mkdir(parents=True)
    header.parent.mkdir(parents=True)
    source.write_text("int WRAP(int value) { return value; }\n", encoding="utf-8")
    header.write_text("#define WRAP(value) ((value) + 1)\n", encoding="utf-8")
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    function_match = index.find_function_infos("WRAP")[0]
    macro_match = index.find_function_infos("WRAP", file_path="include/wrap.h")[0]

    assert function_match["is_macro"] is False
    assert "code" not in function_match
    assert macro_match["is_macro"] is True
    assert macro_match["file_path"] == "include/wrap.h"


def test_get_function_info_returns_complete_macro_source_without_truncation(tmp_path) -> None:
    header = tmp_path / "include" / "large_macro.h"
    header.parent.mkdir(parents=True)
    body_lines = ["#define LARGE_WRAP(x) \\\n"]
    body_lines.extend(f"    + step_{line}(x) \\\n" for line in range(1, 505))
    body_lines.append("    + final_step(x)\n")
    header.write_text("".join(body_lines), encoding="utf-8")
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    match = index.find_function_infos("LARGE_WRAP")[0]

    assert match["start_line"] == 1
    assert match["end_line"] == len(body_lines)
    assert f"{len(body_lines)} |     + final_step(x)" in match["code"]
    assert "truncated" not in match


def test_get_function_info_prefers_backend_macro_facts(tmp_path, monkeypatch) -> None:
    header = tmp_path / "include" / "backend_macros.h"
    header.parent.mkdir(parents=True)
    header.write_text("#define BACKEND_WRAP(x) fallback(x)\n", encoding="utf-8")

    class MacroInfoBackend(FunctionInfoBackend):
        def get_macro_definitions(self, name: str, limit: int = 20):
            if name != "BACKEND_WRAP":
                return []
            return [
                {
                    "name": "BACKEND_WRAP",
                    "file_path": "include/backend_macros.h",
                    "line": 1,
                    "definition": "#define BACKEND_WRAP(x) backend(x)\n",
                    "is_function_like": 1,
                }
            ]

    index = _index(tmp_path, MacroInfoBackend({}), "unified")

    def fail_regex_fallback():
        raise AssertionError("backend macro facts should avoid regex fallback")

    monkeypatch.setattr(index, "_get_macro_definition_index", fail_regex_fallback)

    match = index.find_function_infos("BACKEND_WRAP")[0]

    assert match["is_macro"] is True
    assert "backend(x)" in match["code"]
    assert "fallback(x)" not in match["code"]
    assert set(match) == {
        "function_name",
        "file_path",
        "index_name",
        "start_line",
        "end_line",
        "signature",
        "is_static",
        "is_macro",
        "code",
        "callees",
        "referenced_globals",
        "referenced_macros",
    }


def test_find_function_infos_falls_back_from_stale_index_name(tmp_path) -> None:
    left = tmp_path / "src" / "a.c"
    right = tmp_path / "src" / "b.c"
    left.parent.mkdir(parents=True)
    left.write_text("int Target(void) { return 1; }\n", encoding="utf-8")
    right.write_text("int Target(void) { return 2; }\n", encoding="utf-8")
    backend = FunctionInfoBackend(
        {
            "TargetLeft": {
                "name": "Target",
                "file": "src/a.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            },
            "TargetRight": {
                "name": "Target",
                "file": "src/b.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(void)",
            },
        }
    )
    index = _index(tmp_path, backend, "unified")

    inferred = index.find_function_infos("Target@src/a.c:10-20")
    explicit = index.find_function_infos(
        "Target@src/a.c:10-20",
        file_path="src/b.c",
    )

    assert [match["index_name"] for match in inferred] == ["Target@src/a.c:1-1"]
    assert [match["index_name"] for match in explicit] == ["Target@src/b.c:1-1"]


def test_find_function_infos_uses_signature_before_simple_name_fallback(tmp_path) -> None:
    int_source = tmp_path / "src" / "z_int.c"
    char_source = tmp_path / "src" / "a_char.c"
    int_source.parent.mkdir(parents=True)
    int_source.write_text("int Target(int value) { return value; }\n", encoding="utf-8")
    char_source.write_text("int Target(char *value) { return *value; }\n", encoding="utf-8")
    backend = FunctionInfoBackend(
        {
            "TargetInt": {
                "name": "Target",
                "file": "src/z_int.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(int value)",
            },
            "TargetChar": {
                "name": "Target",
                "file": "src/a_char.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(char *value)",
            },
        }
    )
    index = _index(tmp_path, backend, "unified")

    exact = index.find_function_infos("static int Target(int value)")
    fallback = index.find_function_infos("Target(int)")

    assert [match["file_path"] for match in exact] == ["src/z_int.c"]
    assert {match["file_path"] for match in fallback} == {
        "src/a_char.c",
        "src/z_int.c",
    }


def test_macro_index_name_is_resolved_before_function_name_fallback(tmp_path) -> None:
    source = tmp_path / "src" / "wrap.c"
    header = tmp_path / "include" / "wrap.h"
    source.parent.mkdir(parents=True)
    header.parent.mkdir(parents=True)
    source.write_text("int WRAP(int value) { return value; }\n", encoding="utf-8")
    header.write_text("#define WRAP(value) ((value) + 1)\n", encoding="utf-8")
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    macro = index.find_function_infos("WRAP", file_path="include/wrap.h")[0]
    repeated = index.find_function_infos(macro["index_name"])

    assert repeated == [macro]


def test_get_function_impl_tool_preserves_exact_signature(tmp_path) -> None:
    int_source = tmp_path / "src" / "z_int.c"
    char_source = tmp_path / "src" / "a_char.c"
    int_source.parent.mkdir(parents=True)
    int_source.write_text("int Target(int value) { return value + 1; }\n", encoding="utf-8")
    char_source.write_text("int Target(char *value) { return *value; }\n", encoding="utf-8")
    backend = FunctionInfoBackend(
        {
            "TargetInt": {
                "name": "Target",
                "file": "src/z_int.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(int value)",
            },
            "TargetChar": {
                "name": "Target",
                "file": "src/a_char.c",
                "start_line": 1,
                "end_line": 1,
                "signature": "int Target(char *value)",
            },
        }
    )
    index = _index(tmp_path, backend, "unified")

    result = GetFunctionImplTool(index).execute(
        {"func_name": "static int Target(int value)"}
    )

    assert result["success"] is True
    assert result["data"]["index_name"] == "Target@src/z_int.c:1-1"
    assert "return value + 1" in result["data"]["code"]


def test_get_function_info_returns_configured_external_function(tmp_path) -> None:
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )
    user_config = RecordingUserConfig(
        {"external_api": {"description": "Configured external API"}}
    )

    result = GetFunctionInfoTool(index, user_config).execute(
        {"func_name": "external_api(int value)"}
    )
    impl_result = GetFunctionImplTool(index, user_config).execute(
        {"func_name": "external_api(int value)"}
    )
    runtime = ToolsRuntime(
        index,
        EmptySnapshotStore(),
        user_config=user_config,
        tool_policy=ToolPolicy.allow_all(),
    )
    runtime_result = runtime.execute_tool(
        "get_function_info",
        {"func_name": "external_api(int value)"},
    )

    assert result["success"] is True
    assert runtime_result == result
    assert impl_result["success"] is True
    assert impl_result["data"]["func_name"] == "external_api"
    assert impl_result["data"]["file"] == "[external]"
    assert impl_result["data"]["is_external"] is True
    assert "Configured external API" in impl_result["data"]["code"]
    assert result["data"]["match_count"] == 1
    match = result["data"]["matches"][0]
    assert match == {
        "function_name": "external_api",
        "file_path": "[external]",
        "start_line": 0,
        "end_line": 0,
        "signature": "external_api(...)",
        "code": impl_result["data"]["code"],
        "callees": [],
        "referenced_globals": [],
        "referenced_macros": [],
        "is_external": True,
    }
    assert "is_static" not in match
    assert "is_static" not in impl_result["data"]
    assert user_config.warnings == []


def test_get_function_info_warns_and_fails_for_unconfigured_external(tmp_path) -> None:
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )
    user_config = RecordingUserConfig()

    result = GetFunctionInfoTool(index, user_config).execute(
        {"func_name": "missing_api(int value)"}
    )

    assert result == {
        "success": False,
        "error": "Function 'missing_api' not found",
    }
    assert len(user_config.warnings) == 1
    warning_type, subject, message = user_config.warnings[0]
    assert warning_type == "missing_external_func"
    assert subject == "missing_api"
    assert "missing_api" in message


def test_get_function_info_fails_without_user_config_for_unknown_function(tmp_path) -> None:
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    result = GetFunctionInfoTool(index).execute({"func_name": "missing_api"})

    assert result == {
        "success": False,
        "error": "Function 'missing_api' not found",
    }
