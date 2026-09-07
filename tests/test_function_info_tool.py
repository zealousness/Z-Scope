from pathlib import Path
from types import SimpleNamespace

from zscope.retrieval.code_index import CodeIndex
from zscope.snapshots.modeling_input import build_semantic_model_input
from zscope.tools.code_retrieval import GetFunctionImplTool
from zscope.tools.function_info import GetFunctionInfoTool
from zscope.tools.policy import ToolPolicy
from zscope.tools.runtime import ToolsRuntime


class FunctionInfoBackend:
    def __init__(
        self,
        function_index,
        *,
        callers=None,
        callees=None,
        symbol_context=None,
        type_context=None,
    ):
        self.function_index = function_index
        self.callers = callers or []
        self.callees = callees or []
        self.symbol_context = symbol_context or {
            "referenced_globals": [],
            "referenced_macros": [],
        }
        self.type_context = type_context or {"referenced_types": []}
        self.caller_calls = 0
        self.type_context_calls = 0

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

    def get_function_type_context(
        self,
        func_name: str,
        file_path: str = "",
        start_line: int = 0,
    ):
        self.type_context_calls += 1
        return {
            key: [dict(item) for item in value] if isinstance(value, list) else dict(value)
            for key, value in self.type_context.items()
        }

    def get_method(self, name: str):
        return None

    def get_method_callees(self, name: str, limit: int = 30):
        return self.get_callees(name, limit=limit)

    def close(self) -> None:
        pass


class MacroSymbolBackend(FunctionInfoBackend):
    def __init__(self, macro_definitions, symbol_definitions):
        super().__init__({})
        self.macro_definitions = macro_definitions
        self.symbol_definitions = symbol_definitions
        self.symbol_definition_queries = []

    def get_macro_definitions(self, name: str, limit: int = 20):
        return [
            dict(record)
            for record in self.macro_definitions.get(name, [])[:limit]
        ]

    def get_macro_definitions_batch(self, names):
        requested = set(names)
        self.symbol_definition_queries.append(sorted(requested))
        return [
            dict(record)
            for record in self.symbol_definitions.get("macros", [])
            if record.get("name") in requested
        ]


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
    assert all(match["referenced_types"] == [] for match in matches)


def test_function_info_normalizes_and_budgets_direct_type_context(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
    header = tmp_path / "include" / "types.h"
    header.parent.mkdir()
    header.write_text(
        "".join(f"typedef int Type{idx:02d};\n" for idx in range(30))
        + "\n" * 69
        + "typedef int ZSignature;\n",
        encoding="utf-8",
    )
    types = [
        {
            "type_index_name": f"Type{idx:02d}@include/types.h:{idx + 1}-{idx + 1}",
            "name": f"Type{idx:02d}",
            "kind": "typedef",
            "file_path": "include/types.h",
            "start_line": idx + 1,
            "end_line": idx + 1,
            "full_definition": f"typedef int Type{idx:02d};",
            "reference_kinds": ["local"],
            "reference_lines": [1],
            "definition_hash": "must-not-leak",
            "dependency_depth": 3,
        }
        for idx in range(30)
    ]
    types.append(
        {
            "type_index_name": "ZSignature@include/types.h:100-100",
            "name": "ZSignature",
            "kind": "typedef",
            "file_path": "include/types.h",
            "start_line": 100,
            "end_line": 100,
            "full_definition": "typedef int ZSignature;",
            "reference_kinds": ["parameter"],
            "reference_lines": [1],
        }
    )
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
        type_context={"referenced_types": types},
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert len(info["referenced_types"]) == 30
    assert any(
        item["type_index_name"] == "ZSignature@include/types.h:100-100"
        for item in info["referenced_types"]
    )
    assert info["referenced_types"][-1]["full_definition"] == (
        "100 | typedef int ZSignature;\n"
    )
    assert all(
        set(item)
        == {
            "type_index_name",
            "kind",
            "full_definition",
            "reference_kinds",
            "reference_lines",
        }
        for item in info["referenced_types"]
    )
    assert all("definition_hash" not in item for item in info["referenced_types"])
    assert all("dependency_depth" not in item for item in info["referenced_types"])
    assert info["referenced_types_truncation"] == {
        "truncated": True,
        "returned": 30,
        "total": 31,
        "definition_bytes_returned": sum(
            len(item["full_definition"].encode("utf-8"))
            for item in info["referenced_types"]
        ),
        "definition_bytes_limit": 32768,
    }
    assert backend.type_context_calls == 1


def test_get_function_info_omits_code_index_type_fields() -> None:
    match = {
        "function_name": "Target",
        "referenced_types": [{"type_index_name": "T@include/t.h:1-1"}],
        "unresolved_referenced_types": [{"name": "U", "reason": "ambiguous"}],
        "referenced_types_truncation": {"truncated": True, "returned": 1, "total": 2},
    }

    class StubIndex:
        def find_function_infos(self, func_name, file_path=""):
            assert func_name == "Target"
            assert file_path == "src/target.c"
            return [match]

    result = GetFunctionInfoTool(StubIndex()).execute(
        {"func_name": "Target", "file_path": "src/target.c"}
    )

    assert result["success"] is True
    assert result["data"]["matches"] == [{"function_name": "Target"}]


def test_get_function_info_retries_without_wrong_file_path_and_returns_all_matches() -> None:
    matches = [
        {
            "function_name": "Target",
            "index_name": "Target@src/a.c:1-2",
            "file_path": "src/a.c",
        },
        {
            "function_name": "Target",
            "index_name": "Target@src/b.c:3-4",
            "file_path": "src/b.c",
        },
    ]

    class RecordingIndex:
        def __init__(self):
            self.calls = []

        def find_function_infos(self, func_name, file_path=""):
            self.calls.append((func_name, file_path))
            return list(matches) if not file_path else []

    index = RecordingIndex()

    result = GetFunctionInfoTool(index).execute(
        {"func_name": "Target", "file_path": "src/wrong.c"}
    )

    assert result == {
        "success": True,
        "file_path_fallback": {
            "reason": "file_path_not_matched",
            "requested_file_path": "src/wrong.c",
            "message": (
                "The supplied file_path did not match the requested function. "
                "The following matches are results from a query without file_path."
            ),
        },
        "data": {
            "match_count": 2,
            "matches": matches,
        },
    }
    assert "query_scope" not in result["file_path_fallback"]
    assert index.calls == [
        ("Target", "src/wrong.c"),
        ("Target", ""),
    ]


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
        assert info["external_callees"] == []
        # The SVF row lacks a source-mapped pointer callsite, so it is not exposed.
        assert info["unresolved_callees"] == [
            {
                "callee_name": "DirectTarget",
                "direct_callsite_lines": [30],
                "indirect_callsites": [],
            }
        ]


def test_get_callees_filters_llvm_intrinsics_before_applying_limit(tmp_path) -> None:
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
            {"name": "llvm.memset.p0.i64", "source": "svf-ander"},
            {"name": "project_func", "filename": "src/project.c"},
            {"name": "llvm.memcpy.p0.p0.i64", "source": "svf-ander"},
            {"name": "external_api"},
            {"name": "project_func", "filename": "src/project.c"},
        ],
    )
    index = _index(tmp_path, backend, "unified")

    records = index.get_callees("Caller", limit=2)
    impl = index.get_function_impl("Caller", warn_missing=False)

    assert [record["name"] for record in records] == [
        "project_func",
        "external_api",
    ]
    assert impl is not None
    assert impl["callees"] == ["project_func", "external_api"]


def test_function_info_filters_llvm_intrinsics_before_classification_and_truncation(
    tmp_path,
) -> None:
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
            },
            "llvm.memset.p0.i64": {
                "name": "llvm.memset.p0.i64",
                "file": "src/generated.ll",
                "start_line": 1,
                "end_line": 1,
                "signature": "void llvm.memset.p0.i64(...)",
            },
        },
        callees=[
            {
                "name": f"external_{idx:02d}",
                "lineNumber": idx + 1,
                "call_type": "direct",
            }
            for idx in range(20)
        ]
        + [
            {
                "name": "llvm.memset.p0.i64",
                "call_file": "src/caller.c",
                "call_line": 0,
                "source": "svf-ander",
            },
            {
                "name": "llvm.memcpy.p0.p0.i64",
                "call_file": "src/caller.c",
                "call_line": 0,
                "source": "svf-ander",
            },
        ],
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert info["project_callees"] == []
    assert info["external_callees"] == []
    assert [item["callee_name"] for item in info["unresolved_callees"]] == [
        f"external_{idx:02d}" for idx in range(20)
    ]
    assert "project_callees_truncation" not in info
    assert "external_callees_truncation" not in info


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
    assert info["project_callees"] == []
    assert info["external_callees"] == []
    assert info["unresolved_callees"] == [
        {
            "callee_name": "OtherTarget",
            "direct_callsite_lines": [60],
            "indirect_callsites": [],
        },
        {
            "callee_name": "SharedTarget",
            "direct_callsite_lines": [40, 50],
            "indirect_callsites": [],
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

    assert info["project_callees"] == [
        {
            "callee_index_name": "Target@src/target.c:1-1",
            "callee_signature": "int Target(void)",
            "is_static": False,
            "callee_summary": "unknown",
            "direct_callsite_lines": [10],
            "indirect_callsites": [],
        }
    ]
    assert info["external_callees"] == []


def test_function_info_does_not_project_function_pointer_placeholder_as_external(tmp_path) -> None:
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
                "name": "callback",
                "filename": "src/ops.h",
                "lineNumber": 10,
                "call_type": "indirect",
                "callee_kind": "function_pointer_field",
            },
            {
                "name": "Target",
                "call_file": "src/caller.c",
                "call_line": 0,
                "source": "svf-ander",
            },
        ],
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert info["project_callees"] == []
    assert info["external_callees"] == []


def test_function_info_uses_three_callee_schema_with_verified_indirect_callsite(tmp_path) -> None:
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
                "signature": "void Target(void*)",
            },
        },
        callees=[
            {
                "name": "Target",
                "call_file": "src/caller.c",
                "call_line": 18,
                "call_type": "indirect",
                "pointer_symbol": "Ops.callback",
                "pointer_kind": "field",
                "pointer_type": "Callback",
                "pointer_signature": "void (*)(void*)",
                "callsite_expression": "ops->callback",
                "guard": "enabled != 0",
            },
            {
                "name": "free",
                "lineNumber": 20,
                "call_type": "direct",
                "callee_signature": "void free(void*)",
            },
            {
                "name": "vendor_submit",
                "lineNumber": 21,
                "call_type": "direct",
            },
        ],
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert info["project_callees"] == [
        {
            "callee_index_name": "Target@src/target.c:1-1",
            "callee_signature": "void Target(void*)",
            "is_static": False,
            "callee_summary": "unknown",
            "direct_callsite_lines": [],
            "indirect_callsites": [
                {
                    "callsite_line": 18,
                    "function_pointer": "Ops.callback",
                    "function_pointer_kind": "field",
                    "function_pointer_type": "Callback",
                    "function_pointer_signature": "void (*)(void*)",
                    "callsite_expression": "ops->callback",
                    "guard": "enabled != 0",
                }
            ],
        }
    ]
    assert info["external_callees"] == [
        {
            "callee_name": "free",
            "callee_signature": "void free(void*)",
            "direct_callsite_lines": [20],
            "indirect_callsites": [],
        }
    ]
    assert info["unresolved_callees"] == [
        {
            "callee_name": "vendor_submit",
            "direct_callsite_lines": [21],
            "indirect_callsites": [],
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

        assert info["external_callees"] == []
        assert info["unresolved_callees"] == [
            {
                "callee_name": "MaybeIndirect",
                "direct_callsite_lines": [31],
                "indirect_callsites": [],
            }
        ]


def test_function_info_applies_fixed_limits_and_independent_truncation(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    macros = tmp_path / "include" / "macros.h"
    source.parent.mkdir(parents=True)
    macros.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
    macros.write_text(
        "".join(f"#define MACRO_{idx:02d} {idx}\n" for idx in range(51)),
        encoding="utf-8",
    )
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
                for idx in range(51)
            ],
        },
    )
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("Caller")[0]

    assert info["project_callees"] == []
    assert info["external_callees"] == []
    assert len(info["unresolved_callees"]) == 20
    assert info["unresolved_callees_truncation"] == {
        "truncated": True,
        "returned": 20,
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
    assert len(info["referenced_macros"]) == 50
    assert info["referenced_macros_truncation"] == {
        "truncated": True,
        "returned": 50,
        "total": 51,
    }


def test_function_info_omits_truncation_for_untruncated_arrays(tmp_path) -> None:
    source = tmp_path / "src" / "caller.c"
    macros = tmp_path / "include" / "macros.h"
    source.parent.mkdir(parents=True)
    macros.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 0; }\n", encoding="utf-8")
    macros.write_text("#define ONLY_MACRO 1\n", encoding="utf-8")
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

    assert "project_callees_truncation" not in info
    assert "external_callees_truncation" not in info
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

    assert info["project_callees"] == [
        {
            "callee_index_name": "helper@demo.c:3-3",
            "callee_signature": "int helper(void)",
            "is_static": False,
            "callee_summary": "unknown",
            "direct_callsite_lines": [6],
            "indirect_callsites": [],
            }
    ]
    assert info["external_callees"] == []
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
    assert info["referenced_macros"][0]["macro_index_name"] == "ENABLED@demo.c:1-1"
    assert info["referenced_macros"][0]["definition"] == "1 | #define ENABLED 1\n"
    assert info["referenced_macros"][0]["reference_lines"] == [5]


def test_function_info_regex_backend_resolves_only_direct_visible_types(tmp_path) -> None:
    source = tmp_path / "src" / "plugin.c"
    header = tmp_path / "include" / "types.h"
    source.parent.mkdir(parents=True)
    header.parent.mkdir(parents=True)
    header.write_text(
        "typedef struct Plugin { int id; } Plugin;\n"
        "typedef struct PluginRegistry { Plugin *plugins; } PluginRegistry;\n",
        encoding="utf-8",
    )
    source.write_text(
        '#include "../include/types.h"\n'
        "int register_plugin(PluginRegistry *registry) {\n"
        "    Plugin *plugin = (Plugin *)0;\n"
        "    return registry->plugins != plugin;\n"
        "}\n",
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    info = index.find_function_infos("register_plugin")[0]

    assert [item["type_index_name"] for item in info["referenced_types"]] == [
        "Plugin@include/types.h:1-1",
        "PluginRegistry@include/types.h:2-2",
    ]
    by_identity = {
        item["type_index_name"]: item for item in info["referenced_types"]
    }
    assert by_identity["Plugin@include/types.h:1-1"]["reference_kinds"] == [
        "local",
        "cast",
    ]
    assert by_identity["PluginRegistry@include/types.h:2-2"]["reference_kinds"] == [
        "parameter",
        "member_access",
    ]
    assert by_identity["Plugin@include/types.h:1-1"]["full_definition"] == (
        "1 | typedef struct Plugin { int id; } Plugin;\n"
    )
    assert "unresolved_referenced_types" not in info


def test_function_info_classifies_static_functions_and_function_like_macros(tmp_path) -> None:
    source = tmp_path / "demo.c"
    source.write_text(
        "#define WRAP(value) helper(value)\n"
        "static int helper(int value) { return value; }\n"
        "int caller(int value) { return WRAP(value) + helper(value); }\n",
        encoding="utf-8",
    )
    index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        indexing_config=SimpleNamespace(backend="regex"),
    )

    info = index.find_function_infos("caller")[0]

    assert info["external_callees"] == []
    assert info["project_callees"] == [
        {
            "callee_index_name": "helper@demo.c:2-2",
            "callee_signature": "static int helper(int value)",
            "is_static": True,
            "callee_summary": "unknown",
            "direct_callsite_lines": [3],
            "indirect_callsites": [],
        },
    ]
    assert info["referenced_macros"] == [
        {
            "macro_index_name": "WRAP@demo.c:1-1",
            "definition": "1 | #define WRAP(value) helper(value)\n",
            "is_function_like": True,
            "reference_lines": [3],
        }
    ]


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
    assert "does not include referenced" in tool_schema["description"]
    assert "does not include referenced" in runtime_schema["description"]
    assert "callers" not in tool_result["data"]["matches"][0]
    for field in (
        "referenced_globals",
        "referenced_macros",
        "referenced_types",
        "referenced_globals_truncation",
        "referenced_macros_truncation",
        "referenced_types_truncation",
        "unresolved_referenced_types",
    ):
        assert field not in tool_result["data"]["matches"][0]
    assert runtime_result["success"] is True
    assert runtime_result["data"]["match_count"] == 1
    assert backend.type_context_calls == 0


def test_type_backend_error_cannot_be_reported_as_empty_context(tmp_path, monkeypatch):
    import pytest
    from zscope.retrieval.clang_type_state import TypeContextUnavailable
    from zscope.snapshots.modeling_input import SemanticModelInputError

    (tmp_path / "a.c").write_text("int Target(void) { return 0; }\n", encoding="utf-8")
    backend = FunctionInfoBackend({"Target": {
        "name": "Target", "file": "a.c", "start_line": 1, "end_line": 1,
        "signature": "int Target(void)"}})
    index = _index(tmp_path, backend, "unified")

    def failed_context(*args):
        raise RuntimeError("injected database failure")

    monkeypatch.setattr(backend, "get_function_type_context", failed_context)
    assert GetFunctionInfoTool(index).execute({"func_name": "Target"})["success"]
    with pytest.raises(TypeContextUnavailable, match="database failure"):
        index.get_function_type_context("Target", "a.c", 1)
    with pytest.raises(SemanticModelInputError) as error:
        build_semantic_model_input(index, "Target", file_path="a.c")
    assert error.value.reason == "type_context_unavailable"


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
        "project_callees": [],
        "external_callees": [],
        "unresolved_callees": [
            {
                "callee_name": "alloc",
                "direct_callsite_lines": [2],
                "indirect_callsites": [],
            }
        ],
    }
    assert runtime_result == result
    raw_match = index.find_function_infos(match["index_name"])[0]
    assert raw_match["referenced_macros"] == [
        {
            "macro_index_name": "GLOBAL_LIMIT@include/macros.h:4-4",
            "definition": "4 | #define GLOBAL_LIMIT 8\n",
            "is_function_like": False,
            "reference_lines": [3],
        }
    ]
    for field in (
        "referenced_globals",
        "referenced_macros",
        "referenced_types",
        "referenced_globals_truncation",
        "referenced_macros_truncation",
        "referenced_types_truncation",
        "unresolved_referenced_types",
    ):
        assert field not in match
    assert index.find_function_infos("GLOBAL_LIMIT") == []


def test_backend_macro_symbol_context_uses_regex_candidates_and_db_definitions(
    tmp_path,
) -> None:
    source = tmp_path / "src" / "macro.c"
    source.parent.mkdir(parents=True)
    source.write_text(
        "#define TARGET(arg) do { \\\n"
        "    UNLOCK(&g_lock); \\\n"
        "    consume((arg), OBJECT_LIMIT, NOT_CALLED, \"GHOST_GLOBAL\"); \\\n"
        "    AMBIG(); /* GHOST_MACRO */ \\\n"
        "} while (0)\n"
        "static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;\n",
        encoding="utf-8",
    )
    include = tmp_path / "include"
    include.mkdir()
    common_lines = ["\n"] * 42
    common_lines[33] = "#define UNLOCK(mutex) unlock_impl(mutex)\n"
    common_lines[39] = "#define OBJECT_LIMIT 64\n"
    common_lines[40] = "#define NOT_CALLED() 1\n"
    common_lines[41] = "#define GHOST_MACRO 1\n"
    (include / "common.h").write_text("".join(common_lines), encoding="utf-8")
    (include / "left.h").write_text("#define AMBIG() left_impl()\n", encoding="utf-8")
    (include / "right.h").write_text("#define AMBIG() right_impl()\n", encoding="utf-8")
    macro_definitions = {
        "TARGET": [
            {
                "name": "TARGET",
                "file_path": "src/macro.c",
                "line": 1,
                "definition": source.read_text(encoding="utf-8").split(
                    "static pthread_mutex_t", 1
                )[0],
                "is_function_like": 1,
            }
        ],
        "UNLOCK": [
            {
                "name": "UNLOCK",
                "file_path": "include/common.h",
                "line": 34,
                "definition": "#define UNLOCK(mutex) unlock_impl(mutex)\n",
                "is_function_like": 1,
            }
        ],
        "AMBIG": [
            {
                "name": "AMBIG",
                "file_path": "include/left.h",
                "line": 1,
                "definition": "#define AMBIG() left_impl()\n",
                "is_function_like": 1,
            },
            {
                "name": "AMBIG",
                "file_path": "include/right.h",
                "line": 1,
                "definition": "#define AMBIG() right_impl()\n",
                "is_function_like": 1,
            },
        ],
    }
    symbol_definitions = {
        "globals": [
            {
                "name": "g_lock",
                "type_str": "pthread_mutex_t",
                "file_path": "src/macro.c",
                "line": 6,
                "storage_class": "static",
                "qualifiers": "",
                "initializer": "PTHREAD_MUTEX_INITIALIZER",
            },
            {
                "name": "g_lock",
                "type_str": "pthread_mutex_t",
                "file_path": "src/other.c",
                "line": 10,
                "storage_class": "static",
                "qualifiers": "",
                "initializer": "",
            },
            {
                "name": "GHOST_GLOBAL",
                "type_str": "int",
                "file_path": "src/macro.c",
                "line": 7,
                "storage_class": "static",
            },
        ],
        "macros": [
            *macro_definitions["UNLOCK"],
            {
                "name": "OBJECT_LIMIT",
                "file_path": "include/common.h",
                "line": 40,
                "definition": "#define OBJECT_LIMIT 64\n",
                "is_function_like": 0,
            },
            {
                "name": "NOT_CALLED",
                "file_path": "include/common.h",
                "line": 41,
                "definition": "#define NOT_CALLED() 1\n",
                "is_function_like": 1,
            },
            *macro_definitions["AMBIG"],
            {
                "name": "GHOST_MACRO",
                "file_path": "include/common.h",
                "line": 42,
                "definition": "#define GHOST_MACRO 1\n",
                "is_function_like": 0,
            },
        ],
    }
    backend = MacroSymbolBackend(macro_definitions, symbol_definitions)
    index = _index(tmp_path, backend, "unified")

    info = index.find_function_infos("TARGET")[0]
    semantic_input = build_semantic_model_input(
        index,
        "TARGET",
        index_name="TARGET@src/macro.c:1-5",
        file_path="src/macro.c",
        start_line=1,
    )

    assert info["referenced_globals"] == []
    assert info["referenced_macros"] == [
        {
            "macro_index_name": "OBJECT_LIMIT@include/common.h:40-40",
            "definition": "40 | #define OBJECT_LIMIT 64\n",
            "is_function_like": False,
            "reference_lines": [3],
        },
        {
            "macro_index_name": "UNLOCK@include/common.h:34-34",
            "definition": "34 | #define UNLOCK(mutex) unlock_impl(mutex)\n",
            "is_function_like": True,
            "reference_lines": [2],
        },
    ]
    assert semantic_input["referenced_globals"] == []
    assert semantic_input["referenced_macros"] == info["referenced_macros"]
    assert "UNLOCK@include/common.h:34-34" not in {
        item["callee_index_name"] for item in info["project_callees"]
    }
    assert all("GHOST" not in name for name in backend.symbol_definition_queries[0])


def test_backend_macro_symbol_context_truncates_only_resolved_macros(tmp_path) -> None:
    source = tmp_path / "many.h"
    macros = tmp_path / "macros.h"
    names = [f"MACRO_{idx:02d}" for idx in range(51)]
    source.write_text(
        f"#define MANY() ({' + '.join(names + ['AMBIGUOUS'])})\n",
        encoding="utf-8",
    )
    macros.write_text(
        "".join(f"#define {name} {idx}\n" for idx, name in enumerate(names)),
        encoding="utf-8",
    )
    (tmp_path / "left.h").write_text("#define AMBIGUOUS 1\n", encoding="utf-8")
    (tmp_path / "right.h").write_text("#define AMBIGUOUS 1\n", encoding="utf-8")
    macro_definitions = {
        "MANY": [
            {
                "name": "MANY",
                "file_path": "many.h",
                "line": 1,
                "definition": source.read_text(encoding="utf-8"),
                "is_function_like": 1,
            }
        ]
    }
    symbol_definitions = {
        "globals": [],
        "macros": [
            {
                "name": name,
                "file_path": "macros.h",
                "line": idx + 1,
                "definition": f"#define {name} {idx}\n",
                "is_function_like": 0,
            }
            for idx, name in enumerate(names)
        ]
        + [
            {
                "name": "AMBIGUOUS",
                "file_path": file_path,
                "line": 1,
                "definition": "#define AMBIGUOUS 1\n",
                "is_function_like": 0,
            }
            for file_path in ("left.h", "right.h")
        ],
    }
    index = _index(
        tmp_path,
        MacroSymbolBackend(macro_definitions, symbol_definitions),
        "unified",
    )

    info = index.find_function_infos("MANY")[0]

    assert info["referenced_globals"] == []
    assert len(info["referenced_macros"]) == 50
    assert info["referenced_macros_truncation"] == {
        "truncated": True,
        "returned": 50,
        "total": 51,
    }
    assert all(
        not item["macro_index_name"].startswith("AMBIGUOUS@")
        for item in info["referenced_macros"]
    )


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
        "project_callees",
            "external_callees",
            "unresolved_callees",
        "referenced_globals",
        "referenced_macros",
        "referenced_types",
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
        "project_callees": [],
        "external_callees": [],
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
