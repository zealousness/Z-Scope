from types import SimpleNamespace

from zscope.framework.llm_client import LLMClient
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.retrieval.unified_backend import UnifiedBackend
from zscope.tools.callers import GetCallersTool


class RecordingCallerIndex:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def find_function_callers(self, func_name, file_path="", limit=20):
        self.calls.append((func_name, file_path, limit))
        return self.result


class CallerBackend:
    def __init__(self, function_index, callers):
        self.function_index = function_index
        self.callers = callers
        self.calls = []

    def build_function_index(self):
        return self.function_index

    def get_function_info_callers(self, func_name, file_path=""):
        self.calls.append((func_name, file_path))
        return list(self.callers)

    def get_callers(self, func_name, limit=20, callee_file=""):
        return list(self.callers)[:limit]

    def get_callees(self, func_name, limit=30):
        return []

    def get_method_callees(self, name, limit=30):
        return []

    def close(self):
        pass


def _function(name, file_path, start_line=1, end_line=3):
    return {
        "name": name,
        "file": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "signature": f"int {name}(void)",
    }


def _index(tmp_path, backend):
    return CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=backend,
        indexing_config=SimpleNamespace(backend="unified"),
    )


def test_get_callers_schema_exposes_identity_file_and_limit() -> None:
    tool = GetCallersTool(RecordingCallerIndex({"match_count": 1, "callers": []}))

    parameters = tool.get_schema()["function"]["parameters"]

    assert parameters == {
        "type": "object",
        "properties": {
            "func_name": {
                "type": "string",
                "description": (
                    "Function or function-like macro name, qualified name, "
                    "or index_name for exact match."
                ),
            },
            "file_path": {
                "type": "string",
                "description": "Optional source file path used to disambiguate same-name targets.",
            },
            "limit": {
                "type": "integer",
                "description": (
                    "Optional maximum number of callers to return (default 20, max 200)."
                ),
            },
        },
        "required": ["func_name"],
    }


def test_get_callers_default_window_reports_count_and_truncation() -> None:
    callers = [
        {
            "caller_index_name": "Caller@src/caller.c:1-3",
            "callsite_lines": [7],
            "call_type": ["direct"],
        }
    ]
    index = RecordingCallerIndex({"match_count": 1, "callers": callers})
    tool = GetCallersTool(index)

    result = tool.execute(
        {
            "func_name": "Target@src/target.c:1-3",
            "file_path": "src/target.c",
        }
    )

    assert result == {
        "success": True,
        "data": {"callers": callers, "caller_count": 1, "truncated": False},
    }
    # One extra row is fetched so overflow beyond the window is detectable.
    assert index.calls == [("Target@src/target.c:1-3", "src/target.c", 21)]


def test_get_callers_reports_truncation_and_honors_limit_parameter() -> None:
    callers = [
        {"caller_index_name": f"Caller{i}@src/caller{i}.c:1-3", "callsite_lines": [i]}
        for i in range(5)
    ]
    index = RecordingCallerIndex({"match_count": 1, "callers": callers})
    tool = GetCallersTool(index)

    result = tool.execute({"func_name": "Target", "limit": 2})

    data = result["data"]
    assert data["callers"] == callers[:2]
    assert data["caller_count"] == 2
    assert data["truncated"] is True
    assert "larger limit" in data["note"]
    assert index.calls == [("Target", "", 3)]


def test_get_callers_clamps_limit_to_configured_maximum() -> None:
    index = RecordingCallerIndex({"match_count": 1, "callers": []})
    tool = GetCallersTool(index)

    tool.execute({"func_name": "Target", "limit": 100000})

    assert index.calls == [("Target", "", 201)]


def test_get_callers_reports_missing_and_ambiguous_targets() -> None:
    missing = GetCallersTool(
        RecordingCallerIndex({"match_count": 0, "callers": []})
    ).execute({"func_name": "missing"})
    ambiguous = GetCallersTool(
        RecordingCallerIndex({"match_count": 2, "callers": []})
    ).execute({"func_name": "Target"})

    assert missing == {
        "success": False,
        "error": "Function 'missing' not found",
        "reason": "function_not_found",
    }
    assert ambiguous == {
        "success": False,
        "error": "Function 'Target' is ambiguous; provide file_path or index_name",
        "reason": "ambiguous_function",
        "match_count": 2,
    }


def test_get_callers_no_longer_injects_hidden_limit_into_tool_signature() -> None:
    arguments = {"func_name": "Target", "file_path": "src/target.c"}

    assert LLMClient._normalize_tool_args("get_callers", arguments) == arguments


def test_code_index_aggregates_caller_identity_lines_and_call_types(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "target.c").write_text(
        "int Target(void) { return 0; }\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "caller.c").write_text(
        "int Caller(void) { return Target(); }\n",
        encoding="utf-8",
    )
    backend = CallerBackend(
        {
            "Target": _function("Target", "src/target.c"),
            "Caller": _function("Caller", "src/caller.c"),
        },
        [
            {
                "name": "Caller",
                "filename": "src/caller.c",
                "lineNumber": 7,
                "call_type": "direct",
            },
            {
                "name": "Caller",
                "filename": "src/caller.c",
                "call_line": 9,
                "source": "svf",
                "call_type": "indirect",
            },
            {
                "name": "Caller",
                "filename": "src/caller.c",
                "call_line": 7,
                "call_type": "invalid",
            },
        ],
    )
    code_index = _index(tmp_path, backend)
    caller_index_name = code_index.find_function_infos("Caller")[0]["index_name"]
    target_index_name = code_index.find_function_infos("Target")[0]["index_name"]

    result = code_index.find_function_callers("Target", limit=20)
    exact_result = code_index.find_function_callers(target_index_name, limit=20)

    assert result == {
        "match_count": 1,
        "callers": [
            {
                "caller_index_name": caller_index_name,
                "callsite_lines": [7, 9],
                "call_type": ["direct", "indirect"],
            }
        ],
    }
    assert exact_result == result
    assert backend.calls == [
        ("Target", "src/target.c"),
        ("Target", "src/target.c"),
    ]


def test_code_index_requires_unique_target_or_file_disambiguation(tmp_path) -> None:
    (tmp_path / "src" / "a").mkdir(parents=True)
    (tmp_path / "src" / "b").mkdir(parents=True)
    for path in ("src/a/target.c", "src/b/target.c"):
        (tmp_path / path).write_text(
            "int Target(void) { return 0; }\n",
            encoding="utf-8",
        )
    backend = CallerBackend(
        {
            "TargetA": _function("Target", "src/a/target.c"),
            "TargetB": _function("Target", "src/b/target.c"),
        },
        [
            {
                "name": "UnknownCaller",
                "source": "svf",
                "call_type": "indirect",
            }
        ],
    )
    code_index = _index(tmp_path, backend)

    ambiguous = code_index.find_function_callers("Target")
    resolved = code_index.find_function_callers(
        "Target",
        file_path="src/b/target.c",
    )

    assert ambiguous == {"match_count": 2, "callers": []}
    assert resolved == {"match_count": 1, "callers": []}
    assert backend.calls == [("Target", "src/b/target.c")]


def test_code_index_supports_function_like_macro_callers(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "macros.h").write_text(
        "#define WRAP() 0\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "caller.c").write_text(
        "int Caller(void) { return WRAP(); }\n",
        encoding="utf-8",
    )
    backend = CallerBackend(
        {"Caller": _function("Caller", "src/caller.c")},
        [
            {
                "name": "Caller",
                "filename": "src/caller.c",
                "lineNumber": 1,
                "call_type": "direct",
            }
        ],
    )
    code_index = _index(tmp_path, backend)
    caller_index_name = code_index.find_function_infos("Caller")[0]["index_name"]
    expected = {
        "match_count": 1,
        "callers": [
            {
                "caller_index_name": caller_index_name,
                "callsite_lines": [1],
                "call_type": ["direct"],
            }
        ],
    }

    assert code_index.find_function_callers("WRAP") == expected
    assert code_index.find_function_callers("WRAP@src/macros.h:1-1") == expected
    assert backend.calls == [("WRAP", "src/macros.h"), ("WRAP", "src/macros.h")]


def test_code_index_groups_conditional_macro_definitions_by_symbol_file(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "macros.h").write_text(
        "#if ENABLED\n"
        "#define WRAP() 1\n"
        "#else\n"
        "#define WRAP() 0\n"
        "#endif\n",
        encoding="utf-8",
    )
    backend = CallerBackend({}, [])
    code_index = _index(tmp_path, backend)

    assert code_index.find_function_callers(
        "WRAP",
        file_path="src/macros.h",
    ) == {"match_count": 1, "callers": []}
    assert backend.calls == [("WRAP", "src/macros.h")]


def test_code_index_requires_file_disambiguation_for_same_name_macros(tmp_path) -> None:
    (tmp_path / "include" / "a").mkdir(parents=True)
    (tmp_path / "include" / "b").mkdir(parents=True)
    for path in ("include/a/macros.h", "include/b/macros.h"):
        (tmp_path / path).write_text("#define WRAP() 0\n", encoding="utf-8")
    backend = CallerBackend({}, [])
    code_index = _index(tmp_path, backend)

    assert code_index.find_function_callers("WRAP") == {
        "match_count": 2,
        "callers": [],
    }
    assert code_index.find_function_callers(
        "WRAP",
        file_path="include/b/macros.h",
    ) == {"match_count": 1, "callers": []}
    assert backend.calls == [("WRAP", "include/b/macros.h")]


def test_unified_backend_preserves_direct_and_indirect_caller_evidence(tmp_path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    backend = UnifiedBackend(db_path=str(tmp_path / "unused.db"))
    backend._clang._db = db
    try:
        db.insert_call_edge(
            "Caller",
            "src/caller.c",
            "Target",
            "src/target.c",
            11,
            call_type="direct",
        )
        db.insert_indirect_call(
            "Caller",
            "Target",
            call_file="src/caller.c",
            call_line=17,
        )
        db.commit()

        rows = backend.get_function_info_callers(
            "Target",
            file_path="src/target.c",
        )

        assert rows == [
            {
                "name": "Caller",
                "filename": "src/caller.c",
                "lineNumber": 11,
                "call_type": "direct",
                "callee_kind": "unknown",
            },
            {
                "name": "Caller",
                "filename": "src/caller.c",
                "call_line": 17,
                "source": "svf-ander",
                "confidence": 1.0,
                "svf_groups": ["default"],
                "call_type": "indirect",
            },
        ]
    finally:
        backend._clang._db = None
        db.close()
