from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.joern_backend import JoernBackend
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.tools.runtime import ToolsRuntime
from zscope.tools.type_info import GetTypeInfoTool


class EmptySnapshotStore:
    pass


class RecordingTypeIndex:
    def __init__(self, matches_by_file):
        self.matches_by_file = matches_by_file
        self.calls = []

    def find_type_infos(self, type_name, file_path=""):
        self.calls.append((type_name, file_path))
        return list(self.matches_by_file.get(file_path, []))


class LegacyTypeBackend:
    def build_function_index(self):
        return {}

    def get_type_info(self, type_name):
        if type_name != "Legacy":
            return None
        return {
            "id": 7,
            "name": "Legacy",
            "kind": "struct",
            "file_path": "include/legacy.h",
            "start_line": 3,
            "end_line": 6,
            "tu_id": 4,
            "members": [],
        }

    def get_method_callees(self, name, limit=30):
        return []

    def get_callers(self, func_name, limit=20, callee_file=""):
        return []

    def get_callees(self, func_name, limit=30):
        return []

    def close(self):
        pass


class FakeJoernClient:
    def get_type_decls(self, name):
        assert name == "State"
        return [
            {
                "name": "State",
                "filename": "include/a.h",
                "lineNumber": 10,
                "lineNumberEnd": 14,
                "full_definition": "typedef struct { int a; } State;",
            },
            {
                "name": "State",
                "filename": "include/b.h",
                "lineNumber": 20,
                "lineNumberEnd": 24,
                "full_definition": "typedef struct { char b; } State;",
            },
        ]


class RecordingTypeDB:
    def __init__(self):
        self.types = []

    def insert_type(
        self,
        name,
        kind,
        file_path,
        start_line,
        end_line,
        full_definition="",
        tu_id=None,
    ):
        self.types.append(
            {
                "name": name,
                "kind": kind,
                "file_path": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "full_definition": full_definition,
                "tu_id": tu_id,
            }
        )
        return 1

    def insert_type_member(self, *args, **kwargs):
        pass


def _match(file_path, member_name="value"):
    return {
        "id": 9,
        "name": "State",
        "kind": "struct",
        "file_path": file_path,
        "start_line": 1,
        "end_line": 4,
        "full_definition": "struct State { int value; };",
        "tu_id": 3,
        "members": [
            {
                "member_name": member_name,
                "member_type": "int",
                "offset_idx": 0,
            }
        ],
    }


def test_get_type_info_schema_accepts_optional_file_path() -> None:
    tool = GetTypeInfoTool(RecordingTypeIndex({}))

    parameters = tool.get_schema()["function"]["parameters"]

    assert parameters == {
        "type": "object",
        "properties": {
            "type_name": {
                "type": "string",
                "description": "Struct, union, enum, typedef, class, or qualified type name.",
            },
            "file_path": {
                "type": "string",
                "description": (
                    "Optional source or header path used to disambiguate same-name types. "
                    "If it has no matches, the tool retries once without this filter."
                ),
            },
        },
        "required": ["type_name"],
    }


def test_get_type_info_returns_match_count_and_sanitized_matches() -> None:
    index = RecordingTypeIndex(
        {
            "": [
                _match("include/a.h", "left"),
                _match("include/b.h", "right"),
            ]
        }
    )
    tool = GetTypeInfoTool(index)

    result = tool.execute({"type_name": "State"})

    assert result["success"] is True
    assert result["data"]["match_count"] == 2
    assert [item["file_path"] for item in result["data"]["matches"]] == [
        "include/a.h",
        "include/b.h",
    ]
    assert all("id" not in item for item in result["data"]["matches"])
    assert all("tu_id" not in item for item in result["data"]["matches"])
    assert all("members" not in item for item in result["data"]["matches"])
    assert all(item["full_definition"] for item in result["data"]["matches"])


def test_get_type_info_passes_file_path_and_keeps_missing_failure() -> None:
    index = RecordingTypeIndex({"include/a.h": [_match("include/a.h")]})
    tool = GetTypeInfoTool(index)

    found = tool.execute({"type_name": "State", "file_path": "include/a.h"})
    missing = tool.execute({"type_name": "State", "file_path": "include/missing.h"})

    assert found["data"]["match_count"] == 1
    assert missing == {"success": False, "error": "Type 'State' not found"}
    assert index.calls == [
        ("State", "include/a.h"),
        ("State", "include/missing.h"),
        ("State", ""),
    ]


def test_get_type_info_retries_without_wrong_file_path_and_returns_all_matches() -> None:
    index = RecordingTypeIndex(
        {
            "": [
                _match("include/a.h", "left"),
                _match("include/b.h", "right"),
            ]
        }
    )
    tool = GetTypeInfoTool(index)

    result = tool.execute(
        {"type_name": "State", "file_path": "include/wrong.h"}
    )

    assert result == {
        "success": True,
        "file_path_fallback": {
            "reason": "file_path_not_matched",
            "requested_file_path": "include/wrong.h",
            "message": (
                "The supplied file_path did not match the requested type. "
                "The following matches are results from a query without file_path."
            ),
        },
        "data": {
            "match_count": 2,
            "matches": [
                {
                    "name": "State",
                    "kind": "struct",
                    "file_path": "include/a.h",
                    "start_line": 1,
                    "end_line": 4,
                    "full_definition": "struct State { int value; };",
                },
                {
                    "name": "State",
                    "kind": "struct",
                    "file_path": "include/b.h",
                    "start_line": 1,
                    "end_line": 4,
                    "full_definition": "struct State { int value; };",
                },
            ],
        },
    }
    assert "query_scope" not in result["file_path_fallback"]
    assert index.calls == [
        ("State", "include/wrong.h"),
        ("State", ""),
    ]


def test_knowledge_db_public_matches_keep_definition_and_hide_derived_members(tmp_path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        left_tu = db.register_tu("src/left.c", 1.0)
        right_tu = db.register_tu("src/right.c", 1.0)
        left_id = db.insert_type(
            "State",
            "struct",
            "include/a.h",
            10,
            14,
            "struct State { int left; };",
            tu_id=left_tu,
        )
        right_id = db.insert_type(
            "State",
            "union",
            "include/b.h",
            20,
            24,
            "union State { char right; };",
            tu_id=right_tu,
        )
        db.insert_type_member(left_id, "left", "int", 0)
        db.insert_type_member(right_id, "right", "char", 0)
        db.commit()

        matches = db.find_type_infos("State")
        scoped = db.find_type_infos("State", file_path="include/b.h")
        internal = db.get_type_info("State")

        assert [(item["file_path"], item["kind"]) for item in matches] == [
            ("include/a.h", "struct"),
            ("include/b.h", "union"),
        ]
        assert all("members" not in item for item in matches)
        assert matches[0]["full_definition"] == "struct State { int left; };"
        assert matches[1]["full_definition"] == "union State { char right; };"
        assert all("id" not in item and "tu_id" not in item for item in matches)
        assert [item["file_path"] for item in scoped] == ["include/b.h"]
        assert internal is not None
        assert "id" in internal
        assert "tu_id" in internal
        assert [member["member_name"] for member in internal["members"]] == ["left"]
    finally:
        db.close()


def test_code_index_wraps_legacy_single_result_backend(tmp_path) -> None:
    code_index = CodeIndex(
        tmp_path,
        source_root=tmp_path,
        backend=LegacyTypeBackend(),
        indexing_config=SimpleNamespace(backend="joern"),
    )

    matches = code_index.find_type_infos("Legacy")
    wrong_file = code_index.find_type_infos("Legacy", file_path="include/other.h")

    assert matches == [
        {
            "name": "Legacy",
            "kind": "struct",
            "file_path": "include/legacy.h",
            "start_line": 3,
            "end_line": 6,
        }
    ]
    assert wrong_file == []


def test_joern_backend_returns_each_type_declaration_definition() -> None:
    backend = JoernBackend(joern_client=FakeJoernClient())

    matches = backend.find_type_infos("State")
    scoped = backend.find_type_infos("State", file_path="include/b.h")

    assert [item["filename"] for item in matches] == ["include/a.h", "include/b.h"]
    assert matches[0]["full_definition"] == "typedef struct { int a; } State;"
    assert matches[1]["full_definition"] == "typedef struct { char b; } State;"
    assert all("members" not in item for item in matches)
    assert [item["filename"] for item in scoped] == ["include/b.h"]


@pytest.mark.parametrize(
    ("definition", "symbol_name", "symbol_kind", "expected_kind"),
    [
        (
            "typedef struct {\n    int value;\n} TaskConfig;",
            "TaskConfig",
            ClangExtractor.SK_CLASS,
            "struct",
        ),
        (
            "typedef union {\n    int code;\n} Payload;",
            "Payload",
            ClangExtractor.SK_CLASS,
            "union",
        ),
        (
            "class Widget {\n    int value;\n};",
            "Widget",
            ClangExtractor.SK_CLASS,
            "class",
        ),
        (
            "enum Mode {\n    MODE_A,\n    MODE_B\n};",
            "Mode",
            ClangExtractor.SK_ENUM,
            "enum",
        ),
    ],
)
def test_clang_extractor_uses_source_for_type_kind_and_definition(
    tmp_path,
    definition,
    symbol_name,
    symbol_kind,
    expected_kind,
) -> None:
    source = tmp_path / "types.h"
    source.write_text(definition, encoding="utf-8")
    lines = definition.splitlines()
    extractor = ClangExtractor(project_root=tmp_path)
    db = RecordingTypeDB()

    extractor._process_symbol(
        {
            "kind": symbol_kind,
            "name": symbol_name,
            "range": {
                "start": {"line": 0, "character": 0},
                "end": {
                    "line": len(lines) - 1,
                    "character": len(lines[-1]),
                },
            },
        },
        source,
        "types.h",
        9,
        db,
        [],
        [],
    )

    assert db.types == [
        {
            "name": symbol_name,
            "kind": expected_kind,
            "file_path": "types.h",
            "start_line": 1,
            "end_line": len(lines),
            "full_definition": definition,
            "tu_id": 9,
        }
    ]


def test_runtime_type_info_negative_cache_is_scoped_by_file_path() -> None:
    index = RecordingTypeIndex({"include/b.h": [_match("include/b.h")]})
    tool = GetTypeInfoTool(index)
    runtime = ToolsRuntime(
        index,
        EmptySnapshotStore(),
        tools=[tool],
    )

    first = runtime.execute_tool(
        "get_type_info",
        {"type_name": "State", "file_path": "include/a.h"},
    )
    cached = runtime.execute_tool(
        "get_type_info",
        {"type_name": "State", "file_path": "include/a.h"},
    )
    other_file = runtime.execute_tool(
        "get_type_info",
        {"type_name": "State", "file_path": "include/b.h"},
    )

    assert first["success"] is False
    assert cached["cached_negative_result"] is True
    assert other_file["success"] is True
    assert index.calls == [
        ("State", "include/a.h"),
        ("State", ""),
        ("State", "include/b.h"),
    ]


def test_runtime_does_not_negative_cache_successful_file_path_fallback() -> None:
    index = RecordingTypeIndex({"": [_match("include/b.h")]})
    runtime = ToolsRuntime(
        index,
        EmptySnapshotStore(),
        tools=[GetTypeInfoTool(index)],
    )
    arguments = {"type_name": "State", "file_path": "include/wrong.h"}

    first = runtime.execute_tool("get_type_info", arguments)
    second = runtime.execute_tool("get_type_info", arguments)

    assert first["success"] is True
    assert second["success"] is True
    assert "cached_negative_result" not in second
    assert index.calls == [
        ("State", "include/wrong.h"),
        ("State", ""),
        ("State", "include/wrong.h"),
        ("State", ""),
    ]


def test_semantic_modeler_policy_distinguishes_multi_match_tools() -> None:
    agent_text = (
        Path(__file__).resolve().parents[1]
        / "zscope"
        / "agents"
        / "semantic_modeler"
        / "AGENT.md"
    ).read_text(encoding="utf-8")

    assert "`get_function_info` and `get_type_info` may return multiple matches" in agent_text
    assert "`get_function_snapshot` and `get_callers` require a unique match" in agent_text
