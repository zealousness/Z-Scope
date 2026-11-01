from __future__ import annotations

import json
import threading
from pathlib import Path
from types import SimpleNamespace

from zscope.retrieval.java_source_backend import JavaSourceBackend
from zscope.tools.code_graph_query import QueryCodeGraphTool
from zscope.tools.data_flow_trace import TraceDataFlowTool
from zscope.tools.read_code import ReadCodeTool
from zscope.tools.registry import build_tool_registry
from zscope.tools.search_code import SearchCodeTool
from zscope.tools.semantic_context import SemanticContextTool
from zscope.tools.static_findings import QueryStaticFindingsTool
from zscope.tools.symbols import SymbolCatalog, classify_direct_literal


def _value(name: str, *, kind: str = "local", index: int | None = None) -> dict:
    result = {
        "name": name,
        "qualified_name": name,
        "usr": f"usr:{name}",
        "value_kind": kind,
        "expression": name,
        "identity_complete": True,
    }
    if index is not None:
        result["index"] = index
    return result


def _location(file: str, line: int, column: int = 1) -> dict:
    return {"file": file, "line": line, "column": column}


class SnapshotStore:
    snapshot_dir = Path(".zscope_snapshots")

    def load_snapshot(self, _name):
        return None

    def list_snapshots(self):
        return []


class MutableSnapshotStore(SnapshotStore):
    def __init__(self, root: Path, snapshot=None, *, stale: bool = False) -> None:
        self.snapshot_dir = root / ".zscope_snapshots"
        self.snapshot = snapshot
        self.stale = stale

    def load_snapshot(self, _name):
        return self.snapshot

    def needs_refresh(self, _name, _code, _context):
        return self.stale, "source_changed" if self.stale else "current"


class EvidenceCodeIndex:
    backend_name = "clang"
    language = "c_cpp"

    def __init__(self, root: Path) -> None:
        self.project_root = root
        self.source_root = root
        self._index_epoch = 1
        self._backend = object()
        self._function_index = {
            "root": {
                "name": "root",
                "qualified_name": "root",
                "signature": "void root(int user_len)",
                "file": "src/demo.c",
                "start_line": 5,
                "end_line": 10,
                "index_name": "root",
                "usr": "usr:root",
            },
            "helper": {
                "name": "helper",
                "qualified_name": "helper",
                "signature": "void helper(int forwarded)",
                "file": "src/demo.c",
                "start_line": 12,
                "end_line": 15,
                "index_name": "helper",
                "usr": "usr:helper",
            },
            "same@a": {
                "name": "same",
                "qualified_name": "same",
                "signature": "int same(int)",
                "file": "src/a.c",
                "start_line": 2,
                "end_line": 2,
                "index_name": "same@a",
            },
            "same@b": {
                "name": "same",
                "qualified_name": "same",
                "signature": "int same(const char *)",
                "file": "src/b.c",
                "start_line": 2,
                "end_line": 2,
                "index_name": "same@b",
            },
        }
        self._facts = {}

    def _get_macro_definition_index(self):
        return {
            "MAX_RETRIES": [
                {
                    "name": "MAX_RETRIES",
                    "file_path": "include/config.h",
                    "start_line": 1,
                    "end_line": 1,
                    "definition": "#define MAX_RETRIES (3U)",
                    "is_function_like": False,
                }
            ],
            "MASK": [
                {
                    "name": "MASK",
                    "file_path": "include/config.h",
                    "start_line": 2,
                    "end_line": 2,
                    "definition": "#define MASK (1U << 4)",
                    "is_function_like": False,
                }
            ],
            "APPLY": [
                {
                    "name": "APPLY",
                    "file_path": "include/config.h",
                    "start_line": 3,
                    "end_line": 3,
                    "definition": "#define APPLY(x) ((x) + 1)",
                    "is_function_like": True,
                }
            ],
            "MULTILINE": [
                {
                    "name": "MULTILINE",
                    "file_path": "include/config.h",
                    "start_line": 4,
                    "end_line": 5,
                    "definition": "#define MULTILINE(x) \\\n  ((x) + 1)",
                    "is_function_like": True,
                }
            ],
        }

    def _get_regex_type_definition_index(self):
        return {}

    def _get_global_definition_index(self):
        return {}

    def resolve_existing_file(self, file_path):
        candidate = self.project_root / str(file_path)
        return candidate if candidate.is_file() else None

    def _read_file_lines(self, path):
        return Path(path).read_text(encoding="utf-8").splitlines(True)

    def _normalize_path(self, path):
        return Path(path).resolve().relative_to(self.project_root.resolve()).as_posix()

    def get_file_snippet(
        self, file_path, start_line, end_line, max_lines=500, default_max_lines=200
    ):
        path = self.resolve_existing_file(file_path)
        if path is None:
            return None
        lines = self._read_file_lines(path)
        requested_end = end_line or (start_line + default_max_lines - 1)
        actual_end = min(len(lines), requested_end, start_line + max_lines - 1)
        return {
            "file": Path(file_path).as_posix(),
            "start_line": start_line,
            "end_line": actual_end,
            "code": "".join(
                f"{line_number} | {lines[line_number - 1]}"
                for line_number in range(start_line, actual_end + 1)
            ),
            "total_lines": len(lines),
            "truncated": actual_end < requested_end,
        }

    def get_type_info(self, _name):
        return None

    def find_type_infos(self, _name, file_path=""):
        return []

    def get_function_program_facts(self, function_name, file_path=""):
        function = self._facts.get(function_name)
        if function is None:
            return {"complete": False, "fact_version": None, "functions": []}
        return {
            "complete": bool(function.get("complete", True)),
            "fact_version": function.get("fact_version"),
            "functions": [function],
        }

    def get_callees(self, _name, limit=30):
        return []

    def get_callers(self, _name, limit=20, callee_file=""):
        return []

    def callback_registrations(self):
        return []


def _function_fact(name: str, parameter: str, events: list[dict], edges=None) -> dict:
    return {
        "kind": "program_function",
        "owner": {"name": name, "file": "src/demo.c", "line": 1},
        "location": _location("src/demo.c", 1),
        "complete": True,
        "fact_version": "zscope.program-events.v7",
        "parameters": [_value(parameter, kind="parameter", index=0)],
        "events": events,
        "cfg_edges": edges or [],
    }


def _event(
    event_id: str,
    kind: str,
    line: int,
    *,
    defs=None,
    uses=None,
    callee: str = "",
    argument_uses=None,
    block: int = 1,
) -> dict:
    return {
        "event_id": event_id,
        "event_kind": kind,
        "block": block,
        "ordinal": int(event_id.split(":")[-1]),
        "location": _location("src/demo.c", line),
        "expression": callee + "(...)" if callee else kind,
        "callee": (
            {
                "name": callee,
                "qualified_name": callee,
                "usr": f"usr:{callee}",
                "location": _location("src/demo.c", line),
            }
            if callee
            else {}
        ),
        "defs": list(defs or []),
        "uses": list(uses or []),
        "argument_uses": list(argument_uses or []),
        "argument_objects": [],
    }


def _prepare_project(tmp_path: Path) -> EvidenceCodeIndex:
    (tmp_path / "src").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "config.h").write_text(
        "#define MAX_RETRIES (3U)\n"
        "#define MASK (1U << 4)\n"
        "#define APPLY(x) ((x) + 1)\n"
        "#define MULTILINE(x) \\\n"
        "  ((x) + 1)\n",
        encoding="utf-8",
    )
    (tmp_path / "src" / "demo.c").write_text(
        '#include "config.h"\n\n\n\n'
        "void root(int user_len) {\n"
        "  int copied = user_len;\n"
        "  helper(copied);\n"
        "  dangerous(copied);\n"
        "}\n\n"
        "void helper(int forwarded) {\n"
        "  dangerous(forwarded);\n"
        "}\n",
        encoding="utf-8",
    )
    return EvidenceCodeIndex(tmp_path)


def test_registry_contracts_are_six_distinct_output_schemas(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    registry = build_tool_registry(code_index, SnapshotStore())

    assert list(registry) == [
        "search_code",
        "read_code",
        "get_semantic_context",
        "query_code_graph",
        "trace_data_flow",
        "query_static_findings",
    ]
    for tool in registry.values():
        contract = tool.get_contract()
        assert contract.input_schema["additionalProperties"] is False
        assert contract.output_schema["properties"]["data"] != {}


def test_each_public_tool_result_matches_its_output_schema(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    registry = build_tool_registry(code_index, SnapshotStore())
    search = registry["search_code"].execute(
        {"query": "root", "kinds": ["function"], "match_mode": "exact"}
    )
    symbol_id = search["data"]["symbols"][0]["symbol_id"]
    results = {
        "search_code": search,
        "read_code": registry["read_code"].execute({"symbol_id": symbol_id}),
        "get_semantic_context": registry["get_semantic_context"].execute({"kind": "summary"}),
        "query_code_graph": registry["query_code_graph"].execute(
            {"symbol_id": symbol_id, "relation": "call"}
        ),
        "trace_data_flow": registry["trace_data_flow"].execute(
            {
                "symbol_id": symbol_id,
                "source": {"kind": "parameter", "name": "user_len"},
                "sink": {"kind": "return"},
            }
        ),
        "query_static_findings": registry["query_static_findings"].execute({}),
    }

    for name, result in results.items():
        assert registry[name].validate_result(result) is None


def test_macro_search_classifies_literals_without_evaluating_expressions(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    tool = SearchCodeTool(SymbolCatalog(code_index))

    literal = tool.execute({"query": "MAX_RETRIES", "kinds": ["macro"], "match_mode": "exact"})
    expression = tool.execute({"query": "MASK", "kinds": ["macro"], "match_mode": "exact"})
    function_like = tool.execute({"query": "APPLY", "kinds": ["macro"], "match_mode": "exact"})

    assert literal["data"]["symbols"][0]["macro"]["literal"]["normalized_value"] == "3"
    assert expression["data"]["symbols"][0]["macro"]["literal"] is None
    assert function_like["data"]["symbols"][0]["macro"]["form"] == "function_like"
    assert classify_direct_literal("-0x10UL")["normalized_value"] == "-16"
    assert classify_direct_literal("0b1010u")["normalized_value"] == "10"
    assert classify_direct_literal("(+1.5f)")["kind"] == "floating"
    assert classify_direct_literal('"ready"')["kind"] == "string"
    assert classify_direct_literal("'x'")["kind"] == "character"
    assert classify_direct_literal("TRUE")["normalized_value"] == "true"

    multiline = tool.execute({"query": "MULTILINE", "kinds": ["macro"], "match_mode": "exact"})
    multiline_symbol = multiline["data"]["symbols"][0]
    read = ReadCodeTool(code_index, tool.catalog).execute(
        {"symbol_id": multiline_symbol["symbol_id"]}
    )
    assert multiline_symbol["macro"]["form"] == "function_like"
    assert read["data"]["source"]["start_line"] == 4
    assert read["data"]["source"]["end_line"] == 5
    assert "5 |   ((x) + 1)" in read["data"]["source"]["code"]


def test_search_inventories_java_types_with_qualified_identity(tmp_path: Path) -> None:
    source = tmp_path / "src/main/java/com/example/RequestModel.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "package com.example;\n"
        "public class RequestModel {\n"
        "    private String value;\n"
        "}\n",
        encoding="utf-8",
    )
    backend = JavaSourceBackend(frontend="builtin")
    assert backend.initialize(str(tmp_path), project_root=tmp_path)

    class JavaIndex:
        backend_name = "java_source"
        language = "java"
        _index_epoch = 1
        _cache_lock = threading.RLock()
        _backend = backend
        _function_index = backend.build_function_index()

    result = SearchCodeTool(SymbolCatalog(JavaIndex())).execute(
        {"query": "com.example.RequestModel", "kinds": ["type"], "match_mode": "exact"}
    )

    assert result["status"] == "ok"
    symbol = result["data"]["symbols"][0]
    assert symbol["kind"] == "type"
    assert symbol["name"] == "RequestModel"
    assert symbol["qualified_name"] == "com.example.RequestModel"
    assert symbol["origin"] == "java_source"
    assert symbol["location"]["file"] == "src/main/java/com/example/RequestModel.java"
    assert symbol["location"]["start_line"] == 2
    assert symbol["location"]["end_line"] == 4


def test_semantic_context_rebuilds_and_reports_persistence(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    store = MutableSnapshotStore(tmp_path)

    def resolver(index_name, file_path):
        assert index_name == "root"
        assert file_path == "src/demo.c"
        store.snapshot = {"contract": {"returns": "void"}}
        return {
            "success": True,
            "data": store.snapshot,
            "message": "Generated and saved snapshot.",
        }

    result = SemanticContextTool(store, code_index, catalog, resolver=resolver).execute(
        {"kind": "function", "symbol_id": symbol["symbol_id"]}
    )

    snapshot = result["data"]["snapshot"]
    assert snapshot["status"] == "current"
    assert snapshot["rebuilt"] is True
    assert snapshot["persisted"] is True
    assert snapshot["rebuild_available"] is True
    assert result["data"]["contract"] == {"returns": "void"}
    assert result["status"] == "partial"  # The semantic map is intentionally absent.


def test_semantic_context_without_resolver_distinguishes_current_missing_and_stale(
    tmp_path: Path, monkeypatch
) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    monkeypatch.setattr(
        "zscope.tools.semantic_context.build_semantic_model_input",
        lambda *_args, **_kwargs: {"index_name": "root", "code": "void root(void) {}"},
    )

    current_store = MutableSnapshotStore(tmp_path, {"contract": {"state": "current"}})
    current = SemanticContextTool(current_store, code_index, catalog).execute(
        {"kind": "function", "symbol_id": symbol["symbol_id"]}
    )
    assert current["data"]["snapshot"]["status"] == "current"
    assert current["data"]["snapshot"]["rebuild_available"] is False

    missing_store = MutableSnapshotStore(tmp_path)
    missing = SemanticContextTool(missing_store, code_index, catalog).execute(
        {"kind": "function", "symbol_id": symbol["symbol_id"]}
    )
    assert missing["data"]["snapshot"]["status"] == "missing"
    assert "snapshot" in missing["coverage"]["missing"]

    stale_store = MutableSnapshotStore(tmp_path, {"contract": {"state": "old"}}, stale=True)
    stale = SemanticContextTool(stale_store, code_index, catalog).execute(
        {"kind": "function", "symbol_id": symbol["symbol_id"]}
    )
    assert stale["data"]["snapshot"]["status"] == "stale"
    assert stale["data"]["snapshot"]["data"] is None
    assert "current_snapshot" in stale["coverage"]["missing"]


def test_semantic_context_preserves_pinned_coverage_rebuild_failure(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    store = MutableSnapshotStore(tmp_path, {"contract": {"state": "old"}})

    result = SemanticContextTool(
        store,
        code_index,
        catalog,
        resolver=lambda *_args: {
            "success": False,
            "reason": "snapshot_outside_pinned_semantic_coverage",
            "error": "outside pinned coverage",
        },
    ).execute({"kind": "function", "symbol_id": symbol["symbol_id"]})

    assert result["status"] == "partial"
    assert result["data"]["snapshot"]["status"] == "stale"
    assert "snapshot_outside_pinned_semantic_coverage" in result["coverage"]["missing"]


def test_search_rejects_ambiguous_or_nested_regex_repetition(tmp_path: Path) -> None:
    tool = SearchCodeTool(SymbolCatalog(_prepare_project(tmp_path)))

    nested = tool.validate_arguments({"query": "(a{1,3})+", "match_mode": "regex"})
    ambiguous = tool.validate_arguments({"query": "(a|aa)+$", "match_mode": "regex"})

    assert nested["status"] == "invalid_request"
    assert nested["error"]["path"] == "query"
    assert ambiguous["status"] == "invalid_request"


def test_symbol_ids_disambiguate_overloads_and_go_stale_after_identity_change(
    tmp_path: Path,
) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    matches = catalog.search("same", ["function"], "exact", None)

    assert len(matches) == 2
    assert len({item["symbol_id"] for item in matches}) == 2
    old_id = matches[0]["symbol_id"]
    old_key = str(matches[0]["index_name"])
    code_index._function_index[old_key]["start_line"] = 20
    code_index._function_index[old_key]["end_line"] = 20
    code_index._index_epoch += 1

    assert catalog.resolve(old_id) is None


def test_read_code_uses_symbol_id_and_explicit_continuation(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    tool = ReadCodeTool(code_index, catalog)

    first = tool.execute({"symbol_id": symbol["symbol_id"], "max_lines": 2})
    second = tool.execute(
        {
            "symbol_id": symbol["symbol_id"],
            "start_line": first["data"]["source"]["next_start_line"],
            "max_lines": 20,
        }
    )

    assert first["status"] == "partial"
    assert first["data"]["source"]["code"].startswith("5 |")
    assert second["status"] == "ok"
    assert second["data"]["source"]["end_line"] == 10


def test_read_code_file_mode_without_end_reports_eof_continuation(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    tool = ReadCodeTool(code_index, SymbolCatalog(code_index))

    result = tool.execute({"file_path": "src/demo.c", "start_line": 1, "max_lines": 2})

    assert result["status"] == "partial"
    assert result["data"]["source"]["end_line"] == 2
    assert result["data"]["source"]["next_start_line"] == 3


def test_read_code_scans_multiline_global_declaration_to_real_semicolon(
    tmp_path: Path,
) -> None:
    code_index = _prepare_project(tmp_path)
    (tmp_path / "src" / "globals.c").write_text(
        "const char *GLOBAL_MESSAGE =\n"
        "    /* a misleading ; in a comment */\n"
        '    "ready;still";\n'
        "int after;\n",
        encoding="utf-8",
    )
    code_index._get_global_definition_index = lambda: {
        "GLOBAL_MESSAGE": [
            {
                "name": "GLOBAL_MESSAGE",
                "file_path": "src/globals.c",
                "start_line": 1,
                "type": "const char *",
            }
        ]
    }
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("GLOBAL_MESSAGE", ["global"], "exact", None)[0]

    result = ReadCodeTool(code_index, catalog).execute({"symbol_id": symbol["symbol_id"]})

    assert result["status"] == "ok"
    assert result["data"]["source"]["end_line"] == 3
    assert "after" not in result["data"]["source"]["code"]
    assert result["data"]["definition"]["complete"] is True


def test_recursive_and_cross_field_validation_reports_exact_paths(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    flow = TraceDataFlowTool(code_index, catalog)
    symbol = catalog.search("root", ["function"], "exact", None)[0]

    missing = flow.validate_arguments(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter"},
            "sink": {"kind": "return"},
        }
    )
    unknown = flow.validate_arguments(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len", "extra": 1},
            "sink": {"kind": "return"},
        }
    )
    escaped = flow.validate_arguments(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "location", "file_path": "../secret.c", "line": 1},
            "sink": {"kind": "return"},
        }
    )
    invented = flow.validate_arguments(
        {
            "symbol_id": "root",
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "return"},
        }
    )

    assert missing["error"]["path"] == "source.name"
    assert unknown["error"]["path"] == "source.extra"
    assert escaped["error"]["path"] == "source.file_path"
    assert invented["error"]["code"] == "invalid_symbol_id"


def test_graph_queries_direct_reference_callback_and_svf_indirect_edges(
    tmp_path: Path,
) -> None:
    code_index = _prepare_project(tmp_path)

    class GraphDB:
        def query_symbol_references(self, **_kwargs):
            return [
                {
                    "function_name": "root",
                    "function_file": "src/demo.c",
                    "symbol_name": "MAX_RETRIES",
                    "symbol_kind": "macro",
                    "symbol_file": "include/config.h",
                    "reference_line": 6,
                    "access_kind": "read",
                }
            ]

        def get_indirect_call_records(self, _name, **_kwargs):
            return [
                {
                    "name": "helper",
                    "call_file": "src/demo.c",
                    "call_line": 7,
                    "source": "svf",
                    "confidence": 0.92,
                    "callsite_id": "cs:7",
                    "pointer_symbol": "handler",
                    "svf_groups": ["entry-root"],
                }
            ]

    code_index._backend = SimpleNamespace(db=GraphDB())
    code_index.get_callees = lambda name, limit=100000: (
        [{"name": "helper", "call_file": "src/demo.c", "call_line": 7}]
        if str(name).startswith("root")
        else (
            [{"name": "dangerous", "call_file": "src/demo.c", "call_line": 13}]
            if str(name).startswith("helper")
            else []
        )
    )
    code_index.callback_registrations = lambda: [
        {
            "caller_name": "root",
            "caller_file": "src/demo.c",
            "callee_name": "helper",
            "callee_file": "src/demo.c",
            "file": "src/demo.c",
            "line": 7,
        }
    ]
    catalog = SymbolCatalog(code_index)
    root = catalog.search("root", ["function"], "exact", None)[0]
    tool = QueryCodeGraphTool(code_index, catalog)

    direct = tool.execute(
        {
            "symbol_id": root["symbol_id"],
            "relation": "call",
            "direction": "outgoing",
            "depth": 2,
        }
    )
    reference = tool.execute(
        {
            "symbol_id": root["symbol_id"],
            "relation": "reference",
            "direction": "outgoing",
        }
    )
    callback = tool.execute(
        {
            "symbol_id": root["symbol_id"],
            "relation": "callback",
            "direction": "outgoing",
        }
    )
    indirect = tool.execute(
        {
            "symbol_id": root["symbol_id"],
            "relation": "indirect_call",
            "direction": "outgoing",
        }
    )
    first_page = tool.execute(
        {
            "symbol_id": root["symbol_id"],
            "relation": "call",
            "direction": "outgoing",
            "depth": 2,
            "limit": 1,
            "offset": 0,
        }
    )
    second_page = tool.execute(
        {
            "symbol_id": root["symbol_id"],
            "relation": "call",
            "direction": "outgoing",
            "depth": 2,
            "limit": 1,
            "offset": first_page["page"]["next_offset"],
        }
    )

    assert direct["data"]["edges"][0]["target"]["name"] == "helper"
    assert [edge["distance"] for edge in direct["data"]["edges"]] == [1, 2]
    assert direct["data"]["edges"][1]["target"]["symbol_id"] is None
    assert reference["data"]["edges"][0]["target"]["kind"] == "macro"
    assert callback["data"]["edges"][0]["dispatch"] == "callback_registration"
    assert indirect["data"]["edges"][0]["dispatch"] == "svf_resolved"
    assert indirect["data"]["edges"][0]["evidence"]["callsite_id"] == "cs:7"
    assert first_page["page"]["has_more"] is True
    assert first_page["page"]["next_offset"] == 1
    assert second_page["data"]["edges"][0]["distance"] == 2
    assert second_page["page"]["has_more"] is False
    for result in (direct, reference, callback, indirect):
        assert tool.validate_result(result) is None, json.dumps(result, indent=2)


def test_flow_v5_assignment_is_must_and_guarded_path_is_may(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    parameter = _value("user_len", kind="parameter", index=0)
    copied = _value("copied")
    code_index._facts["root"] = _function_fact(
        "root",
        "user_len",
        [
            _event("1:0", "assignment", 6, defs=[copied], uses=[parameter], block=1),
            _event(
                "2:0",
                "call",
                8,
                uses=[copied],
                callee="dangerous",
                argument_uses=[[copied]],
                block=2,
            ),
        ],
        edges=[{"from": 1, "to": 2, "condition": "copied > 0", "branch": "true"}],
    )
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    result = TraceDataFlowTool(code_index, catalog).execute(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "call", "query": "dangerous"},
            "include_may_alias": False,
            "max_call_depth": 0,
        }
    )

    assert result["status"] == "ok"
    assert result["data"]["paths"][0]["classification"] == "may"
    assert result["data"]["paths"][0]["guards"] == ["copied > 0 is true"]


def test_flow_crosses_direct_argument_to_callee_parameter(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    source = _value("user_len", kind="parameter", index=0)
    forwarded = _value("forwarded", kind="parameter", index=0)
    code_index._facts["root"] = _function_fact(
        "root",
        "user_len",
        [
            _event(
                "1:0",
                "call",
                7,
                uses=[source],
                callee="helper",
                argument_uses=[[source]],
            )
        ],
    )
    code_index._facts["helper"] = _function_fact(
        "helper",
        "forwarded",
        [
            _event(
                "1:0",
                "call",
                13,
                uses=[forwarded],
                callee="dangerous",
                argument_uses=[[forwarded]],
            )
        ],
    )
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    result = TraceDataFlowTool(code_index, catalog).execute(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "call", "query": "dangerous"},
            "include_may_alias": False,
            "max_call_depth": 1,
        }
    )

    assert result["data"]["paths"]
    assert "argument" in {edge["kind"] for edge in result["data"]["paths"][0]["edges"]}


def test_call_result_flow_requires_real_callee_return_path(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    source = _value("user_len", kind="parameter", index=0)
    result_value = _value("copied")
    code_index._facts["root"] = _function_fact(
        "root",
        "user_len",
        [
            _event(
                "1:0",
                "call",
                7,
                defs=[result_value],
                uses=[source],
                callee="helper",
                argument_uses=[[source]],
            ),
            _event(
                "1:1",
                "call",
                8,
                uses=[result_value],
                callee="dangerous",
                argument_uses=[[result_value]],
            ),
        ],
    )
    forwarded = _value("forwarded", kind="parameter", index=0)
    code_index._facts["helper"] = _function_fact(
        "helper",
        "forwarded",
        [_event("1:0", "return", 13, uses=[forwarded])],
    )
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    result = TraceDataFlowTool(code_index, catalog).execute(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "call", "query": "dangerous"},
            "include_may_alias": False,
            "max_call_depth": 1,
        }
    )

    path = result["data"]["paths"][0]
    assert path["classification"] == "must"
    assert "return" in {edge["kind"] for edge in path["edges"]}


def test_call_result_does_not_synthesize_argument_to_return_flow(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    source = _value("user_len", kind="parameter", index=0)
    result_value = _value("copied")
    code_index._facts["root"] = _function_fact(
        "root",
        "user_len",
        [
            _event(
                "1:0",
                "call",
                7,
                defs=[result_value],
                uses=[source],
                callee="helper",
                argument_uses=[[source]],
            ),
            _event(
                "1:1",
                "call",
                8,
                uses=[result_value],
                callee="dangerous",
                argument_uses=[[result_value]],
            ),
        ],
    )
    code_index._facts["helper"] = _function_fact(
        "helper",
        "forwarded",
        [_event("1:0", "return", 13)],
    )
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]

    result = TraceDataFlowTool(code_index, catalog).execute(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "call", "query": "dangerous"},
            "include_may_alias": False,
            "max_call_depth": 1,
        }
    )

    assert result["data"]["paths"] == []
    assert result["data"]["reason"] == "complete_search_no_path"


def test_flow_rejects_v4_facts_as_unavailable(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    fact = _function_fact("root", "user_len", [])
    fact["fact_version"] = "zscope.program-events.v4"
    code_index._facts["root"] = fact
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    result = TraceDataFlowTool(code_index, catalog).execute(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "return"},
        }
    )

    assert result["status"] == "unavailable"
    assert result["data"]["reason"] == "backend_unavailable"
    assert "program_events_v5" in result["coverage"]["missing"]


def test_flow_maps_joern_parameter_paths_and_normalizes_unknown_lines(
    tmp_path: Path,
) -> None:
    code_index = _prepare_project(tmp_path)

    class JoernBackendStub:
        def get_data_flow(self, source_func, source_param, sink_pattern):
            assert source_func == "root"
            assert source_param == "user_len"
            assert sink_pattern == "dangerous"
            return [
                {
                    "path": [
                        {
                            "code": "user_len",
                            "filename": "src/demo.c",
                            "lineNumber": 5,
                        },
                        {
                            "code": "dangerous(user_len)",
                            "filename": "src/demo.c",
                            "lineNumber": -1,
                        },
                    ]
                }
            ]

    code_index.language = "java"
    code_index.backend_name = "joern"
    code_index._backend = JoernBackendStub()
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["method"], "exact", None)[0]
    tool = TraceDataFlowTool(code_index, catalog)

    result = tool.execute(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "call", "query": "dangerous"},
        }
    )

    assert result["status"] == "ok"
    assert result["data"]["paths"][0]["classification"] == "may"
    assert result["data"]["paths"][0]["nodes"][1]["location"]["line"] is None
    assert tool.validate_result(result) is None, json.dumps(result, indent=2)


def test_java_source_flow_is_explicitly_unsupported(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    code_index.language = "java"
    code_index.backend_name = "java_source"
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("root", ["method"], "exact", None)[0]

    result = TraceDataFlowTool(code_index, catalog).execute(
        {
            "symbol_id": symbol["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "call", "query": "dangerous"},
        }
    )

    assert result["status"] == "unsupported"
    assert result["data"]["reason"] == "unsupported_selector"
    assert "java_def_use_backend" in result["coverage"]["missing"]


class FrozenLedger:
    is_frozen = True
    revision = "rev-1"

    def frozen_records(self):
        return [
            {
                "candidate_id": "candidate-1",
                "candidate_uid": "uid-1",
                "status": "confirmed",
                "candidate_disposition": "confirmed",
                "validation_attempt_count": 1,
                "sources": ["graph_rule"],
                "defect_class": "memory_safety",
                "ticket": {
                    "trigger": "ZSCOPE.CPP.TEST",
                    "skill": "bounds_and_integer",
                    "task": "Potential out-of-bounds write",
                    "origin": "src/demo.c:8",
                    "evidence": {
                        "candidate_payload": {
                            "rule_id": "ZSCOPE.CPP.TEST",
                            "category": "memory_safety",
                            "location": {"file": "src/demo.c", "line": 8},
                        },
                        "large_private_pack": "x" * 10000,
                    },
                },
                "terminal_issue": {
                    "description": "Confirmed bounds violation",
                    "location": {"file": "src/demo.c", "line": 8},
                },
            }
        ]


def test_static_findings_reads_only_frozen_compact_records(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    result = QueryStaticFindingsTool(code_index, catalog, FrozenLedger()).execute({})

    finding = result["data"]["findings"][0]
    assert finding["validation"]["state"] == "confirmed"
    assert finding["authority"] == "deterministic"
    assert finding["evidence_refs"] == [
        {"kind": "source", "file": "src/demo.c", "line": 8, "column": None}
    ]
    assert "large_private_pack" not in str(finding)


def test_static_findings_hides_mutable_ledger_records(tmp_path: Path) -> None:
    class MutableLedger:
        is_frozen = False

        def frozen_records(self):
            raise AssertionError("mutable records must not be exposed")

    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    result = QueryStaticFindingsTool(code_index, catalog, MutableLedger()).execute({})

    assert result["status"] == "partial"
    assert result["data"]["findings"] == []
    assert "ledger_not_frozen" in result["coverage"]["missing"]
    assert "mutable" in " ".join(result["warnings"])


def test_findings_reject_stale_symbol_id_instead_of_name_fallback(tmp_path: Path) -> None:
    code_index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(code_index)
    tool = QueryStaticFindingsTool(code_index, catalog, FrozenLedger())

    result = tool.execute({"symbol_id": "zs1:function:000000000000000000000000"})

    assert result["status"] == "not_found"
    assert result["next_actions"]
