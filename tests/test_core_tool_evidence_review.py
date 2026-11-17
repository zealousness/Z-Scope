"""Tool evidence must retain identity constraints and incomplete query scope."""

from dataclasses import replace
import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from test_evidence_tools import (
    FrozenLedger,
    MutableSnapshotStore,
    _event,
    _function_fact,
    _prepare_project,
    _value,
)
from test_security_semantics_tool import _semantic_map
from zscope.semantics.security_map import SQLiteSecurityMapStore
from zscope.tools.code_graph_query import QueryCodeGraphTool
from zscope.tools.flow_query import FlowQueryService, _PathBudget
from zscope.tools.data_flow_trace import TraceDataFlowTool
from zscope.common.joern_client import JoernClient
from zscope.tools.semantic_context import SemanticContextTool
from zscope.tools.static_findings import QueryStaticFindingsTool
from zscope.tools.symbols import SymbolCatalog


def test_nested_incomplete_cfg_cannot_become_a_complete_absence(tmp_path):
    index = _prepare_project(tmp_path)
    parameter = _value("user_len", kind="parameter", index=0)
    index._facts["root"] = _function_fact(
        "root",
        "user_len",
        [_event("1:0", "call", 7, uses=[parameter], callee="helper", argument_uses=[[parameter]])],
    )
    index._facts["helper"] = {**_function_fact("helper", "forwarded", []), "complete": False}
    result = FlowQueryService(index, SymbolCatalog(index)).trace_clang(
        "root",
        "src/demo.c",
        {"kind": "parameter", "name": "user_len"},
        {"kind": "call", "query": "dangerous"},
        include_may_alias=False,
        max_call_depth=1,
        max_paths=10,
    )
    assert result["status"] == "partial"
    assert "complete_cfg" in result["missing"]
    assert result["reason"] == "not_observed_with_partial_coverage"


def test_nested_flows_share_one_path_expansion_budget(tmp_path):
    index = _prepare_project(tmp_path)
    source = _value("user_len", kind="parameter", index=0)
    forwarded = _value("forwarded", kind="parameter", index=0)
    index._facts["root"] = _function_fact(
        "root",
        "user_len",
        [_event("1:0", "call", 7, uses=[source], callee="helper", argument_uses=[[source]])],
    )
    index._facts["helper"] = _function_fact(
        "helper",
        "forwarded",
        [
            _event(
                "1:0", "call", 15, uses=[forwarded], callee="dangerous", argument_uses=[[forwarded]]
            )
        ],
    )
    budget = _PathBudget(3)
    result = FlowQueryService(index, SymbolCatalog(index)).trace_clang(
        "root",
        "src/demo.c",
        {"kind": "parameter", "name": "user_len"},
        {"kind": "call", "query": "dangerous"},
        include_may_alias=False,
        max_call_depth=1,
        max_paths=10,
        _path_budget=budget,
    )
    assert budget.exhausted and budget.remaining == 0
    assert result["status"] == "partial" and result["paths"] == []
    assert "path_search_bound" in result["missing"]


def test_flow_prunes_unreachable_sink_before_enumerating_diamond_paths():
    class CountingGraph(dict):
        reads = 0

        def get(self, *args):
            self.reads += 1
            return super().get(*args)

    graph = CountingGraph({"root": [{"to": "0:a"}, {"to": "0:b"}]})
    for level in range(8):
        for branch in ("a", "b"):
            graph[f"{level}:{branch}"] = [{"to": f"{level+1}:a"}, {"to": f"{level+1}:b"}]
    paths, truncated = FlowQueryService._paths_bounded(graph, {"root"}, {"unreachable"}, 10)
    assert paths == [] and not truncated
    assert graph.reads <= 2 * len(graph)


def test_flow_reachable_diamond_retains_only_one_lazy_path():
    class CountingGraph(dict):
        reads = 0

        def get(self, *args):
            self.reads += 1
            return super().get(*args)

    graph = CountingGraph({"root": [{"to": "0:a"}, {"to": "0:b"}]})
    for level in range(32):
        for branch in ("a", "b"):
            graph[f"{level}:{branch}"] = (
                [{"to": f"{level+1}:a"}, {"to": f"{level+1}:b"}] if level < 31 else [{"to": "sink"}]
            )
    paths, truncated = FlowQueryService._paths_bounded(graph, {"root"}, {"sink"}, 1)
    assert len(paths) == 1 and len(paths[0][0]) == 34 and not truncated
    assert graph.reads <= 2 * len(graph)


def test_variable_source_does_not_taint_other_call_arguments(tmp_path):
    index = _prepare_project(tmp_path)
    source = _value("user_len", kind="parameter", index=0)
    other = _value("unrelated", kind="local")
    forwarded = _value("forwarded", kind="parameter", index=0)
    second = _value("second", kind="parameter", index=1)
    index._facts["root"] = _function_fact(
        "root",
        "user_len",
        [
            _event(
                "1:0",
                "call",
                7,
                uses=[source, other],
                callee="helper",
                argument_uses=[[source], [other]],
            )
        ],
    )
    helper = _function_fact(
        "helper",
        "forwarded",
        [_event("1:0", "call", 15, uses=[second], callee="dangerous", argument_uses=[[second]])],
    )
    helper["parameters"] = [forwarded, second]
    index._facts["helper"] = helper
    result = FlowQueryService(index, SymbolCatalog(index)).trace_clang(
        "root",
        "src/demo.c",
        {"kind": "variable", "name": "user_len"},
        {"kind": "call", "query": "dangerous"},
        include_may_alias=False,
        max_call_depth=1,
        max_paths=10,
    )
    assert result["paths"] == []


def test_flow_deep_diamond_exhaustion_is_partial_not_absence(tmp_path, monkeypatch):
    index = _prepare_project(tmp_path)
    index._facts["root"] = _function_fact("root", "user_len", [])
    service = FlowQueryService(index, SymbolCatalog(index))
    graph = {"root": [{"to": "0:a"}, {"to": "0:b"}]}
    for level in range(210):
        for branch in ("a", "b"):
            graph[f"{level}:{branch}"] = (
                [{"to": f"{level+1}:a"}, {"to": f"{level+1}:b"}]
                if level < 209
                else [{"to": "sink"}]
            )
    monkeypatch.setattr(service, "_build_graph", lambda _: {"adjacency": graph})
    monkeypatch.setattr(service, "_select_source", lambda *_: {"root"})
    monkeypatch.setattr(service, "_select_sink", lambda *_, **__: {"sink"})
    budget = _PathBudget(1_000)
    result = service.trace_clang(
        "root",
        "src/demo.c",
        {"kind": "parameter", "name": "user_len"},
        {"kind": "call", "query": "sink"},
        include_may_alias=False,
        max_call_depth=0,
        max_paths=1,
        _path_budget=budget,
    )
    assert budget.exhausted and budget.remaining == 0
    assert result["status"] == "partial" and result["paths"] == []
    assert "path_search_bound" in result["missing"]
    assert result["reason"] == "not_observed_with_partial_coverage"


@pytest.mark.parametrize("backend", ["clang", "joern"])
def test_regex_timeout_is_an_explicit_query_error(tmp_path, monkeypatch, backend):
    index = _prepare_project(tmp_path)
    if backend == "joern":
        index.backend_name = "joern"
        index._backend = SimpleNamespace(
            get_data_flow=lambda *_: (_ for _ in ()).throw(TimeoutError())
        )
    else:
        index._facts["root"] = _function_fact(
            "root", "user_len", [_event("1:0", "call", 8, callee="dangerous")]
        )

        class TimedPattern:
            def search(self, *_args, **_kwargs):
                raise TimeoutError()

        monkeypatch.setattr("zscope.tools.flow_query.regex.compile", lambda *_: TimedPattern())
    catalog = SymbolCatalog(index)
    root = catalog.search("root", ["function"], "exact", None)[0]
    result = TraceDataFlowTool(index, catalog).execute(
        {
            "symbol_id": root["symbol_id"],
            "source": {"kind": "parameter", "name": "user_len"},
            "sink": {"kind": "call", "query": "dangerous", "match_mode": "regex"},
        }
    )
    assert result["status"] == "invalid_request"
    assert result["error"]["code"] == "regex_query_timeout"


def test_joern_sink_regex_has_one_deadline_across_all_names(monkeypatch):
    client = object.__new__(JoernClient)
    queries = []
    client.query = lambda query: queries.append(query) or ["first", "second"]
    clock = iter([0.0, 0.4, 1.1])
    monkeypatch.setattr("zscope.common.joern_client.time.monotonic", lambda: next(clock))
    with pytest.raises(TimeoutError):
        client.get_data_flow_to_sink("root", "arg", ".*")
    assert len(queries) == 1


def test_joern_adversarial_regex_times_out_before_remote_flow_query():
    client = object.__new__(JoernClient)
    queries = []
    client.query = lambda query: queries.append(query) or ["a" * 50_000 + "!"]
    with pytest.raises(TimeoutError):
        client.get_data_flow_to_sink("root", "arg", "(?:a|aa)+$")
    assert queries == ["cpg.call.name.distinct.l.toJson"]


@pytest.mark.parametrize(
    "constraint", [{"file_path": "src/other.c"}, {"signature": "void helper(char *)"}]
)
def test_graph_identity_constraints_do_not_fall_back_to_a_different_symbol(tmp_path, constraint):
    index = _prepare_project(tmp_path)
    result = QueryCodeGraphTool(index, SymbolCatalog(index))._resolve_name("helper", **constraint)
    assert result["symbol_id"] is None


def test_flow_does_not_ignore_a_conflicting_native_usr(tmp_path):
    index = _prepare_project(tmp_path)
    event = _event("1:0", "call", 7, callee="helper")
    event["callee"]["usr"] = "usr:different-helper"
    assert (
        FlowQueryService(index, SymbolCatalog(index))._call_targets("root", "src/demo.c", event)
        == []
    )


def test_graph_preserves_distinct_call_columns_and_zero_confidence(tmp_path):
    index = _prepare_project(tmp_path)
    index.get_callees = lambda _name, limit=30: [
        {
            "name": "helper",
            "filename": "src/demo.c",
            "call_line": 7,
            "column": column,
            "confidence": 0.0,
        }
        for column in (2, 18)
    ][:limit]
    catalog = SymbolCatalog(index)
    symbol = catalog.search("root", ["function"], "exact", None)[0]
    result = QueryCodeGraphTool(index, catalog).execute(
        {
            "symbol_id": symbol["symbol_id"],
            "relation": "call",
            "direction": "outgoing",
        }
    )
    edges = result["data"]["edges"]
    assert len(edges) == 2
    assert {edge["site"]["column"] for edge in edges} == {2, 18}
    assert all(edge["evidence"]["confidence"] == 0.0 for edge in edges)


def test_graph_callee_definition_file_is_not_the_call_site(tmp_path):
    index = _prepare_project(tmp_path)
    index.get_callees = lambda _name, limit=30: [
        {"name": "helper", "filename": "src/other.c", "lineNumber": 7}
    ]
    index._function_index["helper"]["file"] = "src/other.c"
    catalog = SymbolCatalog(index)
    root = catalog.search("root", ["function"], "exact", None)[0]
    edge = QueryCodeGraphTool(index, catalog).execute(
        {
            "symbol_id": root["symbol_id"],
            "relation": "call",
            "direction": "outgoing",
        }
    )["data"]["edges"][0]
    assert edge["target"]["location"]["file"] == "src/other.c"
    assert edge["site"]["file"] == "src/demo.c"


def test_graph_incoming_calls_exclude_callback_registration(tmp_path):
    index = _prepare_project(tmp_path)
    index.get_callers = lambda *_args, **_kwargs: [
        {"name": "root", "filename": "src/demo.c", "lineNumber": 7, "registration_kind": "thread"}
    ]
    catalog = SymbolCatalog(index)
    helper = catalog.search("helper", ["function"], "exact", None)[0]
    result = QueryCodeGraphTool(index, catalog).execute(
        {
            "symbol_id": helper["symbol_id"],
            "relation": "call",
            "direction": "incoming",
        }
    )
    assert result["data"]["edges"] == []


def test_filtered_callback_rows_do_not_hide_backend_truncation(tmp_path):
    index = _prepare_project(tmp_path)
    index._backend = SimpleNamespace()
    index.get_callers = (
        lambda *_args, limit, **_kwargs: [{"name": "root", "registration_kind": "thread"}] * limit
    )
    catalog = SymbolCatalog(index)
    helper = catalog.search("helper", ["function"], "exact", None)[0]
    result = QueryCodeGraphTool(index, catalog).execute(
        {
            "symbol_id": helper["symbol_id"],
            "relation": "call",
            "direction": "incoming",
        }
    )
    assert result["data"]["edges"] == []
    assert result["status"] == "partial"


def test_scoped_static_findings_do_not_expose_foreign_or_unknown_builds(tmp_path):
    index = _prepare_project(tmp_path)
    index.pinned_build_context_id = "BUILD_A"
    template = FrozenLedger().frozen_records()[0]
    ledger = SimpleNamespace(
        is_frozen=True,
        revision="frozen",
        frozen_records=lambda: [
            {**template, "candidate_uid": build or "UNKNOWN", "build_context_id": build}
            for build in ("BUILD_A", "BUILD_B", "")
        ],
    )
    result = QueryStaticFindingsTool(index, SymbolCatalog(index), ledger).execute({})
    assert [item["finding_id"] for item in result["data"]["findings"]] == ["candidate:BUILD_A"]
    assert "candidate_build_identity" in result["coverage"]["missing"]


def test_static_signal_cap_is_reported_and_symbols_are_grouped_once(tmp_path, monkeypatch):
    index = _prepare_project(tmp_path)
    monkeypatch.setattr("zscope.tools.static_findings._BACKEND_SIGNAL_LIMIT", 2)
    index._backend = SimpleNamespace(
        db=SimpleNamespace(
            get_enriched_taint_bugs=lambda *, limit: [
                {
                    "source_func": "root",
                    "sink_func": "dangerous",
                    "file_path": "src/demo.c",
                    "line": 8,
                }
            ]
            * limit
        )
    )
    catalog = SymbolCatalog(index)
    snapshot = catalog.snapshot
    calls = []
    catalog.snapshot = lambda: calls.append(True) or snapshot()
    result = QueryStaticFindingsTool(index, catalog, FrozenLedger()).execute({})
    assert "backend_signal_limit" in result["coverage"]["missing"]
    assert result["status"] == "partial"
    assert len(calls) == 1


def test_scoped_backend_signals_use_the_instance_accessor(tmp_path):
    index = _prepare_project(tmp_path)
    index.pinned_build_context_id = "BUILD_A"
    calls = []

    def scoped(*, build_context_id, limit):
        calls.append((build_context_id, limit))
        return {
            "status": "complete",
            "build_context_id": build_context_id,
            "rows": [
                {
                    "source_func": "root",
                    "sink_func": "dangerous",
                    "file_path": "src/demo.c",
                    "line": 8,
                }
            ],
        }

    index.get_instance_backend_signals = scoped
    result = QueryStaticFindingsTool(index, SymbolCatalog(index)).execute({})
    signals = [
        item for item in result["data"]["findings"] if item["record_type"] == "backend_signal"
    ]
    assert len(signals) == 1 and calls == [("BUILD_A", 1_000_000)]
    assert result["coverage"]["details"]["build_context_id"] == "BUILD_A"


@pytest.mark.parametrize("number", [float("nan"), float("inf"), -float("inf")])
def test_static_nonfinite_numbers_do_not_become_confident_evidence(number):
    assert QueryStaticFindingsTool._confidence(number) is None
    assert QueryStaticFindingsTool._positive_coordinate(number) is None


def test_semantic_corrupt_store_is_not_reported_as_missing(tmp_path):
    index = _prepare_project(tmp_path)
    catalog = SymbolCatalog(index)
    subject = catalog.search("root", ["function"], "exact", None)[0]
    (tmp_path / "security_map.db").write_bytes(b"not a sqlite database")
    store = MutableSnapshotStore(tmp_path, {"contract": {}}, stale=False)
    store.snapshot_dir = tmp_path
    result = SemanticContextTool(
        store, index, catalog, resolver=lambda *_: {"success": True, "data": store.snapshot}
    ).execute(
        {
            "kind": "function",
            "symbol_id": subject["symbol_id"],
        }
    )
    assert "security_semantic_map_unreadable" in result["coverage"]["missing"]
    assert "security_semantic_map" not in result["coverage"]["missing"]


@pytest.mark.parametrize("state", ["missing", "empty", "corrupt", "deep"])
def test_cached_semantic_map_distinguishes_missing_and_unreadable(tmp_path, state):
    index = _prepare_project(tmp_path)
    path = tmp_path / "security_map.db"
    if state == "corrupt":
        path.write_bytes(b"not a sqlite database")
    elif state != "missing":
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE security_maps (payload_json TEXT, updated_at TEXT)")
            if state == "deep":
                conn.execute(
                    "INSERT INTO security_maps VALUES (?, '')", ("[" * 10_000 + "0" + "]" * 10_000,)
                )
            conn.commit()
        finally:
            conn.close()
    store = MutableSnapshotStore(tmp_path, {"contract": {}}, stale=False)
    store.snapshot_dir = tmp_path
    result = SemanticContextTool(store, index, SymbolCatalog(index), cache_only=True).execute(
        {"kind": "summary"}
    )
    gap = (
        "security_semantic_map"
        if state in {"missing", "empty"}
        else "security_semantic_map_unreadable"
    )
    assert result["status"] == "unavailable" and result["coverage"]["missing"] == [gap]


@pytest.mark.parametrize(
    "changed,build,stored_build",
    [
        (False, "", ""),
        (True, "", ""),
        (False, "BUILD_A", ""),
        (False, "BUILD_A", "BUILD_B"),
        (False, "BUILD_A", "BUILD_A"),
    ],
)
def test_semantic_map_checks_source_hash_before_marking_function_current(
    tmp_path, changed, build, stored_build
):
    index = _prepare_project(tmp_path)
    index.pinned_build_context_id = build
    catalog = SymbolCatalog(index)
    subject = catalog.search("root", ["function"], "exact", None)[0]
    code = index.get_file_snippet("src/demo.c", 5, 10)["code"]
    index.get_function_impl = lambda *_args, **_kwargs: {
        "code": code + (" changed" if changed else ""),
        "file": "src/demo.c",
        "start_line": 5,
        "end_line": 10,
        "index_name": "root",
    }
    original = _semantic_map()
    record = replace(
        original.functions[0],
        index_name="root",
        function_name="root",
        file_path="src/demo.c",
        start_line=5,
        end_line=10,
        signature=subject["signature"],
        code_hash=hashlib.sha256(code.encode()).hexdigest(),
        backend_coverage={"build_context_id": stored_build},
    )
    SQLiteSecurityMapStore(tmp_path / "security_map.db").save_map(
        replace(original, functions=(record,))
    )
    store = MutableSnapshotStore(tmp_path, {"contract": {}}, stale=False)
    store.snapshot_dir = tmp_path
    result = SemanticContextTool(
        store, index, catalog, resolver=lambda *_: {"success": True, "data": store.snapshot}
    ).execute(
        {
            "kind": "function",
            "symbol_id": subject["symbol_id"],
        }
    )
    if changed or build != stored_build:
        assert result["data"]["security_semantics"]["status"] == "unavailable"
        assert result["data"]["security_semantics"]["records"] == []
        assert "security_map_source_changed" in result["coverage"]["missing"]
    else:
        assert result["data"]["security_semantics"]["status"] == "current"
        assert len(result["data"]["security_semantics"]["records"]) == 1
