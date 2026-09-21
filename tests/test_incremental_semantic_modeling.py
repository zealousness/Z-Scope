"""Behavioral acceptance tests for the pre-rule semantic publication barrier."""

from copy import deepcopy
from pathlib import Path
import threading

import pytest

from test_global_modeler import FakeCodeIndex, RecordingAgent, _config
from zscope.common.cancellation import CancellationError, CancellationToken, bind_cancellation_token
from zscope.config.function_entry import FunctionEntry
from zscope.config.user_config_store import UserConfigStore
from zscope.orchestration.global_modeler import GlobalModeler
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.orchestration.snapshot_candidates import (
    register_snapshot_candidates,
    snapshot_candidates,
)
from zscope.snapshots.store import SnapshotStore


def modeler_for(tmp_path, index, calls, agent=None):
    config = _config(tmp_path)
    config.concurrency.entry_workers = 1
    config.concurrency.llm_max_inflight = 3
    return GlobalModeler(
        config,
        index,
        SnapshotStore(Path(config.analysis.snapshot_dir)),
        UserConfigStore(Path(config.analysis.user_config_db)),
        semantic_agent_factory=agent or (lambda: RecordingAgent(calls)),
    )


def test_unchanged_normal_scan_has_zero_model_calls_and_stops_propagation(tmp_path):
    calls = []
    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls)
    modeler.run([FunctionEntry("entry")])
    assert sorted(calls) == ["entry", "leaf", "mid", "sibling"]
    calls.clear()
    stats = modeler.run([FunctionEntry("entry")])
    assert calls == []
    assert stats.cache_hit_functions == 4
    index.impls["leaf"]["code"] = index.impls["leaf"]["code"].replace(
        "external_leaf()", "external_leaf(1)"
    )
    stats = modeler.run([FunctionEntry("entry")])
    assert calls == ["leaf"]
    assert stats.cache_hit_functions == 3


def test_callee_contract_change_propagates_only_to_affected_parent(tmp_path):
    calls = []
    state = {"owns": False}

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            if context["func_name"] == "leaf" and state["owns"]:
                response.data["return_values"]["ownership"] = "caller_owned"
            return response

    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    state["owns"] = True
    index.impls["leaf"]["code"] += "4 | /* changed expression */ return 1;\n"
    stats = modeler.run([FunctionEntry("entry")])
    assert calls == ["leaf", "mid"]
    assert stats.propagated_functions == 1


def test_model_pool_overlaps_with_one_entry_worker_and_shared_callee(tmp_path):
    calls = []
    barrier = threading.Barrier(2, timeout=3)

    class Agent(RecordingAgent):
        def run(self, context):
            if context["func_name"] in {"leaf", "sibling"}:
                barrier.wait()
            return super().run(context)

    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls, lambda: Agent(calls))
    stats = modeler.run([FunctionEntry("entry"), FunctionEntry("mid")])
    assert stats.stage_complete
    assert sorted(calls) == ["entry", "leaf", "mid", "sibling"]
    assert 2 <= stats.peak_concurrency <= 3


def test_missing_snapshot_retries_and_cancellation_is_not_a_partial_success(tmp_path):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    modeler.snapshot_store.delete_snapshot("leaf@src/leaf.c:1-8")
    modeler.run([FunctionEntry("entry")])
    assert calls == ["leaf"]
    token = CancellationToken()
    token.cancel("user_cancelled")
    with bind_cancellation_token(token), pytest.raises(CancellationError):
        modeler.run([FunctionEntry("entry")])


def test_cached_snapshot_points_register_without_rules_and_without_model_calls(tmp_path):
    calls = []

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            response.data["suspicious_points"] = (
                [
                    {
                        "category": "memory_safety",
                        "lines": "2",
                        "description": "Check the lifetime of the returned pointer.",
                    }
                ]
                if context["func_name"] == "leaf"
                else []
            )
            return response

    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls, lambda: Agent(calls))
    modeler.run([FunctionEntry("entry"), FunctionEntry("mid")])
    calls.clear()
    modeler.run([FunctionEntry("entry"), FunctionEntry("mid")])
    assert calls == []
    ledger = CandidateLedger(project_id="p", project_root=str(tmp_path), revision="r")
    issues = register_snapshot_candidates(modeler.result, CandidateRegistrar(ledger))
    assert len(issues) == 1
    assert issues[0]["line"] == 2
    assert issues[0]["attribution"]["discovered_by"] == ["semantic_modeling"]
    assert issues[0]["discovery_status"] == "hypothesis"
    assert {tuple(path) for path in issues[0]["call_paths"]} == {
        ("entry", "mid", "leaf"),
        ("mid", "leaf"),
    }
    assert ledger.records()
    assert modeler.result.suspicious_metrics["total"] == 1
    assert modeler.result.suspicious_metrics["registered"] == 1
    assert modeler.result.suspicious_metrics["registered_occurrences"] == 2
    frozen = ledger.freeze()
    assert all(not r.get("terminal_disposition") for r in frozen["records"])
    assert not modeler.user_config.list_external_functions()


def test_unresolvable_points_are_partial_and_never_get_ordinal_lines(tmp_path):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.run([FunctionEntry("entry")])
    result = modeler.result
    snapshot = next(iter(result.snapshots.values()))
    snapshot["suspicious_points"] = [
        {"category": "concurrency", "lines": "unknown", "description": "Needs investigation"}
    ]
    issues, metrics = snapshot_candidates(result)
    assert issues == []
    assert metrics["unresolved"] == 1
    assert metrics["unresolved_points"][0]["reason"] == "snapshot_point_location_unresolved"


def test_rule_and_concurrency_changes_do_not_invalidate_models(tmp_path):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    modeler.config.concurrency.entry_workers = 7
    modeler.config.analysis.max_premodel_depth = 1
    modeler.config.analysis.max_premodel_callees = 1
    modeler.snapshot_store.effective_rules_sha256 = "new-rules"
    modeler.run([FunctionEntry("entry")])
    assert calls == []


def test_line_movement_and_comments_reuse_snapshots(tmp_path):
    calls = []
    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls)
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    impl = index.impls["leaf"]
    impl["start_line"], impl["end_line"] = 11, 18
    impl["index_name"] = "leaf@src/leaf.c:11-18"
    impl["code"] = "11 | int leaf(void) {\n12 |  return /* harmless */ external_leaf();\n13 | }\n"
    modeler.run([FunctionEntry("entry")])
    assert calls == []
    assert modeler.snapshot_store.load_snapshot(impl["index_name"])["start_line"] == 11


def test_snapshot_alone_reaches_validator_after_freeze_and_dedup(tmp_path, monkeypatch):
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
    from zscope.core.validation.runner import ValidationRunner

    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.run([FunctionEntry("entry"), FunctionEntry("mid")])
    result = modeler.result
    leaf = next(s for s in result.snapshots.values() if s["func_name"] == "leaf")
    leaf["suspicious_points"] = [
        {"category": "memory_safety", "lines": "2", "description": "Check pointer lifetime"}
    ]
    parallel = ParallelAnalyzer(
        modeler.config, code_index=modeler.code_index, semantic_result=result
    )
    registrar = CandidateRegistrar(parallel._candidate_ledger)
    register_snapshot_candidates(result, registrar)
    register_snapshot_candidates(result, registrar)
    validated = []

    def validate(self, state):
        ledger = state["candidate_ledger"]
        pending = state["pending_new_issues"]
        assert len(pending) == 1
        assert len(pending[0]["call_paths"]) == 2
        with pytest.raises(RuntimeError, match="frozen"):
            register_snapshot_candidates(result, registrar)
        assert pending[0]["discovery_status"] == "hypothesis"
        validated.extend(pending)

    monkeypatch.setattr(ValidationRunner, "run", validate)
    parallel._run_scan_validation_queue()
    assert len(validated) == 1
    assert result.suspicious_metrics["validation_outcomes"] == {"pending": 1}


def test_changed_or_deleted_points_do_not_resurrect(tmp_path):
    calls = []
    active = {"point": True}

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            response.data["suspicious_points"] = (
                [{"category": "memory_safety", "lines": "2", "description": "Check lifetime"}]
                if active["point"] and context["func_name"] == "leaf"
                else []
            )
            return response

    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    modeler.run([FunctionEntry("entry")])
    assert len(snapshot_candidates(modeler.result)[0]) == 1
    active["point"] = False
    modeler.snapshot_store.delete_snapshot("leaf@src/leaf.c:1-8")
    calls.clear()
    modeler.run([FunctionEntry("entry")])
    assert calls == ["leaf"]
    assert snapshot_candidates(modeler.result)[0] == []

    calls.clear()
    modeler.run([FunctionEntry("entry")])
    assert calls == []
    assert snapshot_candidates(modeler.result)[0] == []


def test_parent_starts_as_soon_as_its_dependency_finishes(tmp_path):
    calls = []
    parent_started = threading.Event()

    class Agent(RecordingAgent):
        def run(self, context):
            if context["func_name"] == "sibling":
                assert parent_started.wait(3), "scheduler waited for an unrelated branch"
            if context["func_name"] == "mid":
                parent_started.set()
            return super().run(context)

    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls, lambda: Agent(calls))
    assert modeler.run([FunctionEntry("entry")]).stage_complete


def test_macro_dependency_changes_rebuild_only_actual_consumers(tmp_path):
    calls = []

    class Index(FakeCodeIndex):
        definition = "1 | #define LIMIT 8"

        def find_function_infos(self, func_name, file_path=""):
            rows = super().find_function_infos(func_name, file_path)
            for row in rows:
                if row["function_name"] == "leaf":
                    row["referenced_macros"] = [
                        {
                            "macro_index_name": "LIMIT@include/limits.h:1-1",
                            "definition": self.definition,
                            "is_function_like": False,
                            "reference_lines": [2],
                        }
                    ]
            return rows

    index = Index()
    modeler = modeler_for(tmp_path, index, calls)
    assert modeler.run([FunctionEntry("entry")]).stage_complete
    calls.clear()
    assert modeler.run([FunctionEntry("entry")]).stage_complete
    assert calls == []
    index.definition = "1 | #define LIMIT 16"
    modeler.run([FunctionEntry("entry")])
    assert set(calls) == {"leaf"}  # Object-like macros are deterministic dependencies.


def test_unconverged_recursive_component_is_unknown_and_retried(tmp_path):
    calls = []
    index = FakeCodeIndex()
    index.impls = {"entry": index._impl("entry", ["entry"])}

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            response.data["return_values"]["ownership"] = "owned" if len(calls) % 2 else "borrowed"
            return response

    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    stats = modeler.run([FunctionEntry("entry")])
    assert len(calls) == 3
    assert modeler.result.partial
    assert modeler.result.snapshots == {}
    assert any("recursive_contract_unknown" in reason for reason in stats.partial_reasons)
    modeler.run([FunctionEntry("entry")])
    assert len(calls) == 6


def test_long_call_chain_component_discovery_does_not_use_python_recursion(tmp_path):
    from zscope.orchestration.global_modeler import FunctionKey, _Graph

    keys = [FunctionKey(f"fn{i}") for i in range(2000)]
    graph = _Graph(
        impls={key: {} for key in keys},
        children={key: {keys[i + 1]} for i, key in enumerate(keys[:-1])},
    )
    modeler = modeler_for(tmp_path, FakeCodeIndex(), [])
    _, components = modeler._strongly_connected_components(graph)
    assert len(components) == 2000


def test_actual_agent_prompt_includes_frozen_structured_callee_contracts():
    from zscope.agents.semantic_modeler.agent import _prompt_metadata

    contracts = {"child": {"interface_contracts": [{"role": "allocator"}]}}
    assert (
        _prompt_metadata({"callee_interface_contracts": contracts})["callee_interface_contracts"]
        == contracts
    )


def test_deleted_function_retracts_generated_contract_but_preserves_unrelated_entry(tmp_path):
    calls = []

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            if context["func_name"] == "leaf":
                response.data["interface_contracts"] = [
                    {
                        "role": "allocator",
                        "carrier": {"kind": "return"},
                        "conditions": [],
                        "pairs": ["sibling"],
                        "confidence": 0.9,
                    }
                ]
            return response

    index = FakeCodeIndex()
    modeler = modeler_for(tmp_path, index, calls, lambda: Agent(calls))
    index.impls["leaf"].update(signature="void *leaf(void)", code="void *leaf(void) { return malloc(4); }")
    modeler.run([FunctionEntry("entry")])
    assert "leaf" in modeler.result.local_semantics.allocators
    assert any(r["func_name"] == "leaf" for r in modeler.user_config.list_external_functions())
    calls.clear()
    index.impls["mid"]["callees"] = []
    del index.impls["leaf"]
    modeler.run([FunctionEntry("entry")])
    assert "leaf" not in modeler.result.local_semantics.allocators
    assert not any(r["func_name"] == "leaf" for r in modeler.user_config.list_external_functions())


def test_manual_contract_notes_do_not_invalidate_models(tmp_path):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    workbook = modeler.user_config.workbook
    workbook.write_rows(
        {"resource": [{"symbol_name": "leaf", "kind": "copy", "source": "user", "notes": "first"}]}
    )
    modeler.run([FunctionEntry("entry")])
    calls.clear()
    rows = workbook.read_rows()
    rows["resource"][0]["notes"] = "editorial update"
    workbook.write_rows(rows)
    modeler.run([FunctionEntry("entry")])
    assert calls == []
    rows["resource"][0]["kind"] = "allocator"
    workbook.write_rows(rows)
    modeler.run([FunctionEntry("entry")])
    assert calls == ["mid"]  # The manual leaf is rebuilt without LLM; its caller sees the new contract.


def test_same_named_entry_points_are_filtered_by_symbol_identity(tmp_path):
    from test_global_modeler import SameNameCodeIndex

    calls = []

    class Agent(RecordingAgent):
        def run(self, context):
            response = super().run(context)
            response.data["suspicious_points"] = [
                {"category": "memory_safety", "lines": "2", "description": "Check lifetime."}
            ]
            return response

    modeler = modeler_for(tmp_path, SameNameCodeIndex(), calls, lambda: Agent(calls))
    modeler.run(
        [
            FunctionEntry("handle", file_path="src/a/handler.c"),
            FunctionEntry("handle", file_path="src/b/handler.c"),
        ]
    )
    points, metrics = snapshot_candidates(
        modeler.result, entry="handle", entry_file="src/a/handler.c"
    )
    assert metrics["total"] == 1
    assert points[0]["file_path"] == "src/a/handler.c"
    assert points[0]["call_path_symbols"][0][0]["file_path"] == "src/a/handler.c"


def test_snapshot_commit_failure_is_partial_and_retryable(tmp_path, monkeypatch):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    save = modeler.snapshot_store.save_snapshot

    def fail_leaf(index_name, *args, **kwargs):
        if index_name.startswith("leaf@"):
            raise OSError("storage unavailable")
        return save(index_name, *args, **kwargs)

    monkeypatch.setattr(modeler.snapshot_store, "save_snapshot", fail_leaf)
    modeler.run([FunctionEntry("entry")])
    assert modeler.result.partial
    assert not any(s["func_name"] == "leaf" for s in modeler.result.snapshots.values())
    monkeypatch.setattr(modeler.snapshot_store, "save_snapshot", save)
    calls.clear()
    modeler.run([FunctionEntry("entry")])
    assert "leaf" in calls
    assert not modeler.result.partial


def test_workbook_publication_failure_excludes_stale_generated_contracts(tmp_path, monkeypatch):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.user_config.workbook.write_rows(
        {
            "resource": [
                {
                    "symbol_name": "leaf",
                    "kind": "allocator",
                    "source": "inferred:semantic_modeling",
                    "file_path": "src/leaf.c",
                    "signature": "int leaf ( void )",
                },
                {"symbol_name": "manual", "kind": "allocator", "source": "user"},
            ]
        }
    )

    def fail(*args, **kwargs):
        raise OSError("workbook is locked")

    monkeypatch.setattr(modeler.user_config.workbook, "merge_generated", fail)
    modeler.run([FunctionEntry("entry")])
    assert modeler.result.partial
    assert "leaf" not in modeler.result.local_semantics.allocators
    assert "manual" in modeler.result.local_semantics.allocators


def test_public_modeling_profile_is_used_in_factory_and_cache_spec(tmp_path):
    from zscope.orchestration.global_modeler import modeling_profile
    from zscope.orchestration.semantic_modeling import IncrementalSemanticModeling

    modeler = modeler_for(tmp_path, FakeCodeIndex(), [])
    before = IncrementalSemanticModeling(modeler).spec
    modeler.config.scan.llm_profiles.modeling = "modeling_endpoint"
    assert modeling_profile(modeler.config) == "modeling_endpoint"
    assert IncrementalSemanticModeling(modeler).spec != before


def test_equivalent_rule_and_snapshot_obligations_share_validation_and_keep_provenance(tmp_path):
    calls = []
    modeler = modeler_for(tmp_path, FakeCodeIndex(), calls)
    modeler.run([FunctionEntry("entry")])
    snapshot = next(s for s in modeler.result.snapshots.values() if s["func_name"] == "leaf")
    snapshot["suspicious_points"] = [
        {"category": "bounds", "lines": "2", "description": "Check the access bound."}
    ]
    points, _ = snapshot_candidates(modeler.result)
    rule = deepcopy(points[0])
    for key in ("attribution", "snapshot_version", "candidate_kind"):
        rule.pop(key, None)
    rule.update(
        {
            "id": "rule_observation",
            "candidate_id": "rule_observation",
            "candidate_source": "deterministic_rule",
            "rule": "bounded_copy_sizeof_pointer",
        }
    )
    rule["evidence_pack"] = {
        "semantic_contract_version": modeler.result.contract_version,
        "proof_status": "unproven",
    }
    ledger = CandidateLedger(project_id="p", project_root=str(tmp_path), revision="r")
    registrar = CandidateRegistrar(ledger)
    registrar.register_issues([rule], source="deterministic_rule", force_unconfirmed=True)
    register_snapshot_candidates(modeler.result, registrar)
    records = ledger.records()
    assert len(records) == 1
    assert set(records[0].sources) == {"deterministic_rule", "semantic_snapshot"}
    attribution = records[0].ticket.evidence["candidate_payload"]["attribution"]
    assert set(attribution["discovered_by"]) == {"semantic_modeling", "deterministic_rule"}


def test_two_concurrent_scans_model_same_symbol_version_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    calls = []
    first = modeler_for(tmp_path, FakeCodeIndex(), calls)
    second = modeler_for(tmp_path, FakeCodeIndex(), calls)
    barrier = threading.Barrier(2, timeout=3)

    def run(modeler):
        barrier.wait()
        return modeler.run([FunctionEntry("entry")])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [first, second]))
    assert sorted(calls) == ["entry", "leaf", "mid", "sibling"]
    assert sum(result.cache_hit_functions for result in results) == 4


def test_modeling_context_reads_all_dependency_metadata_without_affecting_tools(tmp_path):
    from test_function_info_tool import FunctionInfoBackend, _index
    from zscope.retrieval.code_index import semantic_modeling_context

    source = tmp_path / "src" / "caller.c"
    source.parent.mkdir(parents=True)
    source.write_text("int Caller(void) { return 1; }\n", encoding="utf-8")
    functions = {
        name: {
            "name": name,
            "file": "src/caller.c",
            "start_line": 1,
            "end_line": 1,
            "signature": f"int {name}(void)",
        }
        for name in ["Caller", *[f"child_{i}" for i in range(35)]]
    }
    backend = FunctionInfoBackend(
        functions,
        callees=[
            {
                "name": f"child_{i}",
                "filename": "src/caller.c",
                "lineNumber": 1,
                "call_type": "direct",
            }
            for i in range(35)
        ],
        type_context={
            "referenced_types": [
                {
                    "name": f"T{i}",
                    "kind": "struct",
                    "type_index_name": f"T{i}@include/types.h:1-1",
                    "file_path": "include/types.h",
                    "start_line": 1,
                    "end_line": 1,
                    "full_definition": f"struct T{i} {{ int value; }};",
                    "reference_kinds": ["local"],
                    "reference_lines": [1],
                }
                for i in range(35)
            ]
        },
    )
    index = _index(tmp_path, backend, "unified")
    bounded = index.find_function_infos("Caller")[0]
    assert len(bounded["project_callees"]) == 30
    assert len(bounded["referenced_types"]) == 30
    with semantic_modeling_context():
        full = index.find_function_infos("Caller")[0]
    assert len(full["project_callees"]) == 35
    assert len(full["referenced_types"]) == 35
    assert not any(key.endswith("_truncation") for key in full)
    assert len(index.find_function_infos("Caller")[0]["project_callees"]) == 30


def test_analyzer_keeps_snapshot_points_as_context_without_registering_candidates(tmp_path):
    from zscope.core.analysis.analyzer import Analyzer

    modeler = modeler_for(tmp_path, FakeCodeIndex(), [])
    modeler.run([FunctionEntry("entry")])
    leaf = next(
        snapshot
        for snapshot in modeler.result.snapshots.values()
        if snapshot["func_name"] == "leaf"
    )
    leaf["suspicious_points"] = [
        {"category": "memory_safety", "lines": "2", "description": "Check pointer lifetime."}
    ]
    analyzer = Analyzer.__new__(Analyzer)
    analyzer.config = modeler.config
    analyzer.config.project.agents = []
    analyzer.semantic_result = modeler.result
    analyzer.defer_validation_to_scan = False
    analyzer.decision_fact_cache = None
    analyzer._run_single_entry_active_discovery = lambda state: None
    ledger = CandidateLedger(project_id="p", project_root=str(tmp_path), revision="r")
    state = {
        "agent_context": {},
        "entry_func": "entry",
        "pending_new_issues": [],
        "candidate_ledger": ledger,
    }
    analyzer._step_vulnerability_mining(state)
    assert state["pending_new_issues"] == []
    assert ledger.records() == []
    assert leaf["suspicious_points"][0]["lines"] == "2"


def test_outward_fingerprint_excludes_legacy_narration_and_suspicious_points():
    from copy import deepcopy
    from zscope.semantics.contracts import digest, outward_contract

    before = {
        "func_name": "f",
        "summary": "first wording",
        "parameters": [
            {
                "parameter_name": "p",
                "parameter_type": "void *",
                "nullable": "no",
                "constraints": ["a live object"],
            }
        ],
        "return_values": {
            "return_type": "int",
            "caller_obligations": "release after use",
            "success_cases": [{"value": "0", "condition": "operation succeeded"}],
        },
        "interface_contracts": [],
        "suspicious_points": [],
    }
    after = deepcopy(before)
    after["summary"] = "different wording"
    after["parameters"][0]["constraints"] = ["object must remain valid"]
    after["return_values"]["caller_obligations"] = "caller cleans up later"
    after["return_values"]["success_cases"][0]["condition"] = "success"
    after["suspicious_points"] = [
        {"category": "memory_safety", "lines": "2", "description": "review"}
    ]
    assert digest(outward_contract(before)) == digest(outward_contract(after))
    after["parameters"][0]["nullable"] = "yes"
    assert digest(outward_contract(before)) != digest(outward_contract(after))
