"""Real native inventory shared by all modes; no remote model requests."""

from types import SimpleNamespace

import pytest
from test_hierarchical_discovery import summary

from test_instance_analysis import native_variants, _native_index, _native_config, _semantic_stub
from zscope.config.function_entry import FunctionEntry
from zscope.framework.base import AgentResponse
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.hierarchical_discovery import ContractDiscoveryAgent
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer


def test_three_modes_reuse_exact_static_inventory_and_cache(native_variants, monkeypatch):
    backend, root, cdb = native_variants
    model_levels = []

    def summarize(agent, data):
        model_levels.append(data["unit"]["level"])
        agent.visible.update(agent.members)
        value = {
            "preconditions": [],
            "postconditions": [],
            "actual_effects": [],
            "state_transitions": [],
            "obligations": [],
            "hypotheses": [],
            "unknowns": ["test model; no quality inference"],
        }
        if data["unit"]["level"] == "function" and data["unit"]["function"] == "helper":
            # An intentionally unconfirmed contract exercises registration and
            # proposal persistence; it must never be counted as a true defect.
            h = summary(data["unit"], hypothesis=True)["hypotheses"][0]
            h["source_ref"] = h["sink_ref"] = (
                data["unit"]["id"] + ":" + str(data["unit"]["start_line"])
            )
            h["assumptions"] = ["unconfirmed fixture contract"]
            value["hypotheses"] = [h]
        return AgentResponse(success=True, data=value, metadata={})

    monkeypatch.setattr(ContractDiscoveryAgent, "run", summarize)
    inventories, candidates = [], []
    for mode in ("fast", "balanced", "deep"):
        index = _native_index(backend, root, cdb)
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        config = _native_config(root, cdb)
        config.scan.depth = mode
        analyzer = ParallelAnalyzer(
            config, code_index=index, semantic_result=_semantic_stub(), llm_clients={}
        )
        if mode == "deep":
            analyzer._scan_role_llm_client = lambda role: SimpleNamespace(models=["fixture"])
        try:
            report = analyzer.analyze_entry_instances(plan)
            assert report.status == "analyzed"
            state = analyzer._fast_static_scan_state
            assert state["activated"] is True
            inventories.append(
                {(r["build_context_id"], r["usr"]) for r in state["analysis_units"] if r.get("usr")}
            )
            records = analyzer._candidate_ledger.records()
            novel = [
                r
                for r in records
                if r.ticket.evidence.get("candidate_payload", {}).get("candidate_source")
                == "hierarchical_discovery"
            ]
            candidates.append({r.candidate_uid for r in records if r not in novel})
            if mode != "fast":
                assert state["cache"]["local_cold_misses"] == 0
            if mode == "deep":
                assert analyzer._active_discovery_state["path"] == "hierarchical_contracts"
                assert novel
                assert all(r.disposition != "confirmed" for r in novel)
                assert analyzer._active_discovery_state["rule_proposals"]
            else:
                assert model_levels == []
        finally:
            analyzer.close()
    assert inventories[0] == inventories[1] == inventories[2]
    assert candidates[0] == candidates[1] == candidates[2]
    assert set(model_levels) == {"function", "feature", "module"}
