from copy import deepcopy
from types import SimpleNamespace

import pytest

from zscope.framework.base import AgentResponse
from zscope.orchestration.candidates import CandidateLedger, CandidateRegistrar
from zscope.orchestration.hierarchical_discovery import (
    ContractDiscoveryAgent,
    HierarchicalDiscovery,
    build_hierarchy,
    inherited_obligations,
    rule_proposals,
    validate_lifecycle,
    validate_summary,
)
from zscope.rules.validation_obligations import binding_for_issue


def function(name="a", build="build-a", calls=()):
    return {
        "id": f"FN_{name}_{build}",
        "level": "function",
        "function": name,
        "usr": f"c:@F@{name}",
        "build_context_id": build,
        "file": f"/{name}.c",
        "start_line": 1,
        "end_line": 5,
        "source": "1: int a() {\n2: return 1;\n3: }",
        "manifest": {"source_digest": name + build},
        "facts": {
            "functions": [
                {
                    "owner": {"usr": f"c:@F@{name}"},
                    "events": [{"callee": {"usr": f"c:@F@{c}"}} for c in calls],
                }
            ]
        },
    }


def summary(unit, *, hypothesis=False):
    ref = unit["id"] + ":2"
    return {
        "preconditions": [],
        "postconditions": [],
        "actual_effects": [],
        "state_transitions": [],
        "obligations": [],
        "unknowns": [],
        "hypotheses": (
            [
                {
                    "defect_class": "resource_leak",
                    "description": "失败分支遗漏清理",
                    "violated_condition": "失败返回前应释放本次分配",
                    "source_ref": ref,
                    "sink_ref": ref,
                    "counter_explanation": "可能经由返回值转移所有权",
                    "assumptions": [],
                    "required_facts": ["ownership_transfer", "cleanup_coverage"],
                    "positive_example": "allocate; fail; return",
                    "negative_example": "allocate; fail; release; return",
                    "applicability": "当前分配成功且失败路径可达",
                    "exclusions": "所有权已转移",
                    "proposal_kind": "new_rule",
                    "object": "resource",
                    "generation": "allocation@2",
                }
            ]
            if hypothesis
            else []
        ),
    }


EMPTY_LIFECYCLE = {"boundaries": [], "lifetimes": []}


def test_same_usr_variant_is_never_wildcard_and_cross_tu_requires_link():
    a, b, other = function(calls=["b"]), function("b", "build-b"), function("b", "variant-b")
    hierarchy = build_hierarchy([a, b, other], [], EMPTY_LIFECYCLE)
    assert hierarchy["edges"] == []
    hierarchy = build_hierarchy(
        [a, b, other], [{"target_id": "app", "members": ["build-a", "build-b"]}], EMPTY_LIFECYCLE
    )
    assert hierarchy["edges"] == [[a["id"], b["id"]]]
    ambiguous = build_hierarchy(
        [a, b, other], [{"members": ["build-a", "build-b", "variant-b"]}], EMPTY_LIFECYCLE
    )
    assert ambiguous["edges"] == []
    assert ambiguous["gaps"]


def test_parent_boundary_cannot_create_link_authority():
    a, b = function(), function("b", "build-b")
    config = {
        "lifetimes": [],
        "boundaries": [
            {"id": "service", "level": "module", "members": [a["id"], b["id"]], "confirmed": True}
        ],
    }
    hierarchy = build_hierarchy([a, b], [], config)
    assert any(g["reason"] == "missing_real_link_record" for g in hierarchy["gaps"])
    assert not any(u["boundary_confirmed"] for u in hierarchy["units"])


def test_references_must_be_read_and_in_native_function():
    unit = function()
    value = summary(unit, hypothesis=True)
    inventory = {unit["id"]: unit}
    assert not validate_summary(value, inventory, set())
    assert validate_summary(value, inventory, set(inventory))
    value["hypotheses"][0]["sink_ref"] = unit["id"] + ":99"
    assert not validate_summary(value, inventory, set(inventory))


@pytest.mark.parametrize("kind", ["release", "unlock", "completion", "state"])
def test_debts_preserve_identity_and_require_real_transfer_edge(kind):
    a, b = function(), function("b")
    child = summary(b)
    child["obligations"] = [
        {
            "kind": kind,
            "object": "out.resource",
            "generation": "allocation@2",
            "owner": b["id"],
            "condition": "return == 0",
            "boundary": "caller teardown",
            "status": "transferred",
            "transfer_to": a["id"],
            "refs": [b["id"] + ":2"],
            "assumptions": [],
        }
    ]
    unresolved = inherited_obligations({b["id"]: child}, [])
    assert unresolved[0]["status"] == "unknown"
    propagated = inherited_obligations({b["id"]: child}, [[a["id"], b["id"]]])
    assert propagated[0]["status"] == "transferred"
    assert propagated[0]["transfer_chain"] == [b["id"], a["id"]]
    assert propagated[0]["generation"] == "allocation@2"
    assert propagated[0]["authority"] == "semantic_hypothesis"


def test_process_retention_never_becomes_discharge():
    a = function()
    child = summary(a)
    child["obligations"] = [
        {
            "kind": "release",
            "object": "global.cache",
            "generation": "allocation@2",
            "owner": a["id"],
            "condition": "allocation succeeded",
            "boundary": "process exit",
            "status": "retained",
            "transfer_to": "",
            "refs": [a["id"] + ":2"],
            "assumptions": [],
        }
    ]
    assert inherited_obligations({a["id"]: child}, [])[0]["status"] == "retained"
    config = deepcopy(EMPTY_LIFECYCLE)
    config["lifetimes"] = [
        {
            "id": "cache",
            "build_context_id": "build-a",
            "object": "global.cache",
            "lifetime": "process",
            "reason": "bounded singleton",
            "confirmed": True,
        }
    ]
    assert validate_lifecycle(config) == config
    config["lifetimes"][0]["build_context_id"] = ""
    with pytest.raises(ValueError):
        validate_lifecycle(config)


def test_ruleless_hypothesis_survives_real_candidate_registration(tmp_path):
    a = function()
    hypothesis = summary(a, hypothesis=True)["hypotheses"][0]
    candidate = HierarchicalDiscovery.candidate(hypothesis, {a["id"]: a}, a, "current")
    ledger = CandidateLedger(project_id="project", project_root=str(tmp_path), revision="rev")
    CandidateRegistrar(ledger, run_id="run").register_issues(
        [candidate],
        source="hierarchical_discovery",
        default_entry_identity="entry",
        force_unconfirmed=True,
    )
    assert len(ledger.records()) == 1
    binding = binding_for_issue(candidate)
    assert binding is not None and binding.origin == "llm_contract_hypothesis"
    assert binding.rule_id == ""
    candidate["rule"] = "unknown_rule"
    assert binding_for_issue(candidate) is None


def test_cold_hot_resume_and_declaration_change(monkeypatch, tmp_path):
    a, b = function(calls=["b"]), function("b")
    hierarchy = build_hierarchy([a, b], [], EMPTY_LIFECYCLE)
    calls = []

    def run(agent, data):
        calls.append(data["unit"]["level"])
        agent.visible.update(agent.members)
        return AgentResponse(success=True, data=summary(a), metadata={"cumulative_total_tokens": 7})

    monkeypatch.setattr(ContractDiscoveryAgent, "run", run)
    discovery = HierarchicalDiscovery(
        client=SimpleNamespace(), cache_dir=tmp_path, require_current=lambda: None
    )
    cold = discovery.run(hierarchy, EMPTY_LIFECYCLE)
    assert set(calls) == {"function", "feature", "module"}
    hot = discovery.run(hierarchy, EMPTY_LIFECYCLE)
    assert cold["summaries"] == hot["summaries"]
    assert hot["model_calls"] == 0 and hot["cache_hits"] == cold["model_calls"]
    changed = deepcopy(EMPTY_LIFECYCLE)
    changed["lifetimes"] = [{"id": "cache", "confirmed": False}]
    assert discovery.run(hierarchy, changed)["model_calls"] == cold["model_calls"]


def test_currentness_failure_does_not_publish_model_result(monkeypatch, tmp_path):
    a = function()
    count = [0]

    def current():
        count[0] += 1
        if count[0] > 1:
            raise ValueError("changed native inputs")

    monkeypatch.setattr(
        ContractDiscoveryAgent,
        "run",
        lambda self, data: AgentResponse(success=True, data=summary(a), metadata={}),
    )
    discovery = HierarchicalDiscovery(
        client=SimpleNamespace(), cache_dir=tmp_path, require_current=current
    )
    with pytest.raises(ValueError, match="changed native"):
        discovery.run(build_hierarchy([a], [], EMPTY_LIFECYCLE), EMPTY_LIFECYCLE)
    assert not list(tmp_path.glob("*.json"))


def test_proposal_is_draft_until_matching_candidate_confirmed():
    a = function()
    candidate = HierarchicalDiscovery.candidate(
        summary(a, hypothesis=True)["hypotheses"][0], {a["id"]: a}, a, "input"
    )
    candidate["candidate_uid"] = "c1"
    assert rule_proposals([candidate], [])[0]["status"] == "draft"
    proposal = rule_proposals(
        [candidate], [{"candidate_uid": "c1", "candidate_disposition": "confirmed"}]
    )[0]
    assert proposal["status"] == "ready_for_review" and proposal["auto_enable"] is False


@pytest.mark.parametrize("depth", ["fast", "balanced", "deep"])
def test_old_finder_is_offline_only(tmp_path, depth):
    from test_single_entry_active_discovery import _analyzer, _state

    analyzer = _analyzer(tmp_path, depth)
    analyzer._legacy_discovery_offline = False
    state = _state(tmp_path)
    analyzer._run_single_entry_active_discovery(state)
    assert state["active_discovery"]["status"] == "coordinator_owned"
    assert state["pending_new_issues"] == []


def test_operational_funnel_separates_static_recovery_from_deep_novelty():
    from zscope.orchestration.hierarchical_discovery import mode_outcomes

    rows = [
        {
            "validation_cluster_uid": "static",
            "candidate_disposition": "confirmed",
            "validator_v3_entered": True,
            "autonomous_validation_cost": {"tokens": 40, "elapsed_seconds": 2},
        },
        {"validation_cluster_uid": "new", "candidate_disposition": "confirmed"},
        {"validation_cluster_uid": "cheap", "candidate_disposition": "rejected_with_proof"},
    ]
    result = mode_outcomes(
        rows,
        {
            "candidates": [
                {"validation_cluster_uid": "new", "deep_contribution": "additional_candidate"}
            ]
        },
    )
    assert result["static_candidates"] == 2
    assert result["cheap_rejected"] == 1
    assert result["cheap_unresolved"] == result["autonomous_confirmed"] == 1
    assert result["deep_additional_confirmed"] == 1
    assert result["autonomous_tokens"] == 40
    assert result["quality_measurement"] == "requires_independent_benchmark_scoring"


def test_withdrawn_proposal_is_retained_as_stale(tmp_path):
    from zscope.orchestration.hierarchical_discovery import save_rule_proposals

    path = tmp_path / "proposals.json"
    old = {
        "id": "RP_old",
        "schema_version": "zscope.rule-proposal.v1",
        "status": "ready_for_review",
    }
    save_rule_proposals(path, [old])
    retained = save_rule_proposals(path, [])
    assert retained[0]["status"] == "stale"
    assert retained[0]["auto_enable"] is False


def test_incremental_leaf_reuse_and_composition_ablation(monkeypatch, tmp_path):
    a, b = function(calls=["b"]), function("b")
    calls = []

    def run(agent, data):
        calls.append(data["unit"]["id"])
        agent.visible.update(agent.members)
        return AgentResponse(success=True, data=summary(a), metadata={})

    monkeypatch.setattr(ContractDiscoveryAgent, "run", run)
    discovery = HierarchicalDiscovery(
        client=SimpleNamespace(), cache_dir=tmp_path, require_current=lambda: None
    )
    discovery.run(build_hierarchy([a, b], [], EMPTY_LIFECYCLE), EMPTY_LIFECYCLE)
    a["source"] += "\n/* changed */"
    calls.clear()
    incremental = discovery.run(build_hierarchy([a, b], [], EMPTY_LIFECYCLE), EMPTY_LIFECYCLE)
    assert a["id"] in calls and b["id"] not in calls
    assert incremental["cache_hits"] >= 1
    calls.clear()
    ablated = discovery.run(
        build_hierarchy([a, b], [], EMPTY_LIFECYCLE), EMPTY_LIFECYCLE, compose=False
    )
    assert set(calls) == {a["id"], b["id"]}
    assert ablated["ablation"]["compose"] is False
