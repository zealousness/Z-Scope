"""S04: current native replay, explicit business assumptions and report projection."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from test_lifecycle_paths import candidates, paths_project
from test_validation_pipeline import FakeUserConfig, _score
from zscope.core.candidates.decision_facts import attach_decision_facts
from zscope.core.validation.pipeline import ValidationPipeline, needs_review_sub_state
from zscope.core.validation.protocol_assessment import assess_protocol_candidate
from zscope.semantics.contracts import ContractRegistry


def assessed(project, name="cancel_stale"):
    (issue,) = candidates(project, name)
    attach_decision_facts(issue)
    issue["protocol_assessment"] = assess_protocol_candidate(issue, project[0], project[2])
    return issue


@pytest.mark.parametrize(
    "name,state,count",
    [
        ("cancel_stale", "conditional", 1),
        ("retained_then_returned", "conditional", 1),
        ("other_pool", "conditional", 1),
        ("new_generation", "conditional", 1),
        ("failure_unreleased", "conditional", 2),
        ("stale_retained", "pending", 1),
    ],
)
def test_native_replay_and_scoped_assumptions(paths_project, name, state, count):
    issue = assessed(paths_project, name)
    assessment = issue["protocol_assessment"]
    assert assessment["state"] == state, assessment
    assert assessment["technical_witness_current"]
    assert not assessment["proof_authority"]
    assert len(assessment["assumptions"]) == count
    assert all(
        a["status"] == "unconfirmed" and a["source_kind"] == "analysis_requirement"
        for a in assessment["assumptions"]
    )
    assert all(
        a["scope"]["object_ref"] == assessment["object_ref"] for a in assessment["assumptions"]
    )
    assert all(
        r["verification"]["source_hash"] and r["contract_hash"] for r in assessment["source_refs"]
    )
    assert assessment["technical_gaps"] == (
        ["event:later_slot_access"] if state == "pending" else []
    )


@pytest.mark.parametrize("verdict", ["verified", "uncertain", "rejected"])
@pytest.mark.parametrize("erase_missing", [False, True])
def test_model_and_generic_completion_cannot_supply_business_authority(
    paths_project, verdict, erase_missing
):
    issue = assessed(paths_project, "failure_unreleased")
    if erase_missing:
        issue["missing_fact_kinds"] = []
        issue["decision_fact_slice"]["missing_fact_kinds"] = []
        issue["decision_fact_slice"]["coverage"] = "complete"
        issue["candidate_promotion_eligible"] = True
    result = ValidationPipeline(
        FakeUserConfig(), uncertain_confirm_threshold=0.8
    ).apply_validator_result(
        issue,
        {"confidence_score": 1.0, "protocol_assessment": {"state": "confirmed"}},
        verdict=verdict,
        score_data=_score(1.0),
    )
    assert result.report_bucket == "observations"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["needs_review_sub_state"] == "business_conditional"
    assert "业务前提" in issue["promotion_review_reason"]


@pytest.mark.parametrize(
    "change", ["json", "candidate", "observation", "receipt", "technical_gap", "conflict"]
)
def test_forged_stale_and_conflicting_receipts_are_pending(paths_project, change):
    issue = assessed(paths_project)
    issue["candidate_disposition"] = "needs_review"
    assert needs_review_sub_state(deepcopy(issue)) == "business_conditional"
    if change == "json":
        issue = json.loads(json.dumps(issue))
    elif change == "candidate":
        issue["candidate_id"] = "unrelated"
    elif change == "observation":
        issue["evidence_pack"]["object_protocol_path"]["selected_observation"][
            "kind"
        ] = "wrong_pool_return"
    elif change == "receipt":
        issue["protocol_assessment"]["assumptions"] = []
    elif change == "technical_gap":
        issue["decision_fact_slice"]["missing_fact_kinds"].append("event:unknown_alias")
    else:
        issue["blocking_negative_evidence"] = True
    assert needs_review_sub_state(issue) == "protocol_pending"


def test_changed_source_contract_and_build_invalidate_replay(paths_project):
    issue = assessed(paths_project)
    index, _, registry = paths_project
    for contract in registry.contracts:
        changed = ContractRegistry(list(registry.contracts))
        changed.add(replace(contract, evidence=[{"changed": True}]))
        result = assess_protocol_candidate(issue, index, changed)
        assert result["state"] == "pending"
        assert "path_or_contract_changed" in result["technical_gaps"]
    assert assess_protocol_candidate(issue, index, ContractRegistry())["state"] == "pending"
    assert assess_protocol_candidate(issue, index, None)["state"] == "pending"

    class ChangedSource:
        get_function_program_facts = index.get_function_program_facts

        def get_function_impl(self, *args, **kwargs):
            return {"code": "void changed(void) {}"}

    result = assess_protocol_candidate(issue, ChangedSource(), registry)
    assert result["technical_gaps"] == ["protocol_source_changed"]
    issue["evidence_pack"]["object_protocol_path"]["build_context_id"] = "unrelated"
    assert assess_protocol_candidate(issue, index, registry)["state"] == "pending"


def test_disabled_model_still_replays_and_report_preserves_questions(paths_project):
    from test_validation_runner import _runner, _state
    from zscope.reporting.issue_markdown import build_document
    from zscope.reporting.report import Issue
    from zscope.reporting.views import build_report_views

    (issue,) = candidates(paths_project, "failure_unreleased")
    attach_decision_facts(issue)
    runner = _runner(None, enabled=False, code_index=paths_project[0])
    runner.get_contract_registry = lambda: paths_project[2]
    state = _state(issue)
    runner.run(state)
    assert not state["issues"] and len(state["observations"]) == 1
    assert issue["needs_review_sub_state"] == "business_conditional"
    assert Issue.from_dict(issue).protocol_assessment["assumptions"]
    persisted = json.loads(json.dumps(issue))
    views = build_report_views([], [persisted])
    review = views["with_needs_review"]["issues"][0]
    assert len(review["needs_review_presentation"]["business_assumptions"]) == 2
    markdown = build_document(review, "protocol-review")
    assert "条件性风险" in markdown and "责任终点" in markdown
    assert "source_refs" in markdown and "analysis_requirement" in markdown
    # Reloading a saved conclusion cannot authorize a new scan without replay.
    runner.get_contract_registry = lambda: None
    runner.run(_state(persisted))
    assert persisted["needs_review_sub_state"] == "protocol_pending"


def test_enabled_runner_includes_advisory_assumptions_in_model_context(paths_project):
    from test_validation_runner import _runner, _state

    (issue,) = candidates(paths_project, "cancel_stale")
    attach_decision_facts(issue)
    runner = _runner(None, code_index=paths_project[0])
    runner.get_contract_registry = lambda: paths_project[2]
    evidence = runner._build_evidence_pack(issue, _state(issue), "")
    assert evidence["protocol_assessment"]["technical_witness_current"]
    val_input = runner._validator_input(issue, "", evidence)
    assert "analysis_requirement" in json.dumps(val_input)


@pytest.mark.parametrize("verdict", ["verified", "uncertain", "rejected"])
def test_full_runner_preserves_conditional_until_acceptance(paths_project, verdict):
    from test_validation_runner import _runner, _state, FakeValidatorAgent
    from zscope.framework.base import AgentResponse

    (issue,) = candidates(paths_project, "cancel_stale")
    attach_decision_facts(issue)
    agent = FakeValidatorAgent(
        [
            AgentResponse(
                success=True,
                data={
                    "verdict": verdict,
                    "confidence_score": 1.0,
                    "reasoning": "model opinion",
                },
            )
        ]
    )
    runner = _runner(agent, code_index=paths_project[0])
    runner.get_contract_registry = lambda: paths_project[2]
    state = _state(issue)
    runner.run(state)
    assert not state["issues"]
    (observation,) = state["observations"]
    assert observation["needs_review_sub_state"] == "business_conditional"
    assert observation["policy_disposition"] == "needs_review"
    assert agent.inputs and observation["protocol_assessment"]["source_refs"]


def test_current_assessment_changes_validator_cluster_cache(paths_project):
    from types import SimpleNamespace
    from test_validation_runner import _runner

    issue = assessed(paths_project)
    issue["validation_cluster_uid"] = "same-cluster"
    runner = _runner(None)
    item = SimpleNamespace(
        raw_issue=issue, issue_func="cancel_stale", issue_code="", evidence_pack={}
    )
    first = runner._validator_cache_key(item)
    issue["protocol_assessment"] = assess_protocol_candidate(issue, paths_project[0], None)
    assert first != runner._validator_cache_key(item)


def test_summary_markdown_keeps_assumptions_and_technical_gaps(paths_project, tmp_path):
    from zscope.reporting.report import FinalReport, ReportGenerator
    from zscope.reporting.views import build_report_views

    items = [assessed(paths_project, name) for name in ("failure_unreleased", "stale_retained")]
    pipeline = ValidationPipeline(FakeUserConfig())
    for issue in items:
        pipeline.apply_unvalidated(issue, _score(1.0))
    views = build_report_views([], items, canonical_projection=True)
    final = FinalReport(
        entry_function="protocols", overall_verdict="no_issue_found", report_views=views
    )
    generator = ReportGenerator.__new__(ReportGenerator)
    generator.project_root = tmp_path
    content = generator.save_markdown_report(final).read_text(encoding="utf-8")
    assert "条件性风险：业务前提待核实" in content
    assert "待补证：技术证据未闭合" in content
    assert "业务前提（未确认）" in content and "责任终点" in content
    assert "event:later_slot_access" in content
