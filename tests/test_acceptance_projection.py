"""U02: conservative acceptance/coverage projection tests.

Every case pins one direction of the conservative contract: model verdicts,
scores, labels, shadow rows, suppression and missing triggers never promote
a finding; only re-derivable programmatic adjudication does.
"""

from __future__ import annotations

import json

import pytest

from zscope.core.validation.protocol_assessment import (
    RULE as PROTOCOL_RULE,
    _identity as protocol_candidate_identity,
)
from zscope.reporting.acceptance import (
    ACCEPTANCE_STATES,
    acceptance_coverage,
    acceptance_for_issue,
    report_context_for,
)
from zscope.reporting.report import FinalReport, Issue

ACCEPTANCE_KEYS = {
    "state",
    "reason",
    "resource_label",
    "build_context_id",
    "trigger_summary",
    "reproduction",
    "sources_count",
}


def _base_issue(**overrides):
    issue = {
        "id": "ISSUE_1",
        "function": "process_request",
        "location": "src/handler.c:42",
        "category": "security",
        "subcategory": "buffer_overflow",
        "confidence": 0.5,
        "impact_level": "high",
        "validation_status": "needs_review",
        "candidate_disposition": "needs_review",
    }
    issue.update(overrides)
    return issue


def _confirm_proof(**overrides):
    proof = {
        "proof_kind": "unguarded_source_to_sink",
        "outcome": "confirm",
        "completeness": "complete",
        "facts": ["source_to_sink_complete", "missing_guard"],
        "fact_ids": ["fact-1", "fact-2"],
        "code_hash": "codehash-confirm",
        "producer_engine": "clang_cfg",
    }
    proof.update(overrides)
    return proof


def _reject_proof(**overrides):
    proof = {
        "proof_kind": "guard_dominates_sink",
        "outcome": "reject",
        "completeness": "complete",
        "facts": ["guard_dominates_sink"],
        "fact_ids": ["fact-3"],
        "code_hash": "codehash-reject",
        "producer_engine": "clang_cfg",
    }
    proof.update(overrides)
    return proof


def _confirmed_issue(**overrides):
    proof = _confirm_proof()
    issue = _base_issue(
        validation_status="validated",
        candidate_disposition="confirmed",
        finding_kind="verified_vulnerability",
        decision_proof={
            "outcome": "confirm",
            "proof_kind": proof["proof_kind"],
            "producer_engine": proof["producer_engine"],
            "completeness": "complete",
        },
        promotion_reason="deterministic_confirmation_proof",
        proof_provider="clang_cfg",
        proof_coverage="complete",
        resource_identity="obj-123",
        trigger_condition="外部长度到达拷贝",
        evidence_sources=["cfg_engine", "cfg_engine", "svf"],
        evidence_pack={
            "build_context_id": "build-abc",
            "proofs": [proof],
        },
    )
    issue.update(overrides)
    return issue


def _protocol_issue(**overrides):
    issue = _base_issue(
        rule_id=PROTOCOL_RULE,
        candidate_id="cand-protocol-1",
        resource_identity="pool-slot-0-gen-3",
        needs_review_sub_state="business_conditional",
        evidence_pack={
            "build_context_id": "build-xyz",
            "object_protocol_path": {
                "schema": "zscope.object-protocol-path.v5",
                "complete": True,
                "selected_observation": {
                    "kind": "repeat_return",
                    "resource_id": "pool-slot-0-gen-3",
                },
            },
        },
    )
    issue.update(overrides)
    return issue


def _assessment_for(issue, **overrides):
    assessment = {
        "schema": "zscope.protocol-assessment.v12",
        "state": "conditional",
        "technical_witness_current": True,
        "technical_gaps": [],
        "proof_authority": False,
        "build_context_id": "build-xyz",
        "assumptions": [
            {
                "id": "ASSUMPTION_1",
                "fact_kind": "event:business_release_requirement",
                "statement": "业务路径允许该归还顺序。",
                "status": "unconfirmed",
                "source_kind": "analysis_requirement",
                "scope": {"build_context_id": "build-xyz"},
            }
        ],
    }
    assessment.update(overrides)
    assessment["candidate_binding"] = protocol_candidate_identity(issue)
    return assessment


def _assert_contract_shape(acceptance):
    assert set(acceptance.keys()) == ACCEPTANCE_KEYS
    assert acceptance["state"] in ACCEPTANCE_STATES
    assert set(acceptance["reproduction"].keys()) == {"status", "summary"}
    json.dumps(acceptance)


def test_confirmed_requires_replayable_programmatic_proof():
    issue = _confirmed_issue()
    acceptance = acceptance_for_issue(issue, report_context_for({"schema_version": 2}))
    _assert_contract_shape(acceptance)
    assert acceptance["state"] == "confirmed"
    assert acceptance["reason"] == "deterministic_confirmation_proof_current"
    assert acceptance["resource_label"] == "obj-123"
    assert acceptance["build_context_id"] == "build-abc"
    assert acceptance["trigger_summary"] == "外部长度到达拷贝"
    assert acceptance["sources_count"] == 2
    assert acceptance["reproduction"] == {"status": "not_measured", "summary": None}


def test_confirmed_survives_json_round_trip():
    issue = json.loads(json.dumps(_confirmed_issue()))
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "confirmed"


@pytest.mark.parametrize(
    "extra,reason",
    [
        ({"promotion_reason": "model_high_confidence_confirmation"}, "model_verdict_without_proof"),
        ({"confirmed_via": "high_confidence_band"}, "model_verdict_without_proof"),
        ({}, "policy_confirmation_without_proof"),
    ],
)
def test_model_verified_high_score_never_confirms(extra, reason):
    issue = _base_issue(
        validation_status="validated",
        candidate_disposition="confirmed",
        finding_kind="verified_vulnerability",
        confidence=0.99,
        final_score=0.99,
        validator_verdict="verified",
        **extra,
    )
    acceptance = acceptance_for_issue(issue)
    _assert_contract_shape(acceptance)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == reason


def test_model_rejected_without_proof_stays_pending():
    issue = _base_issue(
        validation_status="rejected",
        candidate_disposition="rejected_with_proof",
        rejection_source="validator_without_deterministic_proof",
        validator_verdict="rejected",
        confidence=0.97,
    )
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "rejection_without_replayable_proof"


def test_model_rejected_unproven_review_row_stays_pending():
    issue = _base_issue(
        needs_review_sub_state="model_rejected_unproven",
        validator_verdict="rejected",
    )
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "model_rejection_without_proof"


def test_rejection_with_replayable_proof_is_ruled_out():
    issue = _base_issue(
        validation_status="rejected",
        candidate_disposition="rejected_with_proof",
        rejection_source="deterministic_validator_proof",
        deterministic_rejection=True,
        evidence_pack={"proofs": [_reject_proof()]},
    )
    acceptance = acceptance_for_issue(issue)
    _assert_contract_shape(acceptance)
    assert acceptance["state"] == "ruled_out"
    assert acceptance["reason"] == "deterministic_rejection_proof_current"


def test_llm_authored_proof_has_no_authority():
    issue = _confirmed_issue()
    issue["evidence_pack"]["proofs"] = [_confirm_proof(producer_engine="llm")]
    issue.pop("decision_proof")
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "policy_confirmation_without_proof"


def test_incomplete_proof_facts_stay_pending():
    issue = _confirmed_issue()
    issue["evidence_pack"]["proofs"] = [_confirm_proof(facts=["source_to_sink_complete"])]
    issue.pop("decision_proof")
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"


@pytest.mark.parametrize(
    "marker",
    [
        {"validation_status": "shadow"},
        {"candidate_disposition": "shadow_observation"},
        {"finding_kind": "rollout_shadow_observation"},
    ],
)
def test_shadow_observation_never_promotes(marker):
    issue = _confirmed_issue()
    issue.update(marker)
    if "validation_status" in marker:
        issue["candidate_disposition"] = "shadow_observation"
    acceptance = acceptance_for_issue(issue)
    _assert_contract_shape(acceptance)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "shadow_observation_not_adjudication"


def test_risk_accept_disposition_does_not_change_adjudication():
    confirmed = _confirmed_issue()
    confirmed["human_disposition"] = "risk_accept"
    confirmed["acceptance_disposition"] = {"type": "risk_accept", "reason": "业务可接受"}
    assert acceptance_for_issue(confirmed)["state"] == "confirmed"

    pending = _base_issue()
    pending["human_disposition"] = "risk_accept"
    pending["acceptance_disposition"] = {"type": "risk_accept"}
    baseline = acceptance_for_issue(_base_issue())
    assert acceptance_for_issue(pending) == baseline


@pytest.mark.parametrize("source", ["user_config", "finding_baseline", "static_analysis"])
def test_suppression_is_not_adjudication(source):
    issue = _base_issue(
        validation_status="rejected",
        candidate_disposition="rejected_with_proof",
        rejection_source=source,
        evidence_pack={"proofs": [_reject_proof()]},
    )
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "suppression_not_adjudication"


def test_evidence_conflict_stays_pending():
    issue = _confirmed_issue()
    issue["evidence_pack"]["proofs"].append(_reject_proof())
    issue["evidence_conflict"] = True
    issue["validation_status"] = "needs_review"
    issue["candidate_disposition"] = "needs_review"
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "conflicting_programmatic_proofs"


def test_conditional_source_branch_not_proof_confirmed():
    issue = _confirmed_issue()
    issue["analysis_scope"] = "conditional_source_branch"
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"


def test_dynamic_witness_proof_without_live_attestation_stays_pending():
    proof = _confirm_proof(
        proof_kind="dynamic_witness_candidate_match",
        facts=[
            "candidate_object_matched",
            "candidate_site_matched",
            "defect_family_matched",
            "binary_identity_bound",
            "source_identity_bound",
            "replay_consistent",
        ],
    )
    issue = _confirmed_issue()
    issue["evidence_pack"]["proofs"] = [proof]
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "proof_not_replayable_from_report"


def test_business_conditional_from_consistent_serialized_assessment():
    issue = _protocol_issue()
    issue["protocol_assessment"] = _assessment_for(issue)
    issue = json.loads(json.dumps(issue))
    acceptance = acceptance_for_issue(issue, report_context_for({"schema_version": 2}))
    _assert_contract_shape(acceptance)
    assert acceptance["state"] == "business_conditional"
    assert acceptance["reason"] == "business_premises_unconfirmed"
    assert acceptance["build_context_id"] == "build-xyz"
    assert acceptance["resource_label"] == "pool-slot-0-gen-3"


def test_protocol_technical_gaps_are_pending_not_business():
    issue = _protocol_issue(needs_review_sub_state="protocol_pending")
    issue["protocol_assessment"] = _assessment_for(
        issue, state="pending", technical_gaps=["event:later_slot_access"]
    )
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "technical_gaps_open"


def test_business_conditional_with_open_technical_gaps_degrades():
    issue = _protocol_issue()
    issue["protocol_assessment"] = _assessment_for(
        issue, technical_gaps=["event:later_slot_access"]
    )
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "technical_gaps_open"


def test_denied_business_premise_is_not_conditional():
    issue = _protocol_issue()
    assessment = _assessment_for(issue)
    assessment["assumptions"][0]["status"] = "denied"
    issue["protocol_assessment"] = assessment
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "protocol_assessment_not_current"


@pytest.mark.parametrize(
    "tamper",
    [
        "missing_assessment",
        "binding_mismatch",
        "witness_not_current",
        "no_assumptions",
        "state_established",
        "blocking_negative_evidence",
    ],
)
def test_stale_or_incomplete_receipts_stay_pending(tamper):
    issue = _protocol_issue()
    assessment = _assessment_for(issue)
    if tamper == "missing_assessment":
        pass
    elif tamper == "binding_mismatch":
        issue["protocol_assessment"] = assessment
        issue["candidate_id"] = "unrelated-candidate"
    elif tamper == "witness_not_current":
        assessment["technical_witness_current"] = False
        issue["protocol_assessment"] = assessment
    elif tamper == "no_assumptions":
        assessment["assumptions"] = []
        issue["protocol_assessment"] = assessment
    elif tamper == "state_established":
        assessment["state"] = "established"
        issue["protocol_assessment"] = assessment
    elif tamper == "blocking_negative_evidence":
        issue["protocol_assessment"] = assessment
        issue["blocking_negative_evidence"] = True
    acceptance = acceptance_for_issue(issue)
    _assert_contract_shape(acceptance)
    assert acceptance["state"] == "pending"


def test_protocol_confirmed_requires_current_replay():
    issue = _protocol_issue(
        validation_status="validated",
        candidate_disposition="confirmed",
        decision_proof={
            "outcome": "confirm",
            "proof_kind": "checked_object_protocol_with_business_declarations",
        },
    )
    issue["protocol_assessment"] = _assessment_for(issue, state="established")
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "protocol_confirmation_requires_current_replay"


def test_heterogeneous_builds_same_line_are_independent():
    strong = _confirmed_issue(location="src/shared.c:100")
    weak = _base_issue(
        location="src/shared.c:100",
        validation_status="validated",
        candidate_disposition="confirmed",
        evidence_pack={"build_context_id": "build-other"},
    )
    strong_acceptance = acceptance_for_issue(strong)
    weak_acceptance = acceptance_for_issue(weak)
    assert strong_acceptance["state"] == "confirmed"
    assert strong_acceptance["build_context_id"] == "build-abc"
    assert weak_acceptance["state"] == "pending"
    assert weak_acceptance["build_context_id"] == "build-other"


def test_same_line_different_objects_do_not_share_assessment():
    first = _protocol_issue(location="src/pool.c:77")
    first["protocol_assessment"] = _assessment_for(first)
    second = _protocol_issue(
        location="src/pool.c:77",
        candidate_id="cand-protocol-2",
        resource_identity="pool-slot-1-gen-3",
    )
    # Reusing the first row's assessment for a different object must fail the
    # binding check instead of borrowing the conditional state.
    second["protocol_assessment"] = json.loads(json.dumps(first["protocol_assessment"]))
    assert acceptance_for_issue(first)["state"] == "business_conditional"
    acceptance = acceptance_for_issue(second)
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "protocol_assessment_not_current"


@pytest.mark.parametrize("schema_version", [0, 1, "1", "legacy", None])
def test_legacy_or_unknown_reports_stay_pending(schema_version):
    issue = _confirmed_issue()
    acceptance = acceptance_for_issue(issue, {"schema_version": schema_version})
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "legacy_report_schema"
    # Display fields stay populated; only adjudication is held back.
    assert acceptance["resource_label"] == "obj-123"


def test_current_schema_report_adjudicates():
    issue = _confirmed_issue()
    for context in (
        {"schema_version": 2},
        {"schema_version": "2"},
        report_context_for({"schema_version": 2}),
        None,
    ):
        assert acceptance_for_issue(issue, context)["state"] == "confirmed"


def test_missing_dynamic_trigger_never_promotes():
    issue = _base_issue(
        validation_status="validated",
        candidate_disposition="confirmed",
        confidence=0.95,
        final_score=0.91,
    )
    assert "dynamic_reproduction" not in issue
    acceptance = acceptance_for_issue(issue)
    assert acceptance["state"] == "pending"
    assert acceptance["reproduction"] == {"status": "not_measured", "summary": None}


def test_reproduction_projection_never_changes_state():
    issue = _base_issue()
    for outcome, status in [
        ("witness_observed", "reproduced"),
        ("not_reproduced", "not_reproduced"),
        ("inconclusive", "inconclusive"),
        ("engine_failed", "failed"),
        ("unsupported", "inconclusive"),
        ("cancelled", "inconclusive"),
        ("surprising", "unknown"),
    ]:
        issue["dynamic_reproduction"] = {
            "provider_outcome": outcome,
            "provider": "asan@18.1",
            "provider_detail": "detail text",
        }
        acceptance = acceptance_for_issue(issue)
        assert acceptance["reproduction"]["status"] == status
        assert acceptance["state"] == "pending"
    issue["dynamic_reproduction"] = {"provider_outcome": "witness_observed"}
    acceptance = acceptance_for_issue(
        _confirmed_issue(dynamic_reproduction=issue["dynamic_reproduction"])
    )
    # A reproduced witness still does not replace the programmatic proof path.
    assert acceptance["state"] == "confirmed"
    assert acceptance["reproduction"]["status"] == "reproduced"


def test_display_fields_fall_back_and_stay_bounded():
    issue = _base_issue(
        trigger_condition="x" * 500,
        evidence_pack={
            "resource_signature": "sig:fallback",
            "build_context_id": "pack-build",
        },
    )
    acceptance = acceptance_for_issue(issue)
    assert acceptance["resource_label"] == "sig:fallback"
    assert acceptance["build_context_id"] == "pack-build"
    assert len(acceptance["trigger_summary"]) == 240
    assert acceptance["trigger_summary"].endswith("…")

    empty = _base_issue()
    acceptance = acceptance_for_issue(empty)
    assert acceptance["resource_label"] is None
    assert acceptance["build_context_id"] is None
    assert acceptance["trigger_summary"] is None
    assert acceptance["sources_count"] is None


def test_sources_count_dedupes_real_sources():
    assert acceptance_for_issue(_base_issue(evidence_sources=["a", "a", "b"]))["sources_count"] == 2
    assert acceptance_for_issue(_base_issue(evidence_sources="svf"))["sources_count"] == 1
    assert acceptance_for_issue(_base_issue(evidence_sources=[]))["sources_count"] is None
    assert acceptance_for_issue(_base_issue())["sources_count"] is None


def test_unknown_and_invalid_issue_shapes_stay_pending():
    for payload in ({}, None, "not-a-dict", ["x"]):
        acceptance = acceptance_for_issue(payload)
        _assert_contract_shape(acceptance)
        assert acceptance["state"] == "pending"
    acceptance = acceptance_for_issue({"function": "orphan"})
    assert acceptance["state"] == "pending"
    assert acceptance["reason"] == "validation_not_completed"


def _realistic_report():
    report = FinalReport(
        entry_function="main",
        overall_verdict="issues_found",
        issues=[Issue.from_dict(_confirmed_issue())],
        completeness="degraded",
    )
    report.metadata["build_coverage"] = {
        "status": "partial",
        "instances": 4,
        "sources": 3,
        "extraction_complete": False,
        "scan_complete": False,
        "reasons": ["incomplete_compilation_instances", "link_targets_unverified"],
        "failed_instances": ["build-1", "build-2"],
    }
    report.candidate_terminal_states = [
        {"candidate_disposition": "deferred_budget", "candidate_uid": "u1"},
        {"candidate_disposition": "engine_failed", "candidate_uid": "u1"},
        {"candidate_disposition": "interrupted", "occurrence_uid": "o2"},
        {"candidate_disposition": "confirmed", "candidate_uid": "u9"},
    ]
    report.needs_review_governance = {"validation_not_completed_count": 2}
    return json.loads(json.dumps(report.to_dict()))


def test_coverage_from_real_report_shape():
    report = _realistic_report()
    report["metadata"]["audit_observations"] = [
        {"candidate_disposition": "deferred_budget", "candidate_uid": "u3"}
    ]
    coverage = acceptance_coverage(report)
    json.dumps(coverage)
    assert coverage["completeness"] == "degraded"
    build = coverage["build_coverage"]
    assert build["status"] == "partial"
    assert build["extraction_complete"] is False
    assert build["scan_complete"] is False
    assert build["instances"] == 4
    assert build["sources"] == 3
    kinds = [gap["kind"] for gap in coverage["gaps"]]
    assert "scan_completeness" in kinds
    assert "incomplete_compilation_instances" in kinds
    assert "link_targets_unverified" in kinds
    assert "validation_not_completed" in kinds
    instance_gap = next(
        g for g in coverage["gaps"] if g["kind"] == "incomplete_compilation_instances"
    )
    assert instance_gap["detail"] == "count=2"
    assert coverage["deferred_count"] == 3
    issue = report["issues"][0]
    assert acceptance_for_issue(issue, report_context_for(report))["state"] == "confirmed"


def test_coverage_of_complete_report_has_no_gaps():
    report = _realistic_report()
    report["completeness"] = "complete"
    report["metadata"]["build_coverage"] = {
        "status": "indexed",
        "extraction_complete": True,
        "scan_complete": False,
        "reasons": [],
    }
    report["candidate_terminal_states"] = []
    report["needs_review_governance"] = {}
    coverage = acceptance_coverage(report)
    assert coverage["completeness"] == "complete"
    assert coverage["build_coverage"]["extraction_complete"] is True
    assert coverage["gaps"] == []
    assert coverage["deferred_count"] == 0


def test_coverage_partial_completeness_is_a_gap():
    report = _realistic_report()
    report["completeness"] = "partial"
    report["metadata"]["build_coverage"] = {"status": "indexed", "reasons": []}
    report["candidate_terminal_states"] = []
    report["needs_review_governance"] = {}
    coverage = acceptance_coverage(report)
    assert coverage["completeness"] == "partial"
    assert coverage["gaps"] == [{"kind": "scan_completeness", "detail": "partial"}]


def test_coverage_fallback_without_complete_report():
    for report in ({}, None, {"issues": []}, {"issues": [], "issues_by_severity": {}}):
        coverage = acceptance_coverage(report)
        json.dumps(coverage)
        assert coverage["completeness"] is None
        assert coverage["build_coverage"] is None
        assert coverage["gaps"] == []
        assert coverage["deferred_count"] is None


def test_coverage_gap_truncation_keeps_marker():
    report = {
        "completeness": "complete",
        "metadata": {
            "build_coverage": {
                "status": "partial",
                "reasons": [f"gap_{index}" for index in range(30)],
            }
        },
    }
    coverage = acceptance_coverage(report)
    assert len(coverage["gaps"]) == 16
    assert coverage["gaps"][-1]["kind"] == "additional_gaps_omitted"
    assert coverage["build_coverage"]["reasons"] == [f"gap_{index}" for index in range(8)]


def test_instance_coverage_view_never_projects_scan_complete():
    """A pinned per-entry view cannot be read as scan coverage."""

    report = _realistic_report()
    report["metadata"]["build_coverage"] = {
        "view": "instance",
        "instances": 2,
        "pinned_build_context_id": "ctx-b",
        "scan_complete": True,  # a producer bug must not survive projection
        "extraction_complete": True,
        "reasons": [],
    }
    coverage = acceptance_coverage(report)
    build = coverage["build_coverage"]
    assert build["view"] == "instance"
    assert build["pinned_build_context_id"] == "ctx-b"
    assert build["instances"] == 2
    assert build["scan_complete"] is False


def test_scan_coverage_view_projects_unchanged():
    report = _realistic_report()
    report["metadata"]["build_coverage"] = {
        "view": "scan",
        "instances": 3,
        "scan_complete": False,
        "extraction_complete": False,
        "reasons": ["incomplete_compilation_instances"],
    }
    build = acceptance_coverage(report)["build_coverage"]
    assert build["view"] == "scan"
    assert build["instances"] == 3
    assert build["scan_complete"] is False
    assert "pinned_build_context_id" not in build
