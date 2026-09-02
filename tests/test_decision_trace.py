import hashlib
import json
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

import pytest

from zscope.cli.explain import main as explain_main
from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.core.validation.audit_eligibility import (
    has_exact_v4_producer_occurrence_binding as real_v4_producer_occurrence_binding,
)
from zscope.core.validation.claim_verifier import EvidenceClaimRequest, EvidenceClaimVerifier
from zscope.core.validation.proof_kernel import (
    ProofKernelEngine,
    build_proof_clause,
    build_proof_obligation,
)
import zscope.orchestration.decision_trace as decision_trace_module
from zscope.orchestration.decision_trace import (
    DecisionTraceError,
    DecisionTraceStore,
    audit_terminal_reason_codes,
    load_decision_trace,
    terminal_reason_codes,
    verify_decision_trace,
    verify_evidence_object,
    verify_coverage_trace,
    verify_model_event,
)
from zscope.reporting.assembler import ReportAssembler

from scripts.reverify_v3_trace import reverify_trace_root
from scripts.p2_proof_corpus import build_corpus


@pytest.fixture(autouse=True)
def _test_producer_occurrence_verifier(monkeypatch) -> None:
    monkeypatch.setattr(
        decision_trace_module,
        "_has_exact_v4_producer_occurrence_binding",
        lambda item: item.get("_test_exact_producer_occurrence_binding") is True,
    )


@lru_cache(maxsize=3)
def _frozen_authority_bundle(disposition: str) -> dict:
    if disposition == "needs_review":
        authority = TerminalAuthorityEvaluator().evaluate({}, operation="live").to_dict()
        return {
            "proof_kernel_terminal_authority_decision": authority,
            "terminal_authority_decision": authority,
        }

    case = build_corpus()["cases"][0]
    proof_ir = case["program_proof_ir"]
    original_obligation = case["proof_obligation"]
    if disposition == "confirmed":
        obligation = original_obligation
    elif disposition == "rejected_with_proof":
        original_clause = original_obligation["confirmation_clauses"][0]
        counterproof = build_proof_clause(
            role="counterproof",
            provider_family=original_clause["provider_family"],
            predicate_id=original_clause["predicate_id"],
            fact_kind=original_clause["fact_kind"],
            quantifier=original_clause["quantifier"],
            expected_value=original_clause["expected_value"],
            parameters=original_clause["parameters"],
        )
        obligation = build_proof_obligation(
            validation_cluster_uid="VAL_DECISION_TRACE_COUNTERPROOF",
            defect_family="neutral_decision_trace_counterproof",
            subject_uid="SUBJECT_DECISION_TRACE_COUNTERPROOF",
            decision_region_uid="REGION_DECISION_TRACE_COUNTERPROOF",
            confirmation_clauses=(),
            counterproof_clauses=(counterproof,),
            dependency_hashes=proof_ir["dependency_hashes"],
        )
    else:  # pragma: no cover - test helper contract
        raise ValueError(disposition)
    evaluation = ProofKernelEngine().evaluate(proof_ir=proof_ir, obligation=obligation)
    carrier = {}
    evaluation.apply_to_issue(carrier)
    selected_action_uids = [str(value["action_uid"]) for value in evaluation.actions]
    carrier.update(
        {
            "proof_kernel_input": evaluation.authority_inputs()["proof_kernel_input"],
            "proof_kernel_live_selected_action_uids": selected_action_uids,
            "proof_kernel_checker_results": [dict(value) for value in evaluation.check_results],
            "proof_kernel_artifact_refs": list(evaluation.artifact_refs),
            "proof_kernel_checker_result_refs": list(evaluation.checker_result_refs),
            "proof_kernel_root_manifest_sha256": evaluation.root_manifest_sha256,
        }
    )
    authority = TerminalAuthorityEvaluator().evaluate(carrier, operation="live").to_dict()
    assert authority["disposition"] == disposition
    carrier["proof_kernel_terminal_authority_decision"] = authority
    carrier["terminal_authority_decision"] = authority
    carrier["proof_kernel_producer_binding_sha256"] = "a" * 64
    carrier["proof_kernel_occurrence_binding_sha256"] = "b" * 64
    carrier["_test_exact_producer_occurrence_binding"] = True
    return carrier


def _authority_bundle(disposition: str) -> dict:
    return deepcopy(_frozen_authority_bundle(disposition))


def _record_live_transition(
    store: DecisionTraceStore,
    issue: dict,
    *,
    level: str = "V1",
) -> None:
    event, created = store.record_terminal_transition(
        issue,
        level=level,
        authority=issue["terminal_authority_decision"],
    )
    assert created is True
    assert issue["terminal_transition_event_uid"] == event["event_uid"]


def _legacy_authority(disposition: str) -> dict:
    return {
        "schema_version": "zscope.terminal-authority-decision.v3",
        "terminal": True,
        "disposition": disposition,
        "reason_code": {
            "confirmed": "CONFIRMED_DETERMINISTIC_PROOF",
            "rejected_with_proof": "REJECTED_DETERMINISTIC_COUNTERPROOF",
            "needs_review": "NEEDS_REVIEW_OPEN_CLAUSES",
        }[disposition],
        "authority": "zscope.proof-checker",
        "next_action": "",
        "conflict_resolution": None,
    }


def _tool_record(ref="TOOLFACT_1"):
    payload = {
        "success": True,
        "data": {
            "query": "wire_len",
            "value_range_proved": True,
            "analysis_complete": True,
            "file_path": "src/demo.c",
        },
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "evidence_ref": ref,
        "tool_name": "get_data_flow",
        "arguments": {"query": "wire_len"},
        "arguments_hash": "a" * 64,
        "result_hash": digest,
        "result_payload": payload,
        "dependency_code_hash": digest,
        "location": {"file": "src/demo.c", "function": "sink", "start_line": 10},
    }


def test_cluster_trace_is_ordered_and_hash_chained_under_concurrency(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_1")

    def append(index: int) -> None:
        store.append_event(
            "VAL_1",
            stage="provider",
            actor="test_provider",
            reason_code="FACT_UNKNOWN",
            details={"index": index},
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append, range(100)))

    trace = store.trace("VAL_1")
    assert [event["sequence"] for event in trace["events"]] == list(range(1, 101))
    assert verify_decision_trace(trace) == (True, "ok")
    loaded = load_decision_trace(next((tmp_path / "decision_traces").glob("*.json")))
    assert loaded["trace_root_sha256"] == trace["trace_root_sha256"]


def test_terminal_event_freezes_authoritative_security_spec_without_second_terminal(
    tmp_path: Path,
) -> None:
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_P3")
    store.update_identity(
        {
            "security_spec_mode": "authoritative",
            "security_spec_artifact_refs": ["sha256:" + "a" * 64],
            "security_spec_decision": {
                "active_product_effect": "semantic_input",
                "compiled_spec_count": 3,
                "reason_code": "security_spec_authoritative",
            },
        }
    )
    issue = {
        "validation_cluster_uid": "VAL_P3",
        "candidate_disposition": "needs_review",
        **_authority_bundle("needs_review"),
    }
    store.finalize_issue(issue, view_memberships=("with_needs_review",))
    store.finalize_issue(issue, view_memberships=("with_needs_review",))

    trace = store.trace("VAL_P3")
    terminal = [value for value in trace["events"] if value["stage"] == "policy"]
    assert len(terminal) == 1
    assert terminal[0]["details"]["security_spec_mode"] == "authoritative"
    assert terminal[0]["details"]["security_spec_decision"] == {
        "active_product_effect": "semantic_input",
        "compiled_spec_count": 3,
        "reason_code": "security_spec_authoritative",
    }


def test_terminal_event_attaches_active_hunter_refs_without_second_terminal(
    tmp_path: Path,
) -> None:
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_P4")
    store.update_identity(
        {
            "hypothesis_hunter_mode": "active",
            "hypothesis_hunter_artifact_refs": ["sha256:" + "b" * 64],
            "hypothesis_hunter_decision": {
                "active_product_effect": "candidate_registration_only",
                "reason_code": "hypothesis_hunter_candidate_registration_only",
            },
        }
    )
    issue = {
        "validation_cluster_uid": "VAL_P4",
        "candidate_disposition": "needs_review",
        **_authority_bundle("needs_review"),
    }
    store.finalize_issue(issue, view_memberships=("with_needs_review",))
    store.finalize_issue(issue, view_memberships=("with_needs_review",))

    trace = store.trace("VAL_P4")
    terminal = [value for value in trace["events"] if value["stage"] == "policy"]
    assert len(terminal) == 1
    assert terminal[0]["details"]["hypothesis_hunter_mode"] == "active"
    assert terminal[0]["details"]["hypothesis_hunter_artifact_refs"] == ["sha256:" + "b" * 64]
    assert terminal[0]["details"]["hypothesis_hunter_decision"] == {
        "active_product_effect": "candidate_registration_only",
        "reason_code": "hypothesis_hunter_candidate_registration_only",
    }


def test_trace_and_evidence_tampering_are_detected(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    evidence_ref = store.put_evidence(
        kind="decision_fact",
        payload={"fact_uid": "FACT_1", "value": True},
        producer="unit",
    )
    store.append_event(
        "VAL_1",
        stage="provider",
        actor="unit",
        reason_code="FACT_VERIFIED_TRUE",
        output_refs=(evidence_ref,),
    )
    trace = store.trace("VAL_1")
    trace["events"][0]["details"]["tampered"] = True
    assert verify_decision_trace(trace)[0] is False

    evidence_path = tmp_path / evidence_ref
    raw = json.loads(evidence_path.read_text(encoding="utf-8"))
    raw["payload"]["value"] = False
    evidence_path.write_text(json.dumps(raw), encoding="utf-8")
    assert verify_evidence_object(evidence_path)[0] is False


def test_trace_document_coverage_model_and_usage_tampering_are_detected(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    model_ref = store.put_model_event(
        call_identity="VAL_1:V1",
        stage="V1",
        validation_cluster_uid="VAL_1",
        structured_input={"candidate_uid": "CAND_1"},
        structured_output={"verdict": "uncertain"},
    )
    store.append_event(
        "VAL_1",
        stage="V1",
        actor="validator_agent",
        reason_code="V1_COMPLETED",
        output_refs=(model_ref,),
    )
    trace = store.trace("VAL_1")
    trace["candidate_uids"] = ["CAND_FORGED"]
    assert verify_decision_trace(trace)[0] is False

    model_path = tmp_path / model_ref
    model = json.loads(model_path.read_text(encoding="utf-8"))
    model["structured_output"]["verdict"] = "verified"
    model_path.write_text(json.dumps(model), encoding="utf-8")
    assert verify_model_event(model_path)[0] is False

    store.record_coverage_event(
        "AUDIT_1",
        reason_code="PRODUCER_NO_SIGNAL",
        producer="unit",
        details={"function": "sink"},
    )
    coverage_path = next((tmp_path / "coverage_traces").glob("*.json"))
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert verify_coverage_trace(coverage) == (True, "ok")
    coverage["events"][0]["details"]["function"] = "forged"
    assert verify_coverage_trace(coverage)[0] is False


def test_interrupted_v3_trace_can_be_reclassified_without_model_or_truth(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_REVERIFY")
    tool = _tool_record()
    claim = EvidenceClaimRequest.from_mapping(
        {
            "obligation_uid": "OBL_1",
            "fact_kind": "value_range",
            "predicate": "value_range_is_proved",
            "polarity": "supports",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_1",
            "arguments": {"query": "wire_len"},
            "cited_evidence_refs": [tool["evidence_ref"]],
        }
    )
    frozen = EvidenceClaimVerifier(allow_legacy_observation_claims=True).verify(
        claim,
        issue={
            "obligation_uid": "OBL_1",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_1",
        },
        tool_catalog={tool["evidence_ref"]: tool},
    )
    claim_ref = store.put_evidence(
        kind="model_evidence_claim",
        payload=claim.to_dict(),
        producer="validator_agent",
    )
    tool_ref = store.put_evidence(
        kind="validator_readonly_tool_result",
        payload=tool,
        producer="legacy_readonly_tool",
    )
    result_ref = store.put_evidence(
        kind="evidence_verification_certificate",
        payload=frozen.to_dict(),
        producer="legacy_claim_verifier",
    )
    store.append_event(
        "VAL_INTERRUPTED",
        stage="verifier",
        actor="legacy_claim_verifier",
        reason_code="FACT_VERIFIED_TRUE",
        input_refs=(claim_ref, tool_ref),
        output_refs=(result_ref,),
    )
    store.snapshot()

    result = reverify_trace_root(tmp_path)

    assert result["llm_calls"] == 0
    assert result["truth_inputs"] == 0
    assert result["terminal_trace_count"] == 0
    assert result["classification_counts"] == {"legacy_claim_preview_not_replayed": 1}
    assert result["passed"] is False


def test_strict_proof_trace_reverify_recomputes_from_frozen_ir(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_P2_REVERIFY")
    case = build_corpus()["cases"][0]
    refs = []
    for kind, key in (
        ("program_proof_ir", "program_proof_ir"),
        ("proof_obligation", "proof_obligation"),
        ("action", "evidence_action"),
        ("evidence_certificate", "evidence_certificate"),
        ("proof_check_result", "proof_check_result"),
    ):
        refs.append(
            store.put_evidence(
                kind=kind,
                payload=case[key],
                producer="zscope.proof-kernel.v4",
            )
        )
    store.append_event(
        "VAL_P2_REVERIFY",
        stage="verifier",
        actor="zscope.proof-checker",
        reason_code="FACT_VERIFIED_TRUE",
        output_refs=tuple(refs),
    )
    store.snapshot()

    result = reverify_trace_root(tmp_path)

    assert result["llm_calls"] == 0
    assert result["truth_inputs"] == 0
    assert result["classification_counts"] == {"valid_certificate": 1}
    assert result["passed"] is True


def test_terminal_and_view_events_preserve_root_alias_trace(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    confirmed = {
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        "proof_coverage": "complete",
        "decision_proof": {"coverage": "complete", "polarity": "positive"},
        **_authority_bundle("confirmed"),
        "finding_root_uid": "ROOT_1",
    }
    alias = {
        "candidate_uid": "CAND_2",
        "validation_cluster_uid": "VAL_2",
        "candidate_disposition": "deduplicated_alias",
        "finding_root_uid": "ROOT_1",
        "finding_root_primary_validation_cluster_uid": "VAL_1",
    }
    _record_live_transition(store, confirmed)
    store.finalize_issue(confirmed, view_memberships=("default", "with_needs_review"))
    store.finalize_issue(alias, view_memberships=("excluded",))

    assert confirmed["terminal_reason_codes"] == ["CONFIRMED_DETERMINISTIC_PROOF"]
    assert alias["terminal_reason_codes"] == ["ROOT_ALIAS", "VIEW_EXCLUDED"]
    primary_trace = store.trace("VAL_1")
    alias_trace = store.trace("VAL_2")
    assert primary_trace["view_memberships"] == ["default", "with_needs_review"]
    assert alias_trace["finding_root"]["role"] == "alias"
    assert (
        sum(
            event["event_uid"] == primary_trace["terminal_event_uid"]
            for event in primary_trace["events"]
        )
        == 1
    )


def test_terminal_transition_exact_replay_and_drift_fail_closed(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    issue = {
        "candidate_uid": "CAND_TRANSITION",
        "validation_cluster_uid": "VAL_TRANSITION",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        **_authority_bundle("confirmed"),
    }
    authority = issue["terminal_authority_decision"]

    event, created = store.record_terminal_transition(
        issue,
        level="V2",
        authority=authority,
    )
    replay, replay_created = store.record_terminal_transition(
        issue,
        level="V2",
        authority=authority,
    )

    assert created is True
    assert replay_created is False
    assert replay == event
    policy_ref = str(event["input_refs"][0])
    policy_evidence = json.loads((tmp_path / policy_ref).read_text(encoding="utf-8"))
    assert policy_evidence["payload"]["proof_kernel_producer_binding_sha256"] == "a" * 64
    assert policy_evidence["payload"]["proof_kernel_occurrence_binding_sha256"] == "b" * 64
    with pytest.raises(DecisionTraceError, match="replay_drift"):
        store.record_terminal_transition(issue, level="V3", authority=authority)

    tampered = deepcopy(issue)
    tampered["terminal_transition_event_hash"] = "f" * 64
    with pytest.raises(DecisionTraceError, match="replay_drift"):
        store.record_terminal_transition(tampered, level="V2", authority=authority)


def test_proof_terminal_requires_a_persisted_live_transition(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    issue = {
        "candidate_uid": "CAND_NO_TRANSITION",
        "validation_cluster_uid": "VAL_NO_TRANSITION",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        **_authority_bundle("confirmed"),
    }

    with pytest.raises(DecisionTraceError, match="no exact live transition"):
        store.finalize_issue(issue, view_memberships=("default", "with_needs_review"))


def test_self_sealed_terminal_cannot_acquire_a_live_trace_transition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        decision_trace_module,
        "_has_exact_v4_producer_occurrence_binding",
        real_v4_producer_occurrence_binding,
    )
    store = DecisionTraceStore(tmp_path)
    issue = {
        "candidate_uid": "CAND_UNBOUND_TRACE",
        "validation_cluster_uid": "VAL_UNBOUND_TRACE",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        **_authority_bundle("confirmed"),
    }
    issue.pop("_test_exact_producer_occurrence_binding", None)
    issue.pop("proof_kernel_producer_binding_sha256", None)
    issue.pop("proof_kernel_occurrence_binding_sha256", None)

    with pytest.raises(
        DecisionTraceError,
        match="terminal_transition_authority_revalidation_failed",
    ):
        store.record_terminal_transition(
            issue,
            level="V1",
            authority=issue["terminal_authority_decision"],
        )

    assert not issue.get("terminal_transition_event_uid")


def test_terminal_transition_persistence_failure_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = DecisionTraceStore(tmp_path)
    issue = {
        "candidate_uid": "CAND_WRITE_FAILURE",
        "validation_cluster_uid": "VAL_WRITE_FAILURE",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        **_authority_bundle("confirmed"),
    }
    monkeypatch.setattr(store, "_write", lambda *_args, **_kwargs: False)

    with pytest.raises(DecisionTraceError, match="decision_trace_write_failed"):
        store.record_terminal_transition(
            issue,
            level="V1",
            authority=issue["terminal_authority_decision"],
        )

    assert not issue.get("terminal_transition_event_uid")
    assert store.trace("VAL_WRITE_FAILURE").get("terminal_transition_event_uid") in {None, ""}


def test_proven_alias_preserves_the_original_immutable_transition(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    alias = {
        "candidate_uid": "CAND_PROVEN_ALIAS",
        "validation_cluster_uid": "VAL_PROVEN_ALIAS",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        **_authority_bundle("confirmed"),
    }
    _record_live_transition(store, alias, level="V3")
    transition_projection = {
        key: alias[key]
        for key in (
            "terminal_transition_event_uid",
            "terminal_transition_event_hash",
            "terminal_transition_authority_sha256",
            "terminal_transition_level",
            "terminal_transition_disposition",
        )
    }
    alias.update(
        {
            "candidate_disposition": "deduplicated_alias",
            "status": "deduplicated_alias",
            "validation_status": "deduplicated_alias",
            "finding_root_original_disposition": "confirmed",
            "finding_root_uid": "ROOT_PROVEN_ALIAS",
            "finding_root_primary_validation_cluster_uid": "VAL_PRIMARY",
        }
    )

    store.finalize_issue(alias, view_memberships=("excluded",))

    assert {key: alias[key] for key in transition_projection} == transition_projection
    trace = store.trace("VAL_PROVEN_ALIAS")
    policy_events = [event for event in trace["events"] if event["stage"] == "policy"]
    assert [event["event_uid"] for event in policy_events] == [
        transition_projection["terminal_transition_event_uid"]
    ]
    assert (
        trace["terminal_transition_event_hash"]
        == transition_projection["terminal_transition_event_hash"]
    )
    assert trace["terminal_disposition"] == "deduplicated_alias"
    assert {event["reason_code"] for event in trace["events"] if event["stage"] == "report"} == {
        "ROOT_ALIAS",
        "VIEW_EXCLUDED",
    }


def test_report_projection_attaches_trace_to_every_terminal_finding(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    outcomes = []
    for disposition, cluster in (
        ("confirmed", "VAL_CONFIRMED"),
        ("needs_review", "VAL_REVIEW"),
        ("rejected_with_proof", "VAL_REJECTED"),
    ):
        issue = {
            "id": cluster,
            "candidate_uid": f"CAND_{cluster}",
            "validation_cluster_uid": cluster,
            "candidate_disposition": disposition,
            "validation_status": (
                "validated"
                if disposition == "confirmed"
                else "rejected" if disposition == "rejected_with_proof" else "needs_review"
            ),
            **_authority_bundle(disposition),
        }
        if disposition in {"confirmed", "rejected_with_proof"}:
            issue["proof_coverage"] = "complete"
            issue["decision_proof"] = {
                "coverage": "complete",
                "polarity": "positive" if disposition == "confirmed" else "negative",
            }
            _record_live_transition(store, issue)
        outcomes.append(
            {
                "validation_cluster_uid": cluster,
                "candidate_uid": issue["candidate_uid"],
                "terminal_disposition": disposition,
                "issue": issue,
            }
        )
    state = {
        "candidate_lifecycle_snapshot": {"outcomes": outcomes},
        "finding_root_projection_enabled": False,
        "decision_trace_store": store,
    }

    projected = ReportAssembler._canonical_outcome_items(state)

    assert projected is not None
    assert len(projected) == 3
    assert all(item.get("decision_trace_ref") for item in projected)
    assert all(item.get("terminal_event_uid") for item in projected)
    assert state["decision_trace_manifest"]["trace_count"] == 3


def test_claim_verifier_rejects_forged_uid_cross_subject_and_wrong_arguments() -> None:
    record = _tool_record()
    catalog = {record["evidence_ref"]: record}
    base = {
        "obligation_uid": "OBL_1",
        "fact_kind": "value_range",
        "predicate": "value_range_is_proved",
        "polarity": "supports",
        "subject_uid": "wire_len",
        "decision_region_uid": "REGION_1",
        "arguments": {"query": "wire_len"},
        "cited_evidence_refs": [record["evidence_ref"]],
    }
    claim = EvidenceClaimRequest.from_mapping(base)
    result = EvidenceClaimVerifier().verify(
        claim,
        issue={
            "obligation_uid": "OBL_1",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_1",
        },
        tool_catalog=catalog,
    )
    assert result.status == "verified_true"
    assert result.verified_fact["verification_certificate"]["certificate_sha256"]

    nested_identity = EvidenceClaimVerifier().verify(
        claim,
        issue={
            "candidate_uid": "CAND_1",
            "security_obligation": {
                "obligation_uid": "OBL_1",
                "subject_uid": "wire_len",
                "decision_region_uid": "REGION_1",
            },
        },
        tool_catalog=catalog,
    )
    assert nested_identity.status == "verified_true"

    forged = dict(base, claim_uid="CLAIM_" + "0" * 32)
    try:
        EvidenceClaimRequest.from_mapping(forged)
    except ValueError as exc:
        assert "UID" in str(exc)
    else:  # pragma: no cover - hard security invariant
        raise AssertionError("forged claim UID was accepted")

    cross_subject = EvidenceClaimVerifier().verify(
        claim,
        issue={"obligation_uid": "OBL_1", "subject_uid": "other"},
        tool_catalog=catalog,
    )
    assert cross_subject.status == "unknown"
    wrong_arguments = EvidenceClaimRequest.from_mapping(
        {**base, "arguments": {"query": "fabricated summary"}}
    )
    result = EvidenceClaimVerifier().verify(
        wrong_arguments,
        issue={"obligation_uid": "OBL_1", "subject_uid": "wire_len"},
        tool_catalog=catalog,
    )
    assert result.status == "unknown"
    assert result.reason_code == "claim_arguments_not_replayed"


def test_claim_verifier_refutation_closes_fact_only_with_complete_counter_witness() -> None:
    record = _tool_record()
    payload = {
        "success": True,
        "data": {
            "query": "wire_len",
            "value_range_proved": False,
            "analysis_complete": True,
            "file_path": "src/demo.c",
        },
    }
    record["result_payload"] = payload
    record["result_hash"] = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    record["dependency_code_hash"] = record["result_hash"]
    base = {
        "obligation_uid": "OBL_1",
        "fact_kind": "value_range",
        "predicate": "value_range_is_proved",
        "subject_uid": "wire_len",
        "decision_region_uid": "REGION_1",
        "arguments": {"query": "wire_len"},
        "cited_evidence_refs": [record["evidence_ref"]],
    }
    verifier = EvidenceClaimVerifier()
    issue = {
        "obligation_uid": "OBL_1",
        "subject_uid": "wire_len",
        "decision_region_uid": "REGION_1",
    }

    refutation = verifier.verify(
        EvidenceClaimRequest.from_mapping({**base, "polarity": "refutes"}),
        issue=issue,
        tool_catalog={record["evidence_ref"]: record},
    )
    support = verifier.verify(
        EvidenceClaimRequest.from_mapping({**base, "polarity": "supports"}),
        issue=issue,
        tool_catalog={record["evidence_ref"]: record},
    )

    assert refutation.status == "verified_true"
    assert refutation.reason_code == "complete_structured_refutation_witness"
    assert refutation.verified_fact["satisfies_fact_kinds"] == ["value_range"]
    assert support.status == "verified_false"
    assert support.verified_fact is None


def test_terminal_authority_never_accepts_model_rejection_without_counterproof() -> None:
    decision = TerminalAuthorityEvaluator().evaluate(
        {"candidate_disposition": "needs_review", "missing_fact_kinds": ["lockset"]},
        model_result={"verdict": "rejected"},
    )
    assert decision.disposition == "needs_review"
    assert decision.reason_code == "NEEDS_REVIEW_MODEL_REJECT_NO_PROOF"
    unclosed_verified = TerminalAuthorityEvaluator().evaluate(
        {
            "candidate_disposition": "confirmed",
            "evidence_closure_state": {"complete": False, "missing_fact_kinds": ["lockset"]},
        },
        model_result={
            "schema_version": "zscope.validator-result.v3",
            "verdict": "verified",
        },
    )
    assert unclosed_verified.disposition == "needs_review"
    assert unclosed_verified.reason_code == "NEEDS_REVIEW_OPEN_CLAUSES"


def test_legacy_v3_terminal_is_audit_only_and_cannot_create_live_trace(tmp_path: Path) -> None:
    issue = {
        "candidate_uid": "CAND_LEGACY",
        "validation_cluster_uid": "VAL_LEGACY",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        "terminal_authority_decision": _legacy_authority("confirmed"),
    }

    assert terminal_reason_codes(issue) == ("NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",)
    assert audit_terminal_reason_codes(issue) == ("CONFIRMED_DETERMINISTIC_PROOF",)
    with pytest.raises(DecisionTraceError, match="TerminalAuthorityDecision v4"):
        DecisionTraceStore(tmp_path).finalize_issue(
            issue,
            view_memberships=("default", "with_needs_review"),
        )


def test_terminal_authority_ignores_legacy_conflict_proofs() -> None:
    evaluator = TerminalAuthorityEvaluator()
    base = {
        "subject_uid": "OBJ_1",
        "decision_region_uid": "REGION_1",
        "positive_decision_proof": {
            "coverage": "complete",
            "subject_uid": "OBJ_1",
            "decision_region_uid": "REGION_1",
        },
        "negative_decision_proof": {
            "coverage": "complete",
            "subject_uid": "OTHER",
            "decision_region_uid": "REGION_1",
        },
        "evidence_conflict": True,
    }
    resolved = evaluator.evaluate(base, has_executable_action=True)
    assert resolved.terminal is False
    assert resolved.disposition == "needs_review"
    assert resolved.next_action == "continue_validation"

    unresolved_issue = dict(base)
    unresolved_issue["negative_decision_proof"] = {
        "coverage": "complete",
        "subject_uid": "OBJ_1",
        "decision_region_uid": "REGION_1",
    }
    unresolved = evaluator.evaluate(unresolved_issue, has_executable_action=True)
    assert unresolved.terminal is False
    assert unresolved.next_action == "continue_validation"
    without_action = evaluator.evaluate(unresolved_issue, has_executable_action=False)
    assert without_action.disposition == "needs_review"
    assert without_action.reason_code == "NEEDS_REVIEW_OPEN_CLAUSES"


def test_explain_and_policy_replay_are_offline_and_hash_verified(tmp_path: Path, capsys) -> None:
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_1")
    issue = {
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "candidate_disposition": "confirmed",
        "validation_status": "validated",
        "proof_coverage": "complete",
        "decision_proof": {"coverage": "complete", "polarity": "positive"},
        **_authority_bundle("confirmed"),
    }
    store.bind_candidate("VAL_1", candidate_uids=("CAND_1",))
    _record_live_transition(store, issue)
    store.finalize_issue(issue, view_memberships=("default", "with_needs_review"))
    manifest = store.snapshot()
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "issues": [issue],
                "run_manifest": {"decision_trace": manifest},
            }
        ),
        encoding="utf-8",
    )

    assert (
        explain_main(["--report", str(report_path), "--cluster", "VAL_1", "--format", "json"]) == 0
    )
    explanation = json.loads(capsys.readouterr().out)
    assert explanation["terminal_disposition"] == "confirmed"
    assert explanation["view_memberships"] == ["default", "with_needs_review"]

    assert (
        explain_main(
            [
                "--report",
                str(report_path),
                "--candidate",
                "CAND_1",
                "--mode",
                "policy-replay",
            ]
        )
        == 0
    )
    replay = json.loads(capsys.readouterr().out)
    assert replay["matches_frozen_terminal"] is True
    assert replay["policy_issue"] == "none"


def test_no_candidate_audit_unit_has_coverage_trace(tmp_path: Path) -> None:
    store = DecisionTraceStore(tmp_path)
    store.record_coverage_event(
        "AUDIT_1",
        reason_code="PRODUCER_NO_SIGNAL",
        producer="unit_producer",
        details={"family": "resource_protocol"},
    )
    manifest = store.snapshot()
    assert manifest["coverage_trace_count"] == 1
    coverage_path = tmp_path / manifest["coverage_traces"]["AUDIT_1"]["path"]
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert coverage["events"][0]["reason_code"] == "PRODUCER_NO_SIGNAL"


def test_usage_sidecar_is_hash_bound_and_token_conserved(tmp_path: Path, capsys) -> None:
    usage_path = tmp_path / "llm_usage_events.jsonl"
    usage_event = {
        "call_id": "CALL_1",
        "total_tokens": 30,
        "attribution": {"validation_cluster_uid": "VAL_1"},
    }
    usage_path.write_text(json.dumps(usage_event) + "\n", encoding="utf-8")

    class UsageLedger:
        def snapshot(self, include_events=False):
            return {
                "schema_version": "zscope.llm-usage-ledger.v1",
                "usage_events_path": str(usage_path),
                "events": [usage_event] if include_events else [],
                "usage_attribution": {"provider_usage_coverage": 1.0},
            }

    store = DecisionTraceStore(tmp_path, usage_ledger=UsageLedger())
    store.append_event(
        "VAL_1",
        stage="V1",
        actor="proof_engine",
        reason_code="V1_COMPLETED",
        call_ids=("CALL_1",),
        token_delta=30,
    )
    issue = {
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "candidate_disposition": "needs_review",
        **_authority_bundle("needs_review"),
    }
    store.finalize_issue(issue, view_memberships=("with_needs_review",))
    manifest = store.snapshot()
    assert manifest["llm_usage_events"]["conservation_valid"] is True
    assert manifest["llm_usage_events"]["trace_token_total"] == 30

    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps({"observations": [issue], "run_manifest": {"decision_trace": manifest}}),
        encoding="utf-8",
    )
    assert explain_main(["--report", str(report_path), "--cluster", "VAL_1"]) == 0
    capsys.readouterr()

    usage_path.write_text(json.dumps({**usage_event, "total_tokens": 31}) + "\n", encoding="utf-8")
    assert explain_main(["--report", str(report_path), "--cluster", "VAL_1"]) == 2
    assert "usage sidecar hash mismatch" in capsys.readouterr().err


def test_audit_unit_usage_is_bound_to_coverage_trace(tmp_path: Path) -> None:
    usage_path = tmp_path / "llm_usage_events.jsonl"
    usage_event = {
        "call_id": "CALL_DISCOVERY",
        "total_tokens": 44,
        "agent": "hypothesis_hunter",
        "stage": "active_discovery",
        "audit_unit_uid": "AUDIT_1",
        "attribution": {
            "agent": "hypothesis_hunter",
            "stage": "active_discovery",
            "audit_unit_uid": "AUDIT_1",
        },
    }
    usage_path.write_text(json.dumps(usage_event) + "\n", encoding="utf-8")

    class UsageLedger:
        def snapshot(self, include_events=False):
            return {
                "schema_version": "zscope.scan-token-usage.v1",
                "usage_events_path": str(usage_path),
                "events": [usage_event] if include_events else [],
            }

    store = DecisionTraceStore(tmp_path, usage_ledger=UsageLedger())
    manifest = store.snapshot()

    assert manifest["llm_usage_events"]["conservation_valid"] is True
    assert manifest["coverage_trace_count"] == 1
    coverage_path = tmp_path / manifest["coverage_traces"]["AUDIT_1"]["path"]
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    assert coverage["events"][0]["call_ids"] == ["CALL_DISCOVERY"]
    assert coverage["events"][0]["token_delta"] == 44


def test_nested_cluster_usage_is_bound_to_decision_trace(tmp_path: Path) -> None:
    usage_path = tmp_path / "llm_usage_events.jsonl"
    usage_event = {
        "call_id": "CALL_NESTED_MODEL",
        "total_tokens": 71,
        "agent": "security_spec_miner",
        "stage": "security_spec_mining",
        "validation_cluster_uid": "VAL_NESTED",
        "attribution": {
            "agent": "security_spec_miner",
            "stage": "security_spec_mining",
            "validation_cluster_uid": "VAL_NESTED",
            "call_kind": "v3_tool_dependency",
        },
    }
    usage_path.write_text(json.dumps(usage_event) + "\n", encoding="utf-8")

    class UsageLedger:
        def snapshot(self, include_events=False):
            return {
                "schema_version": "zscope.scan-token-usage.v1",
                "usage_events_path": str(usage_path),
                "events": [usage_event] if include_events else [],
            }

    store = DecisionTraceStore(tmp_path, usage_ledger=UsageLedger())
    store.bind_candidate("VAL_NESTED", candidate_uids=("CAND_NESTED",))
    manifest = store.snapshot()

    assert manifest["llm_usage_events"]["conservation_valid"] is True
    assert manifest["llm_usage_events"]["trace_token_total"] == 71
    trace_path = tmp_path / manifest["traces"]["VAL_NESTED"]["path"]
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    binding = trace["events"][-1]
    assert binding["reason_code"] == "LLM_USAGE_BOUND"
    assert binding["call_ids"] == ["CALL_NESTED_MODEL"]
    assert binding["details"]["call_kind"] == "v3_tool_dependency"


def test_decision_trace_io_failures_expose_only_fixed_classes(monkeypatch, tmp_path) -> None:
    secret = "PRIVATE_SOURCE_AND_EXPECTED_ANSWER_MUST_NOT_LEAK"
    store = DecisionTraceStore(tmp_path, scan_uid="SCAN_FAILURE_SAFE")

    def fail_write(*_args, **_kwargs):
        raise OSError(secret)

    with monkeypatch.context() as context:
        context.setattr(
            "zscope.orchestration.decision_trace._atomic_write_json",
            fail_write,
        )
        store._write(tmp_path / "trace.json", {})

    manifest = store.snapshot()
    assert manifest["errors"] == ["decision_trace_write_failed"]
    assert manifest["error_counts"] == {"decision_trace_write_failed": 1}
    assert secret not in json.dumps(manifest, ensure_ascii=False, sort_keys=True)

    def fail_read(*_args, **_kwargs):
        raise OSError(secret)

    with monkeypatch.context() as context:
        context.setattr(Path, "read_text", fail_read)
        with pytest.raises(DecisionTraceError) as raised:
            load_decision_trace(tmp_path / "trace.json")
        evidence_result = verify_evidence_object(tmp_path / "evidence.json")
        model_result = verify_model_event(tmp_path / "model.json")

    serialized = json.dumps(
        {
            "load": str(raised.value),
            "evidence": evidence_result,
            "model": model_result,
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    assert secret not in serialized
    assert str(raised.value) == "decision_trace_load_failed"
    assert evidence_result == (False, "evidence_object_load_failed")
    assert model_result == (False, "model_event_load_failed")
