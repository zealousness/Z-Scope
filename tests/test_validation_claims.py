from __future__ import annotations

from zscope.core.validation.claims import replay_counter_claim, replay_positive_claim
from zscope.core.validation.pipeline import ValidationPipeline
from zscope.rules.validation_obligations import attach_obligation_binding


class _Config:
    @staticmethod
    def get_user_feedback(_issue):
        return None


def _issue() -> dict:
    issue = {
        "id": "CLAIM_1",
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "rule": "clang_cfg_free_derived_pointer_alias",
        "category": "invalid_free",
        "defect_class": "invalid_free",
        "build_context_id": "build-current",
        "source": "base + 4",
        "sink": "free(base + 4)",
        "decision_context_version": "zscope.decision-context.v3.3",
        "decision_fact_coverage": "complete",
        "missing_fact_kinds": [],
        "decision_fact_slice": {
            "fact_uids": ["FACT_SOURCE", "FACT_SINK"],
            "edge_uids": [],
            "dependency_code_hashes": ["SNAP_CURRENT"],
            "coverage": "complete",
            "missing_fact_kinds": [],
            "facts": [
                {"fact_uid": "FACT_SOURCE", "fact_kind": "source"},
                {"fact_uid": "FACT_SINK", "fact_kind": "sink"},
            ],
        },
        "validator_evidence_ref_catalog": {
            "FACT_SOURCE": {"kind": "decision_fact", "summary": "base pointer"},
            "FACT_SINK": {"kind": "decision_fact", "summary": "derived free"},
            "SNAP_CURRENT": {"kind": "code_hash", "summary": ""},
        },
    }
    attach_obligation_binding(issue)
    return issue


def _verified() -> dict:
    return {
        "schema_version": "zscope.validator-result.v3",
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "pass": "initial",
        "verdict": "verified",
        "reasoning": "派生指针被直接释放。",
        "positive_evidence": ["FACT_SOURCE 与 FACT_SINK 证明同一局部路径。"],
        "negative_evidence": [],
        "evidence_refs": ["FACT_SOURCE", "FACT_SINK", "SNAP_CURRENT"],
        "blocking_negative_evidence": False,
        "missing_fact_request": None,
        "stop_reason": "decision_complete",
    }


def _rejected() -> dict:
    return {
        **_verified(),
        "verdict": "rejected",
        "positive_evidence": [],
        "negative_evidence": ["The cited current facts prove a distinct object identity."],
    }


def test_positive_claim_replay_accepts_current_cited_fact_slice() -> None:
    replay = replay_positive_claim(_issue(), _verified())

    assert replay.accepted is True
    assert replay.failures == ()
    assert replay.replayed_roles == ("path", "sink", "source")


def test_verified_claim_promotes_even_when_ranking_score_is_low() -> None:
    issue = _issue()
    pipeline = ValidationPipeline(_Config())

    outcome = pipeline.apply_validator_result(
        issue,
        _verified(),
        verdict="verified",
        score_data={
            "final_score": 0.1,
            "path_completeness": 0.1,
            "contract_consistency": 0.1,
            "validation_confidence": 0.1,
        },
    )

    assert outcome.report_bucket == "issues"
    assert issue["candidate_disposition"] == "confirmed"
    assert issue["promotion_reason"] == "validator_positive_claim_replayed"
    assert issue["score_role"] == "ranking_only"


def test_unknown_citation_fails_closed_to_needs_review() -> None:
    issue = _issue()
    result = _verified()
    result["evidence_refs"] = ["FACT_NOT_IN_CURRENT_SLICE"]

    outcome = ValidationPipeline(_Config()).apply_validator_result(
        issue,
        result,
        verdict="verified",
        score_data={"final_score": 1.0},
    )

    assert outcome.report_bucket == "observations"
    assert issue["candidate_disposition"] == "needs_review"
    assert "unknown_evidence_ref" in ":".join(issue["validator_claim_replay"]["failures"])


def test_claim_replay_rejects_wrong_candidate_identity() -> None:
    issue = _issue()
    result = _verified()
    result["candidate_uid"] = "CAND_FROM_ANOTHER_BUILD"

    replay = replay_positive_claim(issue, result)

    assert replay.accepted is False
    assert "candidate_uid_mismatch" in replay.failures


def test_claim_replay_requires_explicit_build_context() -> None:
    issue = _issue()
    issue.pop("build_context_id")

    replay = replay_positive_claim(issue, _verified())

    assert replay.accepted is False
    assert "build_context_missing" in replay.failures


def test_weak_local_detector_requires_rule_specific_positive_facts() -> None:
    issue = _issue()
    issue["rule"] = "clang_cfg_pointer_may_be_uninitialized_before_use"
    issue["rule_id"] = "clang_cfg_pointer_may_be_uninitialized_before_use"
    issue["defect_class"] = "uninitialized_pointer"
    attach_obligation_binding(issue)

    replay = replay_positive_claim(issue, _verified())

    assert replay.accepted is False
    assert any(
        failure.startswith("rule_positive_facts_not_replayable:") for failure in replay.failures
    )


def test_counter_claim_without_deterministic_counterfact_fails_replay() -> None:
    replay = replay_counter_claim(_issue(), _rejected())

    assert replay.accepted is False
    assert "deterministic_counterfact_not_replayed" in replay.failures


def test_counter_claim_accepts_current_deterministic_counterfact() -> None:
    issue = _issue()
    issue["deterministic_proofs"] = [
        {
            "outcome": "reject",
            "proof_kind": "distinct_object_identity",
            "producer_engine": "decision_fact_graph_v1",
            "fact_ids": ["FACT_SOURCE", "FACT_SINK"],
            "code_hash": "SNAP_CURRENT",
            "facts": ["distinct_object_identity"],
            "completeness": "complete",
            "summary": "The released object is not the reported owner.",
        }
    ]

    replay = replay_counter_claim(issue, _rejected())

    assert replay.accepted is True
    assert replay.replayed_roles == ("distinct_object_identity",)
