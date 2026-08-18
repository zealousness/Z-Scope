from __future__ import annotations

from zscope.core.validation.pipeline import ValidationPipeline, preserve_issue_location


class _Memory:
    def __init__(self) -> None:
        self.baseline = None
        self.false_positive = False

    def is_false_positive(self, *_args):
        return self.false_positive

    def get_finding_baseline_for_issue(self, _issue, _dedup_key):
        return self.baseline

    def get_finding_baseline(self, _dedup_key):
        return self.baseline


def _score(value: float = 1.0) -> dict[str, float]:
    return {
        "rule_confidence": value,
        "path_completeness": value,
        "contract_consistency": value,
        "validation_confidence": value,
        "history_feedback": value,
        "final_score": value,
    }


def test_historical_false_positive_is_advisory_and_does_not_mutate_disposition() -> None:
    memory = _Memory()
    memory.false_positive = True
    issue = {"id": "ISSUE", "function": "entry", "location": "src/a.c:7"}

    decision = ValidationPipeline(memory).apply_pre_validation_feedback(issue, "entry")

    assert decision is not None
    assert decision.action == "suppress"
    assert decision.rejection_source == "user_config"
    assert "candidate_disposition" not in issue
    assert "validation_status" not in issue


def test_historical_baseline_is_advisory_and_does_not_close_candidate() -> None:
    memory = _Memory()
    memory.baseline = {"status": "false_positive", "match_strategy": "legacy"}
    issue = {"id": "ISSUE", "dedup_key": "key"}

    decision = ValidationPipeline(memory).apply_pre_validation_feedback(issue, "entry")

    assert decision is not None
    assert decision.rejection_source == "finding_baseline"
    assert decision.baseline == memory.baseline
    assert "finding_kind" not in issue


def test_static_validation_flag_is_advisory_only() -> None:
    issue = {"id": "ISSUE", "validation_required": False}

    decision = ValidationPipeline(_Memory()).apply_pre_validation_feedback(issue, "entry")

    assert decision is not None
    assert decision.rejection_source == "static_analysis"
    assert "candidate_disposition" not in issue


def test_model_verdict_and_legacy_proof_are_evidence_only() -> None:
    pipeline = ValidationPipeline(_Memory())
    issue = {
        "id": "ISSUE",
        "location": "src/a.c:7",
        "deterministic_proofs": [
            {
                "outcome": "confirm",
                "proof_kind": "legacy",
                "completeness": "complete",
            }
        ],
    }

    outcome = pipeline.apply_validator_result(
        issue,
        {
            "verdict": "verified",
            "reasoning": "model says verified",
            "confidence_score": 1.0,
            "deterministic_proof": {"outcome": "confirm"},
        },
        verdict="verified",
        score_data=_score(1.0),
    )

    assert outcome.report_bucket == "observations"
    assert outcome.memory_status == "needs_review"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"
    assert issue["model_adapter_effect"] == "evidence_only"


def test_rejection_or_category_correction_cannot_close_candidate() -> None:
    pipeline = ValidationPipeline(_Memory())
    issue = {"id": "ISSUE", "category": "alloc_free_mismatch"}

    outcome = pipeline.apply_validator_result(
        issue,
        {
            "verdict": "rejected",
            "reasoning": "actually a memory leak",
            "corrected_category": "memory_leak",
        },
        verdict="rejected",
        score_data=_score(1.0),
    )

    assert outcome.memory_status == "needs_review"
    assert issue["category"] == "alloc_free_mismatch"
    assert issue["candidate_disposition"] == "needs_review"


def test_unvalidated_candidate_fails_closed_to_review() -> None:
    issue = {"id": "ISSUE", "location": "src/a.c:7"}

    outcome = ValidationPipeline(_Memory()).apply_unvalidated(issue, _score(0.5))

    assert outcome.report_bucket == "observations"
    assert issue["candidate_disposition"] == "needs_review"
    assert issue["finding_kind"] == "needs_review"


def test_validation_failure_is_operational_obligation() -> None:
    issue = {"id": "ISSUE", "location": "src/a.c:7"}

    outcome = ValidationPipeline(_Memory()).apply_validation_failure(issue, "timeout")

    assert outcome.memory_status == "engine_failed"
    assert issue["record_role"] == "operational_obligation"
    assert issue["finding_kind"] == "validation_engine_failed"


def test_score_components_remain_diagnostic() -> None:
    memory = _Memory()
    memory.baseline = {"status": "accepted"}
    issue = {
        "dedup_key": "key",
        "rule_confidence": 0.8,
        "source": "arg",
        "sink": "free",
        "evidence_pack": {"path": {"complete": True}},
    }

    score = ValidationPipeline(memory).score_components(
        issue, {"confidence_score": 0.9, "verdict": "verified"}
    )

    assert score["path_completeness"] == 1.0
    assert score["history_feedback"] == 1.0
    assert 0.0 <= score["final_score"] <= 1.0
    assert "candidate_disposition" not in issue


def test_preserve_location_recovers_nested_finding_summary() -> None:
    issue = {
        "location": "",
        "evidence_pack": {"finding_summary": {"location": "src/recovered.c:77-79"}},
    }

    preserve_issue_location(issue)

    assert issue["location"] == "src/recovered.c:77-79"
    assert issue["file"] == "src/recovered.c"
    assert issue["line"] == 77
    assert issue["end_line"] == 79
