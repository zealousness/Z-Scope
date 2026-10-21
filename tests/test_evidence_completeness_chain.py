"""Plan Phase 2.2: the report-level ``evidence_completeness`` production chain.

The scan-time envelope can only emit ``unknown`` (validation has not run);
after validation the field must carry the real coverage derived from the
decision-fact slice / completion outcome instead of staying a constant.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict

from zscope.core.validation.runner import ValidationRunner


def _derive(**overrides: Any) -> str:
    issue: Dict[str, Any] = {"id": "I", "rule": "r"}
    issue.update(overrides)
    return ValidationRunner._evidence_completeness_from_issue(issue)


def test_coverage_mapping() -> None:
    assert _derive(decision_fact_coverage="complete") == "complete"
    assert _derive(decision_fact_coverage="partial") == "partial"


def test_completion_status_mapping() -> None:
    assert _derive(evidence_completion_status="completed") == "complete"
    assert _derive(evidence_completion_status="completed_with_proof") == "complete"
    assert _derive(evidence_completion_status="completed_partial") == "partial"


def test_coverage_takes_precedence_over_status() -> None:
    assert (
        _derive(decision_fact_coverage="partial", evidence_completion_status="completed")
        == "partial"
    )


def test_unknown_when_no_structured_signal() -> None:
    assert _derive() == "unknown"
    assert _derive(decision_fact_coverage="", evidence_completion_status="exhausted") == "unknown"
    assert (
        _derive(decision_fact_coverage=None, evidence_completion_status="not_applicable")
        == "unknown"
    )


def test_attribution_writes_real_evidence_completeness() -> None:
    issue: Dict[str, Any] = {
        "id": "I",
        "candidate_disposition": "needs_review",
        "decision_fact_coverage": "complete",
        "evidence_completion_status": "exhausted",
        "attribution": {},
    }
    outcome = SimpleNamespace(memory_status="needs_review", final_score=0.7, report_bucket="o")
    ValidationRunner._record_validator_attribution(
        issue,
        {"pass": "initial"},
        outcome,
    )

    assert issue["evidence_completeness"] == "complete"


def test_attribution_keeps_unknown_without_structured_signals() -> None:
    issue: Dict[str, Any] = {"id": "I", "candidate_disposition": "needs_review", "attribution": {}}
    outcome = SimpleNamespace(memory_status="needs_review", final_score=0.7, report_bucket="o")
    ValidationRunner._record_validator_attribution(
        issue,
        {"pass": "initial"},
        outcome,
    )

    assert issue["evidence_completeness"] == "unknown"
