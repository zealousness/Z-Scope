"""Plan Phase 3: needs_review sub-states, presentation, and opt-in demotion.

The three sub-states refine the review bucket without touching scoring
attribution; the operator opt-in demotes only ``model_rejected_unproven``
rows and leaves a trail marker.
"""

from __future__ import annotations

from typing import Any, Dict

from zscope.core.validation.pipeline import needs_review_sub_state
from zscope.reporting.report import FinalReport
from zscope.reporting.views import build_report_views


def _issue(**overrides: Any) -> Dict[str, Any]:
    issue: Dict[str, Any] = {
        "id": "ISSUE-1",
        "rule": "clang_cfg_unlock_without_matching_lock",
        "validation_status": "needs_review",
        "candidate_disposition": "needs_review",
        "validator_verdict": "rejected",
        "validation_reasoning": "The unlock has no matching acquire in this function.",
        "missing_fact_kinds": ["event:acquire"],
    }
    issue.update(overrides)
    return issue


def test_rejected_verdict_maps_to_model_rejected_unproven() -> None:
    assert needs_review_sub_state(_issue()) == "model_rejected_unproven"


def test_uncertain_without_facts_is_policy_pending() -> None:
    issue = _issue(
        validator_verdict="uncertain",
        missing_fact_kinds=[],
        negative_evidence=None,
        blocking_negative_evidence=False,
    )

    assert needs_review_sub_state(issue) == "policy_pending_promotion"


def test_uncertain_with_missing_facts_is_model_uncertain() -> None:
    issue = _issue(validator_verdict="uncertain")

    assert needs_review_sub_state(issue) == "model_uncertain"


def test_confirmed_and_conflict_items_have_no_sub_state() -> None:
    confirmed = _issue(candidate_disposition="confirmed", validation_status="validated")
    conflict = _issue(
        validator_verdict="uncertain",
        candidate_disposition="needs_review",
        evidence_conflict=True,
        missing_fact_kinds=[],
    )
    conflict["validator_verdict"] = "verified"

    assert needs_review_sub_state(confirmed) == ""
    assert needs_review_sub_state(conflict) == ""


def _review_items() -> list:
    return [
        _issue(id="R1", validation_cluster_uid="VAL-R1"),
        _issue(
            id="R2",
            validation_cluster_uid="VAL-R2",
            validator_verdict="uncertain",
            missing_fact_kinds=["event:acquire"],
        ),
        _issue(
            id="R3",
            validation_cluster_uid="VAL-R3",
            validator_verdict="uncertain",
            missing_fact_kinds=[],
            negative_evidence=None,
            blocking_negative_evidence=False,
        ),
    ]


def test_review_view_annotates_sub_states_and_presentation() -> None:
    items = _review_items()
    views = build_report_views([], items)
    review = views["with_needs_review"]["issues"]
    by_id = {item["id"]: item for item in review}

    assert by_id["R1"]["needs_review_sub_state"] == "model_rejected_unproven"
    presentation = by_id["R1"]["needs_review_presentation"]
    assert presentation["model_verdict"] == "rejected"
    assert "确定性证明" in presentation["suggested_action"]
    assert "补齐缺失证据" in presentation["suggested_action"]
    assert presentation["missing_fact_kinds"] == ["event:acquire"]
    assert by_id["R2"]["needs_review_sub_state"] == "model_uncertain"
    assert by_id["R3"]["needs_review_sub_state"] == "policy_pending_promotion"
    assert views["with_needs_review"]["unproven_rejection_dismissed_count"] == 0


def test_opt_in_demotion_touches_only_review_view() -> None:
    items = _review_items()
    views = build_report_views([], items, demote_unproven_rejections=True)
    review = views["with_needs_review"]["issues"]
    by_id = {item["id"]: item for item in review}

    assert by_id["R1"]["candidate_disposition"] == "dismissed_unproven_rejection"
    assert by_id["R1"]["downgraded_from_disposition"] == "needs_review"
    assert by_id["R2"]["candidate_disposition"] == "needs_review"
    assert by_id["R3"]["candidate_disposition"] == "needs_review"
    assert views["with_needs_review"]["unproven_rejection_dismissed_count"] == 1

    # The default view and the scoring-attribution ledger stay untouched.
    assert views["default"]["issues"] == []
    plain = build_report_views([], items)["with_needs_review"]["issues"]
    assert all(item["candidate_disposition"] == "needs_review" for item in plain)


def test_markdown_review_section_renders_sub_state_and_action(tmp_path) -> None:
    from zscope.reporting.report import ReportGenerator

    review = _issue(id="MD-1", validation_cluster_uid="VAL-MD1")
    review["needs_review_sub_state"] = "model_rejected_unproven"
    review["needs_review_presentation"] = {
        "model_verdict": "rejected",
        "rejection_reason": "The unlock has no matching acquire in this function.",
        "missing_fact_kinds": ["event:acquire"],
        "suggested_action": "模型否决了该问题，但否决没有确定性证明支撑；补齐缺失证据并重新验证后，才能最终定论（确认或拒绝）。",
    }
    report = ReportGenerator.__new__(ReportGenerator)
    report.project_root = tmp_path
    final_report = FinalReport(
        entry_function="td_main",
        overall_verdict="issues_found",
        report_views={
            "with_needs_review": {
                "issues": [review],
                "included_needs_review_count": 1,
            }
        },
    )

    output = report.save_markdown_report(final_report)
    content = output.read_text(encoding="utf-8")

    assert "`model_rejected_unproven`（模型否决但未获确定性证明）" in content
    assert "**缺失事实清单**: `event:acquire`" in content
    assert "补齐缺失证据并重新验证后" in content
