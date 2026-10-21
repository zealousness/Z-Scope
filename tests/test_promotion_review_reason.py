"""Tests for the needs_review promotion-review explanation (未晋级原因)."""

from zscope.core.validation.pipeline import (
    ValidationPipeline,
    promotion_review_reason,
)
from zscope.reporting.views import annotate_needs_review_sub_state

from tests.test_validation_pipeline import FakeUserConfig


def _pipeline(**kwargs) -> ValidationPipeline:
    return ValidationPipeline(FakeUserConfig(), **kwargs)


def _issue(**overrides):
    issue = {
        "id": "ISSUE_9",
        "function": "parse_header",
        "location": "src/parse.c:42",
        "category": "security",
        "subcategory": "memory_bounds_integer",
        "defect_class": "memory_bounds_integer",
    }
    issue.update(overrides)
    return issue


def test_uncertain_below_threshold_explains_confidence_gap():
    pipeline = _pipeline(uncertain_confirm_threshold=0.9)
    issue = _issue()
    val_data = {"verdict": "uncertain", "confidence_score": 0.62, "reasoning": "证据不足"}
    outcome = pipeline.apply_validator_result(
        issue, val_data, verdict="uncertain", score_data={"final_score": 0.8}
    )
    assert outcome.memory_status == "needs_review"
    reason = issue["promotion_review_reason"]
    assert "uncertain" in reason
    assert "0.62" in reason
    assert "0.90" in reason


def test_uncertain_with_disabled_promotion_channel_names_the_knob():
    pipeline = _pipeline()
    issue = _issue()
    val_data = {"verdict": "uncertain", "confidence_score": 0.95, "reasoning": ""}
    pipeline.apply_validator_result(
        issue, val_data, verdict="uncertain", score_data={"final_score": 0.9}
    )
    reason = issue["promotion_review_reason"]
    assert "validation_uncertain_confirm_threshold" in reason


def test_uncertain_with_negative_evidence_names_it():
    pipeline = _pipeline(uncertain_confirm_threshold=0.5)
    issue = _issue()
    val_data = {
        "verdict": "uncertain",
        "confidence_score": 0.9,
        "reasoning": "",
        "negative_evidence": ["上层调用方存在长度检查"],
    }
    pipeline.apply_validator_result(
        issue, val_data, verdict="uncertain", score_data={"final_score": 0.9}
    )
    reason = issue["promotion_review_reason"]
    assert "负面证据" in reason


def test_uncertain_with_missing_facts_names_them():
    reason = promotion_review_reason(
        _issue(missing_fact_kinds=["guard_dominance", "caller_contract"]),
        kind="uncertain_unpromoted",
        final_score=0.9,
        val_data={"confidence_score": 0.95},
        uncertain_confirm_threshold=0.5,
    )
    assert "guard_dominance" in reason
    assert "caller_contract" in reason


def test_verified_low_score_explains_score_gap():
    pipeline = _pipeline()
    issue = _issue()
    outcome = pipeline.apply_validator_result(
        issue,
        {
            "verdict": "verified",
            "confidence_score": 0.9,
            "reasoning": "模型确认了触发路径",
        },
        verdict="verified",
        score_data={"final_score": 0.42, "path_completeness": 0.4},
    )
    assert outcome.memory_status == "needs_review"
    reason = issue["promotion_review_reason"]
    assert "verified" in reason
    assert "0.42" in reason
    assert "0.60" in reason
    assert "0.40" in reason


def test_verified_with_negative_evidence_names_it():
    reason = promotion_review_reason(
        _issue(),
        kind="verified_unpromoted",
        final_score=0.8,
        val_data={
            "confidence_score": 0.9,
            "negative_evidence": ["释放路径已被所有权转移覆盖"],
            "blocking_negative_evidence": True,
        },
        score_data={"final_score": 0.8, "path_completeness": 0.9},
    )
    assert "负面证据" in reason


def test_rejected_without_proof_explains_deterministic_requirement():
    pipeline = _pipeline()
    issue = _issue()
    val_data = {"verdict": "rejected", "confidence_score": 0.7, "reasoning": "调用方不可控"}
    outcome = pipeline.apply_validator_result(
        issue, val_data, verdict="rejected", score_data={"final_score": 0.5}
    )
    assert outcome.memory_status == "needs_review"
    reason = issue["promotion_review_reason"]
    assert "确定性反驳证明" in reason
    # The user-facing reasoning is Chinese and keeps the model reasoning.
    assert "调用方不可控" in issue["validation_reasoning"]


def test_structural_rejection_review_sets_reason():
    pipeline = _pipeline()
    issue = _issue(
        category="security",
        subcategory="double_free",
        defect_class="double_free",
        sink="free(p)",
        evidence_pack={"sink": {"operation": "free(p)"}},
        positive_evidence=["缺少二次释放防护检查"],
    )
    val_data = {"verdict": "rejected", "reasoning": "当前调用方未触发第二次释放"}
    outcome = pipeline.apply_validator_result(
        issue, val_data, verdict="rejected", score_data={"final_score": 0.5}
    )
    assert outcome.memory_status == "needs_review"
    assert issue["rejection_source"] == "validator_structural_review"
    reason = issue["promotion_review_reason"]
    assert "结构性风险" in reason
    assert "可控性" in reason


def test_evidence_conflict_reason_builder():
    reason = promotion_review_reason(_issue(), kind="evidence_conflict")
    assert "相互冲突" in reason
    assert "人工复核" in reason


def test_corrected_category_review_reason():
    reason = promotion_review_reason(
        _issue(),
        kind="corrected_category_review",
        final_score=0.55,
        val_data={"confidence_score": 0.62},
        corrected_category="use_after_free",
    )
    assert "use_after_free" in reason
    assert "0.62" in reason


def test_unvalidated_issue_explains_missing_validator():
    pipeline = _pipeline()
    issue = _issue()
    outcome = pipeline.apply_unvalidated(issue, {"final_score": 0.5})
    assert outcome.report_bucket == "observations"
    reason = issue["promotion_review_reason"]
    assert "Validator 未启用" in reason


def test_views_presentation_is_chinese_and_carries_promotion_reason():
    pipeline = _pipeline()
    issue = _issue()
    val_data = {"verdict": "uncertain", "confidence_score": 0.4, "reasoning": ""}
    pipeline.apply_validator_result(
        issue, val_data, verdict="uncertain", score_data={"final_score": 0.5}
    )
    presentation = annotate_needs_review_sub_state(issue)
    assert presentation, "uncertain without facts must classify into a sub-state"
    action = presentation["suggested_action"]
    assert (
        action == ("补齐缺失的决策事实后重新验证。")
        or "模型" in action
        or "策略" in action
        or "补齐" in action
    )
    assert presentation["promotion_review_reason"] == issue["promotion_review_reason"]
