"""Validation-stage suppression and review-memory helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from ...common.issue_identity import canonical_issue_key
from ...memory import ReviewMemory


FALSE_POSITIVE_BASELINE_STATUSES = {"false_positive", "suppressed"}
TRUE_POSITIVE_BASELINE_STATUSES = {"accepted", "verified", "true_positive"}
VALIDATOR_DETAIL_FIELDS = (
    "exploit_scenario",
    "source",
    "sink",
    "control_of_source",
    "guard_analysis",
    "positive_evidence",
    "negative_evidence",
)


@dataclass
class PreValidationDecision:
    """Decision made before invoking the Validator LLM."""

    action: str
    finding_kind: str
    rejection_source: str
    report_bucket: Optional[str] = "observations"
    baseline: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class ValidationOutcome:
    """Disposition after validation has mutated an issue."""

    report_bucket: Optional[str]
    memory_status: Optional[str] = None
    verdict: str = ""
    final_score: float = 0.0


class ValidationPipeline:
    """Owns user suppression and baseline checks for validation.

    The LLM Validator remains invoked by ``Analyzer`` for now, while this class
    owns the validation-stage disposition rules that decide whether a candidate
    becomes a report issue, an audit observation, or a discarded rejection.
    """

    def __init__(
        self,
        user_config: Any,
        issue_key_fn: Callable[[Dict[str, Any]], str] = canonical_issue_key,
    ):
        self.user_config = user_config
        self.review_memory = (
            user_config if isinstance(user_config, ReviewMemory) else ReviewMemory(user_config)
        )
        self.issue_key_fn = issue_key_fn

    def suppression_category(self, issue: Dict[str, Any]) -> str:
        return str(
            issue.get("defect_class")
            or issue.get("subcategory")
            or issue.get("category")
            or ""
        )

    def apply_pre_validation_feedback(
        self,
        issue: Dict[str, Any],
        issue_func: str,
    ) -> Optional[PreValidationDecision]:
        """Mutate and return a decision when user feedback suppresses an issue."""
        category = self.suppression_category(issue)
        if self.review_memory.is_false_positive(
            str(issue_func),
            str(issue.get("location") or ""),
            category,
        ):
            issue["validation_status"] = "rejected"
            issue["finding_kind"] = "suppressed_false_positive"
            issue["rejection_source"] = "user_config"
            return PreValidationDecision(
                action="suppress",
                finding_kind="suppressed_false_positive",
                rejection_source="user_config",
            )

        baseline = self.find_baseline(issue)
        if baseline and str(baseline.get("status") or "").lower() in FALSE_POSITIVE_BASELINE_STATUSES:
            issue["validation_status"] = "rejected"
            issue["finding_kind"] = "suppressed_baseline"
            issue["rejection_source"] = "finding_baseline"
            match_strategy = baseline.get("match_strategy")
            if match_strategy:
                issue["baseline_match_strategy"] = match_strategy
            return PreValidationDecision(
                action="suppress",
                finding_kind="suppressed_baseline",
                rejection_source="finding_baseline",
                baseline=baseline,
            )
        return None

    def find_baseline(self, issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        dedup_key = str(issue.get("dedup_key") or self.issue_key_fn(issue))
        return self.review_memory.get_finding_baseline_for_issue(issue, dedup_key)

    def history_feedback_score(self, issue: Dict[str, Any]) -> float:
        try:
            baseline = self.find_baseline(issue)
        except Exception:
            baseline = None
        if not baseline:
            return 0.5
        status = str(baseline.get("status") or "").lower()
        if status in TRUE_POSITIVE_BASELINE_STATUSES:
            return 1.0
        if status in FALSE_POSITIVE_BASELINE_STATUSES or status == "rejected":
            return 0.0
        return 0.5

    def score_components(
        self,
        issue: Dict[str, Any],
        val_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """Compute the validation score used for report disposition."""
        val_data = val_data or {}
        rule_confidence = self._coerce_score(
            issue.get("rule_confidence", issue.get("confidence", 0.5)),
            default=0.5,
        )
        path_completeness = self._path_completeness_score(issue, val_data)
        contract_consistency = self._contract_consistency_score(issue, val_data)
        validation_confidence = self._coerce_score(
            val_data.get("confidence_score", issue.get("confidence", 0.5)),
            default=0.5,
        )
        history_feedback = self.history_feedback_score(issue)
        final_score = (
            0.25 * rule_confidence
            + 0.25 * path_completeness
            + 0.20 * contract_consistency
            + 0.20 * validation_confidence
            + 0.10 * history_feedback
        )
        return {
            "rule_confidence": round(rule_confidence, 4),
            "path_completeness": round(path_completeness, 4),
            "contract_consistency": round(contract_consistency, 4),
            "validation_confidence": round(validation_confidence, 4),
            "history_feedback": round(history_feedback, 4),
            "final_score": round(final_score, 4),
        }

    def apply_unvalidated(
        self,
        issue: Dict[str, Any],
        score_data: Dict[str, float],
    ) -> ValidationOutcome:
        """Mark a candidate when the Validator agent is disabled."""
        issue["validation_status"] = "unvalidated"
        issue.setdefault("finding_kind", "unvalidated_candidate")
        issue["score_components"] = score_data
        final_score = self._final_score(score_data)
        issue["final_score"] = final_score
        return ValidationOutcome(
            report_bucket="issues",
            verdict="unvalidated",
            final_score=final_score,
        )

    def apply_validator_result(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        *,
        verdict: str,
        score_data: Dict[str, float],
    ) -> ValidationOutcome:
        """Apply the normalized Validator result and return its report bucket."""
        issue["score_components"] = score_data
        final_score = self._final_score(score_data)
        issue["final_score"] = final_score
        issue["validator_verdict"] = verdict

        if verdict == "verified" and final_score >= 0.6:
            if final_score >= 0.8:
                issue["validation_status"] = "validated"
                issue["finding_kind"] = val_data.get("finding_kind") or "verified_vulnerability"
                report_bucket = "issues"
            else:
                issue["validation_status"] = "needs_review"
                issue["finding_kind"] = "needs_review"
                report_bucket = "observations"

            issue["validation_reasoning"] = val_data.get("reasoning")
            issue["confidence"] = val_data.get(
                "confidence_score",
                issue.get("confidence", 0.5),
            )
            self._copy_validator_detail_fields(issue, val_data)
            return ValidationOutcome(
                report_bucket=report_bucket,
                memory_status=str(issue["validation_status"]),
                verdict=verdict,
                final_score=final_score,
            )

        if verdict == "verified":
            issue["validation_status"] = "uncertain"
            issue["finding_kind"] = "audit_observation"
            issue["validation_reasoning"] = val_data.get("reasoning")
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="uncertain",
                verdict=verdict,
                final_score=final_score,
            )

        if verdict == "uncertain":
            issue["validation_status"] = "uncertain"
            issue["finding_kind"] = val_data.get("finding_kind") or "audit_observation"
            issue["validation_reasoning"] = val_data.get("reasoning")
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="uncertain",
                verdict=verdict,
                final_score=final_score,
            )

        issue["validation_status"] = "rejected"
        issue["finding_kind"] = "rejected"
        issue["rejection_source"] = "validator"
        issue["validation_reasoning"] = val_data.get("reasoning")
        return ValidationOutcome(
            report_bucket=None,
            memory_status="rejected",
            verdict=verdict,
            final_score=final_score,
        )

    def apply_validation_failure(
        self,
        issue: Dict[str, Any],
        error: Any,
    ) -> ValidationOutcome:
        """Keep failed Validator calls visible as pending observations."""
        issue["validation_status"] = "pending"
        issue.setdefault("finding_kind", "validation_pending")
        issue["validation_error"] = error
        return ValidationOutcome(report_bucket="observations", verdict="pending")

    @staticmethod
    def _final_score(score_data: Dict[str, float]) -> float:
        try:
            return float(score_data.get("final_score", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _coerce_score(value: Any, default: float = 0.5) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            score = default
        return max(0.0, min(1.0, score))

    def _path_completeness_score(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> float:
        evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        path = evidence.get("path") if isinstance(evidence.get("path"), dict) else {}
        if path.get("complete") is True or path.get("complete_in_function") is True:
            return 1.0
        if (issue.get("source") or val_data.get("source")) and (issue.get("sink") or val_data.get("sink")):
            return 0.75
        if issue.get("evidence_refs"):
            return 0.7
        return 0.5

    @staticmethod
    def _contract_consistency_score(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> float:
        negative = issue.get("negative_evidence") or val_data.get("negative_evidence") or []
        if negative:
            return 0.55
        if (issue.get("source") or val_data.get("source")) and (issue.get("sink") or val_data.get("sink")):
            return 0.8
        if issue.get("finding_kind") == "backend_signal":
            return 0.7
        return 0.6

    @staticmethod
    def _copy_validator_detail_fields(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> None:
        for field in VALIDATOR_DETAIL_FIELDS:
            if field in val_data and val_data.get(field) not in (None, ""):
                issue[field] = val_data.get(field)
