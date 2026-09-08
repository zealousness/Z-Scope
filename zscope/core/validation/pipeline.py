"""Validation-stage suppression and review-memory helpers."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, cast

from ...common.defect_cwe_map import ensure_issue_cwes
from ...common.issue_identity import canonical_issue_key, parse_issue_location
from ...memory import ReviewMemory
from .proofs import deterministic_decision_proof

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
    "blocking_negative_evidence",
)
_CWE_BY_CORRECTED_CATEGORY = {
    "memory_leak": "CWE-772",
    "heap_overflow": "CWE-122",
    "buffer_overflow": "CWE-787",
    "buffer_overread": "CWE-126",
    "buffer_underread": "CWE-127",
    "buffer_underwrite": "CWE-124",
    "signed_unsigned": "CWE-195",
}
LOCATION_FILE_FIELDS = ("file", "file_path", "module_path")


def _as_dict(value: Any) -> Dict[str, Any]:
    """Narrow validation evidence mappings without copying them."""
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


LOCATION_LINE_FIELDS = ("line", "start_line")
LOCATION_END_LINE_FIELDS = ("end_line",)
LOCATION_STRING_FIELDS = (
    "location",
    "source_location",
    "sink_location",
    "source_loc",
    "sink_loc",
    "origin_location",
    "target_location",
)

# Plan Phase 3.1: needs_review presentation sub-states.  They refine the
# user-facing review bucket without changing scoring attribution.
NEEDS_REVIEW_SUB_STATES = {
    "model_uncertain",
    "model_rejected_unproven",
    "policy_pending_promotion",
}


def needs_review_sub_state(issue: Any) -> str:
    """Classify a needs_review item into one of the plan's three sub-states.

    - ``model_rejected_unproven``: the model rejected the finding, but the
      rejection never became a deterministic proof (evidence completion did
      not supply the decisive fact), so the shipped disposition stays
      needs_review.
    - ``policy_pending_promotion``: the obligation is complete and no
      negative evidence contradicts the finding; it qualifies for a policy
      promotion channel (e.g. the high-confidence band) that is currently
      disabled or awaiting rollout.
    - ``model_uncertain``: the model could not decide and evidence remains
      missing.

    Anything else (verified-unproven, evidence conflicts, pre-validation
    holds) returns an empty sub-state on purpose.
    """

    issue_dict = issue if isinstance(issue, dict) else {}
    disposition = str(issue_dict.get("candidate_disposition") or "").lower()
    status = str(issue_dict.get("validation_status") or "").lower()
    if disposition != "needs_review" and status != "needs_review":
        return ""
    verdict = str(issue_dict.get("validator_verdict") or "").lower()
    if verdict == "rejected":
        return "model_rejected_unproven"
    if verdict == "uncertain":
        if not issue_dict.get("missing_fact_kinds") and not _has_negative_evidence(issue_dict):
            return "policy_pending_promotion"
        return "model_uncertain"
    return ""


def _has_negative_evidence(issue: Dict[str, Any]) -> bool:
    if issue.get("blocking_negative_evidence") is True:
        return True
    return bool(issue.get("negative_evidence"))


def _score_text(score_data: Dict[str, Any], key: str) -> str:
    try:
        return f"{float(score_data.get(key, 0.0) or 0.0):.2f}"
    except (TypeError, ValueError):
        return "0.00"


def _confirmed_evidence_gap_texts(
    issue: Dict[str, Any],
    score_data: Dict[str, Any],
    val_data: Dict[str, Any],
) -> List[str]:
    """List the unmet automatic-promotion criteria for a ``verified`` verdict.

    Mirrors ``_has_confirmed_evidence`` so the report can say exactly which
    promotion tier condition failed instead of a generic "not promoted".
    """

    gaps: List[str] = []
    final_score = _score_text(score_data, "final_score")
    path = _score_text(score_data, "path_completeness")
    contract = _score_text(score_data, "contract_consistency")
    validator_conf = _score_text(score_data, "validation_confidence")
    negative = val_data.get("negative_evidence")
    has_negative = (
        bool(negative) if isinstance(negative, list) else bool(str(negative or "").strip())
    )
    if float(score_data.get("final_score", 0.0) or 0.0) < 0.60:
        gaps.append(f"综合评分 {final_score} 低于自动确认线 0.60")
    if float(score_data.get("path_completeness", 0.0) or 0.0) < 0.75:
        gaps.append(f"路径完整度 {path} 低于 0.75")
    if float(score_data.get("contract_consistency", 0.0) or 0.0) < 0.55:
        gaps.append(f"调用契约一致度 {contract} 低于 0.55")
    if float(score_data.get("validation_confidence", 0.0) or 0.0) < 0.80:
        gaps.append(f"模型验证置信度 {validator_conf} 低于 0.80")
    if has_negative:
        gaps.append("存在未关闭的负面证据")
    context_version = str(issue.get("decision_context_version") or "")
    if context_version in {
        "zscope.decision-context.v3.1",
        "zscope.decision-context.v3.2",
        "zscope.decision-context.v3.3",
    }:
        fact_slice = issue.get("decision_fact_slice")
        if not isinstance(fact_slice, dict) or not (fact_slice.get("fact_uids") or []):
            gaps.append("缺少可审计的确定性决策事实切片")
        coverage = str(issue.get("decision_fact_coverage") or "")
        if coverage not in {"complete", "partial"}:
            gaps.append("决策事实覆盖率不足")
        blocking = val_data.get("blocking_negative_evidence")
        if not isinstance(blocking, bool):
            gaps.append("模型未给出阻断性负面证据的明确结论")
        if issue.get("source") in (None, "", {}, []) or issue.get("sink") in (None, "", {}, []):
            gaps.append("缺少明确的 source/sink 定位")
    if not gaps:
        gaps.append("未满足完整证据层级要求")
    return gaps


def _uncertain_promotion_gap_texts(
    issue: Dict[str, Any],
    val_data: Dict[str, Any],
    final_score: float,
    threshold: Optional[float],
) -> List[str]:
    """List the unmet high-confidence-band conditions for an ``uncertain`` verdict."""

    gaps: List[str] = []
    if threshold is None:
        gaps.append(
            "高置信度自动确认通道未启用（runtime.analysis.validation_uncertain_confirm_threshold）"
        )
    else:
        confidence = val_data.get("confidence_score", issue.get("confidence", 0.5))
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = -1.0
        if confidence < threshold:
            gaps.append(f"模型置信度 {confidence:.2f} 低于自动确认阈值 {threshold:.2f}")
    if final_score < 0.6:
        gaps.append(f"综合评分 {final_score:.2f} 低于 0.60")
    missing = issue.get("missing_fact_kinds")
    if isinstance(missing, list) and missing:
        gaps.append("仍缺少关键决策事实：" + "、".join(str(kind) for kind in missing))
    if issue.get("blocking_negative_evidence") is True:
        gaps.append("存在阻断性负面证据")
    elif issue.get("negative_evidence"):
        count = (
            len(issue["negative_evidence"]) if isinstance(issue["negative_evidence"], list) else 1
        )
        gaps.append(f"存在 {count} 条未关闭的负面证据")
    if not gaps:
        gaps.append("未满足自动确认条件")
    return gaps


def promotion_review_reason(
    issue: Dict[str, Any],
    *,
    kind: str,
    final_score: float = 0.0,
    val_data: Optional[Dict[str, Any]] = None,
    uncertain_confirm_threshold: Optional[float] = None,
    score_data: Optional[Dict[str, Any]] = None,
    corrected_category: str = "",
) -> str:
    """Build the user-facing Chinese explanation of why a candidate stayed
    ``needs_review`` instead of being promoted to ``validated``.

    The text is derived deterministically from the same policy data the
    promotion branches evaluate, so it always matches the real decision.
    """

    val_data = val_data if isinstance(val_data, dict) else {}
    score_data = score_data if isinstance(score_data, dict) else {}
    if kind == "evidence_conflict":
        return (
            "完整的确定性确认证明与拒绝证明同时成立并相互冲突，无法自动裁决为"
            "确认或拒绝；需要人工复核后再定论。"
        )
    if kind == "verified_unpromoted":
        gaps = _confirmed_evidence_gap_texts(issue, score_data, val_data)
        return (
            "模型判定为 verified，但未满足自动确认（晋级 validated）的证据标准："
            + "；".join(gaps)
            + "。因此保留待人工复核，而不是自动确认为真实缺陷。"
        )
    if kind == "uncertain_unpromoted":
        gaps = _uncertain_promotion_gap_texts(
            issue, val_data, final_score, uncertain_confirm_threshold
        )
        return (
            "模型判定为 uncertain（无法确认也无充分反驳证据），未满足自动确认条件："
            + "；".join(gaps)
            + "。因此保留待人工复核。"
        )
    if kind == "rejected_unproven":
        return (
            "模型倾向于否决该候选，但未形成可复现的确定性反驳证明（例如支配性防护、"
            "所有权转移、锁覆盖或不可达路径的完整证据）；按策略不能仅凭模型意见拒绝，"
            "保留待人工复核。"
        )
    if kind == "structural_rejection_review":
        return (
            "该候选为结构性风险且具有具体代码证据，模型否决仅基于当前调用方可控性，"
            "并未证明沉没点本身安全；按策略保留待人工复核，而不是跟随模型否决。"
        )
    if kind == "corrected_category_review":
        category = corrected_category or str(issue.get("category") or "")
        confidence = val_data.get("confidence_score", issue.get("confidence", 0.5))
        try:
            confidence_text = f"{float(confidence):.2f}"
        except (TypeError, ValueError):
            confidence_text = "未知"
        return (
            f"模型否决了原类别，但在同一代码证据上识别出具体的 `{category}` 问题；"
            f"自动确认还需模型置信度与综合评分达标（当前置信度 {confidence_text}、"
            f"综合评分 {final_score:.2f}）。因此保留待人工复核。"
        )
    if kind == "unvalidated":
        return (
            "Validator 未启用：候选未经模型验证，缺少自动确认所需的验证结论与"
            "置信度；保留待人工复核。"
        )
    return "该候选未满足自动确认（晋级 validated）的策略条件，保留待人工复核。"


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
        deterministic_proof_verifier: Optional[
            Callable[[Dict[str, Any], Dict[str, Any]], bool]
        ] = None,
        *,
        enable_deterministic_proof_routing: bool = True,
        uncertain_confirm_threshold: Optional[float] = None,
    ):
        self.user_config = user_config
        self.review_memory = (
            user_config if isinstance(user_config, ReviewMemory) else ReviewMemory(user_config)
        )
        self.issue_key_fn = issue_key_fn
        # Proof authority must be supplied by a deterministic engine boundary.
        # Validator JSON is untrusted and cannot self-attest a contradiction.
        self.deterministic_proof_verifier = deterministic_proof_verifier
        self.enable_deterministic_proof_routing = bool(enable_deterministic_proof_routing)
        # Escalation rung R3 pilot knob (balanced_confirmed_tp_plan.md Phase 2).
        # None keeps the shipped behavior: uncertain verdicts never confirm.
        # When set, an uncertain verdict at or above the threshold confirms
        # only when the security obligation has no missing facts and no
        # negative evidence is on record.
        self.uncertain_confirm_threshold = uncertain_confirm_threshold

    def suppression_category(self, issue: Dict[str, Any]) -> str:
        return str(
            issue.get("defect_class") or issue.get("subcategory") or issue.get("category") or ""
        )

    def apply_pre_validation_feedback(
        self,
        issue: Dict[str, Any],
        issue_func: str,
    ) -> Optional[PreValidationDecision]:
        """Mutate and return a decision when user feedback suppresses an issue."""
        static_decision = self._apply_static_validation_gate(issue)
        if static_decision:
            return static_decision

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
        if (
            baseline
            and str(baseline.get("status") or "").lower() in FALSE_POSITIVE_BASELINE_STATUSES
        ):
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

    def apply_deterministic_prevalidation(
        self,
        issue: Dict[str, Any],
        score_data: Optional[Dict[str, float]] = None,
    ) -> Optional[ValidationOutcome]:
        """Close a group from complete deterministic proof before the Validator.

        The method intentionally accepts neither model text nor a validator
        verdict.  It is therefore safe to use as a token-saving pre-pass in a
        shared validation queue.
        """

        if not self.enable_deterministic_proof_routing:
            return None
        confirmation_proof = deterministic_decision_proof(issue, outcome="confirm")
        rejection_proof = deterministic_decision_proof(issue, outcome="reject")
        if confirmation_proof is None and rejection_proof is None:
            return None

        score_data = score_data or self.score_components(issue, {})
        final_score = self._final_score(score_data)
        preserve_issue_location(issue)
        issue["score_components"] = score_data
        issue["final_score"] = final_score
        issue["validator_avoided"] = True

        if self._is_rollout_shadow_candidate(issue):
            shadow_outcome = (
                "conflicting_proofs"
                if confirmation_proof is not None and rejection_proof is not None
                else "confirmed_by_proof" if confirmation_proof is not None else "rejected_by_proof"
            )
            proof = confirmation_proof or rejection_proof
            if proof is not None and shadow_outcome != "conflicting_proofs":
                issue["decision_proof"] = proof.to_dict()
                issue["proof_provider"] = proof.producer_engine
                issue["proof_coverage"] = "complete"
            issue.update(
                {
                    "validation_status": "shadow",
                    "candidate_disposition": "shadow_observation",
                    "finding_kind": "rollout_shadow_observation",
                    "deterministic_prevalidation_decision": "shadow_observation",
                    "rollout_shadow_evidence_outcome": shadow_outcome,
                    "validation_reasoning": (
                        "该候选在语义/发现影子灰度期间完成评估；其证明结果仅作为遥测保留，"
                        "不会进入默认发现视图。"
                    ),
                }
            )
            return ValidationOutcome(
                report_bucket=None,
                memory_status=None,
                verdict="shadow_observation",
                final_score=final_score,
            )

        if confirmation_proof is not None and rejection_proof is not None:
            issue.update(
                {
                    "validation_status": "needs_review",
                    "candidate_disposition": "needs_review",
                    "finding_kind": "needs_review",
                    "evidence_conflict": True,
                    "deterministic_prevalidation_decision": "evidence_conflict",
                    "promotion_review_reason": promotion_review_reason(
                        issue, kind="evidence_conflict"
                    ),
                    "validation_reasoning": (
                        "完整的确定性确认证明与拒绝证明相互冲突，需要人工复核。"
                    ),
                }
            )
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict="needs_review",
                final_score=final_score,
            )
        if confirmation_proof is not None:
            issue.update(
                {
                    "validation_status": "validated",
                    "candidate_disposition": "confirmed",
                    "finding_kind": "verified_vulnerability",
                    "decision_proof": confirmation_proof.to_dict(),
                    "promotion_reason": "deterministic_prevalidation_proof",
                    "proof_provider": confirmation_proof.producer_engine,
                    "proof_coverage": "complete",
                    "deterministic_prevalidation_decision": "confirmed",
                    "validation_reasoning": confirmation_proof.contradiction_or_obligation,
                }
            )
            return ValidationOutcome(
                report_bucket="issues",
                memory_status="validated",
                verdict="confirmed",
                final_score=final_score,
            )
        assert rejection_proof is not None
        issue.update(
            {
                "validation_status": "rejected",
                "candidate_disposition": "rejected_with_proof",
                "finding_kind": "rejected",
                "rejection_source": "deterministic_prevalidation_proof",
                "deterministic_rejection": True,
                "decision_proof": rejection_proof.to_dict(),
                "proof_provider": rejection_proof.producer_engine,
                "proof_coverage": "complete",
                "deterministic_prevalidation_decision": "rejected_with_proof",
                "validation_reasoning": rejection_proof.contradiction_or_obligation,
            }
        )
        return ValidationOutcome(
            report_bucket=None,
            memory_status="rejected",
            verdict="rejected",
            final_score=final_score,
        )

    @staticmethod
    def _apply_static_validation_gate(issue: Dict[str, Any]) -> Optional[PreValidationDecision]:
        """Honor proof-carrying candidates that do not need an LLM validator pass."""
        evidence_pack = _as_dict(issue.get("evidence_pack"))
        validation_required = issue.get("validation_required")
        if validation_required is None:
            validation_required = evidence_pack.get("validation_required")
        if validation_required is not False:
            return None

        reason = str(
            issue.get("audit_observation_reason")
            or evidence_pack.get("audit_observation_reason")
            or "静态验证门控"
        )
        finding_kind = str(issue.get("finding_kind") or "").strip().lower()
        if finding_kind == "audit_observation" or reason:
            preserve_issue_location(issue)
            issue["validation_status"] = str(issue.get("validation_status") or "uncertain")
            issue["finding_kind"] = "audit_observation"
            issue["validation_reasoning"] = reason
            issue["rejection_source"] = "static_analysis"
            return PreValidationDecision(
                action="audit_observation",
                finding_kind="audit_observation",
                rejection_source="static_analysis",
                report_bucket="observations",
            )

        issue["validation_status"] = "rejected"
        issue["finding_kind"] = "static_suppressed_false_positive"
        issue["rejection_source"] = "static_analysis"
        issue["validation_reasoning"] = reason
        return PreValidationDecision(
            action="suppress",
            finding_kind="static_suppressed_false_positive",
            rejection_source="static_analysis",
            report_bucket=None,
        )

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
        closure = issue.get("v3_evidence_closure")
        if (
            str(val_data.get("pass") or "") == "investigation_synthesis"
            and str(val_data.get("verdict") or "").lower() == "verified"
            and isinstance(closure, dict)
            and closure.get("complete") is True
        ):
            # ValidatorResult v3 intentionally has no free-form confidence
            # field.  A fully cited tool-backed closure is the auditable V3
            # confidence signal used by the existing score policy.
            validation_confidence = max(validation_confidence, 0.85)
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
        preserve_issue_location(issue)
        if self._is_rollout_shadow_candidate(issue):
            issue["validation_status"] = "shadow"
            issue["candidate_disposition"] = "shadow_observation"
            issue["finding_kind"] = "rollout_shadow_observation"
            issue["score_components"] = score_data
            final_score = self._final_score(score_data)
            issue["final_score"] = final_score
            issue["validation_reasoning"] = "Validator 已被禁用，影子发现候选仅保留记录而未晋级。"
            return ValidationOutcome(
                report_bucket=None,
                verdict="shadow_observation",
                final_score=final_score,
            )
        issue["validation_status"] = "needs_review"
        issue["candidate_disposition"] = "needs_review"
        issue.setdefault("finding_kind", "needs_review")
        issue["needs_review_sub_state"] = needs_review_sub_state(issue)
        issue["promotion_review_reason"] = promotion_review_reason(issue, kind="unvalidated")
        issue["score_components"] = score_data
        final_score = self._final_score(score_data)
        issue["final_score"] = final_score
        return ValidationOutcome(
            report_bucket="observations",
            verdict="needs_review",
            final_score=final_score,
        )

    def _high_confidence_uncertain_confirms(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        final_score: float,
    ) -> bool:
        """Return True when the R3 ``high_confidence_band`` rung may confirm.

        Enabled only via ``validation_uncertain_confirm_threshold``.  A model
        ``uncertain`` verdict confirms solely when its confidence clears the
        threshold, the security obligation has no missing decision facts, and
        no negative evidence contradicts the finding.  Any doubt keeps the
        shipped needs_review disposition.
        """

        threshold = self.uncertain_confirm_threshold
        if threshold is None:
            return False
        if final_score < 0.6:
            return False
        confidence = val_data.get("confidence_score", issue.get("confidence", 0.5))
        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            return False
        if confidence < threshold:
            return False
        if issue.get("missing_fact_kinds"):
            return False
        if issue.get("blocking_negative_evidence") is True:
            return False
        if issue.get("negative_evidence"):
            return False
        return True

    def apply_validator_result(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
        *,
        verdict: str,
        score_data: Dict[str, float],
    ) -> ValidationOutcome:
        """Apply the normalized Validator result and return its report bucket."""
        preserve_issue_location(issue)
        issue["score_components"] = score_data
        final_score = self._final_score(score_data)
        issue["final_score"] = final_score
        issue["validator_verdict"] = verdict
        if isinstance(val_data.get("blocking_negative_evidence"), bool):
            issue["blocking_negative_evidence"] = val_data["blocking_negative_evidence"]

        confirmation_proof = (
            deterministic_decision_proof(issue, outcome="confirm")
            if self.enable_deterministic_proof_routing
            else None
        )
        rejection_proof = (
            deterministic_decision_proof(issue, outcome="reject")
            if self.enable_deterministic_proof_routing
            else None
        )
        if self._is_rollout_shadow_candidate(issue):
            proof = confirmation_proof or rejection_proof
            if proof is not None and not (
                confirmation_proof is not None and rejection_proof is not None
            ):
                issue["decision_proof"] = proof.to_dict()
                issue["proof_provider"] = proof.producer_engine
                issue["proof_coverage"] = "complete"
            issue["validation_status"] = "shadow"
            issue["candidate_disposition"] = "shadow_observation"
            issue["finding_kind"] = "rollout_shadow_observation"
            issue["rollout_shadow_model_verdict"] = verdict
            issue["validation_reasoning"] = val_data.get("reasoning")
            issue["confidence"] = val_data.get("confidence_score", issue.get("confidence", 0.5))
            self._copy_validator_detail_fields(issue, val_data)
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket=None,
                memory_status=None,
                verdict=verdict,
                final_score=final_score,
            )
        # A proof is an explicit, reproducible decision authority.  Conflicting
        # complete proofs must be visible for review rather than silently
        # following a model verdict or whichever branch happened to run first.
        review_reason = str(issue.get("review_disposition_reason") or "")
        review_forced = review_reason in {
            "rejection_refuted_unconfirmed",
            "positive_case_incomplete",
            "invalid_review_envelope",
            # M1: a replay escalation that started from ``uncertain`` and ended
            # ``verified`` is held for review instead of auto-confirming.
            "uncertain_confirm_hold",
        }
        conditional = issue.get("analysis_scope") == "conditional_source_branch"
        model_proof_conflict = bool(
            rejection_proof and verdict == "verified" and issue.get("review_adjudication")
        )
        if conditional or review_forced or model_proof_conflict:
            issue["validation_status"] = "needs_review"
            issue["candidate_disposition"] = "needs_review"
            issue["finding_kind"] = "needs_review"
            issue["evidence_conflict"] = model_proof_conflict
            issue["needs_review_sub_state"] = needs_review_sub_state(issue)
            issue["review_disposition_reason"] = (
                "conditional_build_facts_required"
                if conditional
                else (
                    "positive_negative_evidence_conflict" if model_proof_conflict else review_reason
                )
            )
            issue["validation_reasoning"] = val_data.get("reasoning")
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict="needs_review",
                final_score=final_score,
            )
        if confirmation_proof is not None and rejection_proof is not None:
            issue["validation_status"] = "needs_review"
            issue["candidate_disposition"] = "needs_review"
            issue["finding_kind"] = "needs_review"
            issue["evidence_conflict"] = True
            issue["needs_review_sub_state"] = needs_review_sub_state(issue)
            issue["promotion_review_reason"] = promotion_review_reason(
                issue, kind="evidence_conflict"
            )
            issue["validation_reasoning"] = (
                "完整的确定性确认证明与拒绝证明相互冲突，无法自动裁决，需要人工复核。"
            )
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict="needs_review",
                final_score=final_score,
            )
        if confirmation_proof is not None:
            issue["validation_status"] = "validated"
            issue["candidate_disposition"] = "confirmed"
            issue["finding_kind"] = val_data.get("finding_kind") or "verified_vulnerability"
            issue["decision_proof"] = confirmation_proof.to_dict()
            issue["promotion_reason"] = "deterministic_confirmation_proof"
            issue["proof_provider"] = confirmation_proof.producer_engine
            issue["proof_coverage"] = "complete"
            issue["validation_reasoning"] = val_data.get("reasoning")
            issue["confidence"] = val_data.get("confidence_score", issue.get("confidence", 0.5))
            self._copy_validator_detail_fields(issue, val_data)
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket="issues",
                memory_status="validated",
                verdict=verdict,
                final_score=final_score,
            )
        if rejection_proof is not None:
            issue["validation_status"] = "rejected"
            issue["candidate_disposition"] = "rejected_with_proof"
            issue["finding_kind"] = "rejected"
            issue["rejection_source"] = "deterministic_validator_proof"
            issue["deterministic_rejection"] = True
            issue["decision_proof"] = rejection_proof.to_dict()
            issue["proof_provider"] = rejection_proof.producer_engine
            issue["proof_coverage"] = "complete"
            issue["validation_reasoning"] = val_data.get("reasoning")
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket=None,
                memory_status="rejected",
                verdict=verdict,
                final_score=final_score,
            )
        if verdict == "verified" and (final_score >= 0.6 or confirmation_proof is not None):
            if confirmation_proof is not None or self._has_confirmed_evidence(
                issue,
                score_data,
                val_data,
            ):
                issue["validation_status"] = "validated"
                issue["candidate_disposition"] = "confirmed"
                issue["finding_kind"] = val_data.get("finding_kind") or "verified_vulnerability"
                if confirmation_proof is not None:
                    issue["decision_proof"] = confirmation_proof.to_dict()
                    issue["promotion_reason"] = "deterministic_confirmation_proof"
                report_bucket = "issues"
            else:
                issue["validation_status"] = "needs_review"
                issue["candidate_disposition"] = "needs_review"
                issue["finding_kind"] = "needs_review"
                issue["needs_review_sub_state"] = needs_review_sub_state(issue)
                issue["promotion_review_reason"] = promotion_review_reason(
                    issue,
                    kind="verified_unpromoted",
                    final_score=final_score,
                    val_data=val_data,
                    score_data=score_data,
                )
                report_bucket = "observations"

            issue["validation_reasoning"] = val_data.get("reasoning")
            issue["confidence"] = val_data.get(
                "confidence_score",
                issue.get("confidence", 0.5),
            )
            self._copy_validator_detail_fields(issue, val_data)
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket=report_bucket,
                memory_status=str(issue["validation_status"]),
                verdict=verdict,
                final_score=final_score,
            )

        if verdict == "verified":
            issue["validation_status"] = "needs_review"
            issue["candidate_disposition"] = "needs_review"
            issue["finding_kind"] = "needs_review"
            issue["needs_review_sub_state"] = needs_review_sub_state(issue)
            issue["promotion_review_reason"] = promotion_review_reason(
                issue,
                kind="verified_unpromoted",
                final_score=final_score,
                val_data=val_data,
                score_data=score_data,
            )
            issue["validation_reasoning"] = val_data.get("reasoning")
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict=verdict,
                final_score=final_score,
            )

        if verdict == "uncertain":
            issue["validation_reasoning"] = val_data.get("reasoning")
            self._copy_validator_detail_fields(issue, val_data)
            if self._high_confidence_uncertain_confirms(issue, val_data, final_score):
                issue["validation_status"] = "validated"
                issue["candidate_disposition"] = "confirmed"
                issue["finding_kind"] = val_data.get("finding_kind") or "verified_vulnerability"
                issue["promotion_reason"] = "model_high_confidence_confirmation"
                issue["confirmed_via"] = "high_confidence_band"
                preserve_issue_location(issue, val_data)
                return ValidationOutcome(
                    report_bucket="issues",
                    memory_status="validated",
                    verdict=verdict,
                    final_score=final_score,
                )
            issue["validation_status"] = "needs_review"
            issue["candidate_disposition"] = "needs_review"
            issue["finding_kind"] = "needs_review"
            issue["needs_review_sub_state"] = needs_review_sub_state(issue)
            issue["promotion_review_reason"] = promotion_review_reason(
                issue,
                kind="uncertain_unpromoted",
                final_score=final_score,
                val_data=val_data,
                uncertain_confirm_threshold=self.uncertain_confirm_threshold,
            )
            memory_status = "needs_review"
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket="observations",
                memory_status=memory_status,
                verdict=verdict,
                final_score=final_score,
            )

        corrected_category = self._corrected_category_from_validator(issue, val_data)
        if corrected_category:
            original_category = self.suppression_category(issue)
            issue["original_category"] = original_category
            issue["corrected_from_category"] = original_category
            pack = issue.get("evidence_pack")
            if isinstance(pack, dict):
                pack["original_category"] = original_category
                categories = pack.get("alternate_categories")
                if isinstance(categories, list):
                    if original_category not in categories:
                        categories.append(original_category)
                else:
                    pack["alternate_categories"] = [original_category]
            issue["category"] = corrected_category
            issue["subcategory"] = corrected_category
            issue["defect_class"] = corrected_category
            if corrected_category in _CWE_BY_CORRECTED_CATEGORY:
                issue["cwe"] = _CWE_BY_CORRECTED_CATEGORY[corrected_category]
            # The corrected CWE becomes the primary, but every previously
            # assigned CWE stays in the union so multi-CWE matching and the
            # report still see the original classification.
            ensure_issue_cwes(issue)
            issue["validator_verdict"] = "corrected"
            issue["validation_reasoning"] = (
                f"模型否决了原类别，但在同一代码证据上识别出具体的 `{corrected_category}` 问题。"
                f"模型原始推理：{str(val_data.get('reasoning') or '').strip()}"
            ).strip()
            issue["confidence"] = val_data.get(
                "confidence_score",
                issue.get("confidence", 0.5),
            )
            self._copy_validator_detail_fields(issue, val_data)
            preserve_issue_location(issue, val_data)
            corrected_status = (
                "validated"
                if self._corrected_category_is_high_confidence(val_data, final_score)
                else "needs_review"
            )
            issue["validation_status"] = corrected_status
            issue["candidate_disposition"] = (
                "confirmed" if corrected_status == "validated" else "needs_review"
            )
            issue["finding_kind"] = (
                "verified_vulnerability" if corrected_status == "validated" else "needs_review"
            )
            if corrected_status == "needs_review":
                issue["needs_review_sub_state"] = needs_review_sub_state(issue)
                issue["promotion_review_reason"] = promotion_review_reason(
                    issue,
                    kind="corrected_category_review",
                    final_score=final_score,
                    val_data=val_data,
                    corrected_category=corrected_category,
                )
            return ValidationOutcome(
                report_bucket="issues" if corrected_status == "validated" else "observations",
                memory_status=corrected_status,
                verdict="corrected",
                final_score=final_score,
            )

        if self._should_downgrade_structural_rejection(issue, val_data):
            original_reason = str(val_data.get("reasoning") or "").strip()
            issue["validation_status"] = "needs_review"
            issue["candidate_disposition"] = "needs_review"
            issue["finding_kind"] = "needs_review"
            issue["needs_review_sub_state"] = needs_review_sub_state(issue)
            issue["rejection_source"] = "validator_structural_review"
            issue["promotion_review_reason"] = promotion_review_reason(
                issue, kind="structural_rejection_review"
            )
            issue["validation_reasoning"] = (
                "该候选为结构性风险且具有具体代码证据，模型否决仅基于当前调用方可控性，"
                f"并未证明沉没点本身安全。模型原始推理：{original_reason}"
            ).strip()
            self._copy_validator_detail_fields(issue, val_data)
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict=verdict,
                final_score=final_score,
            )

        if rejection_proof is not None or self._has_deterministic_rejection_proof(issue, val_data):
            issue["validation_status"] = "rejected"
            issue["candidate_disposition"] = "rejected_with_proof"
            issue["finding_kind"] = "rejected"
            issue["rejection_source"] = "deterministic_validator_proof"
            issue["deterministic_rejection"] = True
            if rejection_proof is not None:
                issue["decision_proof"] = rejection_proof.to_dict()
            issue["validation_reasoning"] = val_data.get("reasoning")
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket=None,
                memory_status="rejected",
                verdict=verdict,
                final_score=final_score,
            )

        issue["validation_status"] = "needs_review"
        issue["candidate_disposition"] = "needs_review"
        issue["finding_kind"] = "needs_review"
        issue["needs_review_sub_state"] = needs_review_sub_state(issue)
        issue["rejection_source"] = "validator_without_deterministic_proof"
        issue["promotion_review_reason"] = promotion_review_reason(issue, kind="rejected_unproven")
        issue["validation_reasoning"] = (
            "模型否决该候选但未给出确定性反驳证明，候选保留待人工复核。"
            + str(val_data.get("reasoning") or "")
        ).strip()
        preserve_issue_location(issue, val_data)
        return ValidationOutcome(
            report_bucket="observations",
            memory_status="needs_review",
            verdict="needs_review",
            final_score=final_score,
        )

    def apply_validation_failure(
        self,
        issue: Dict[str, Any],
        error: Any,
    ) -> ValidationOutcome:
        """Close a failed Validator call as an operational obligation."""
        preserve_issue_location(issue)
        issue["validation_status"] = "engine_failed"
        issue["candidate_disposition"] = "engine_failed"
        issue.setdefault("finding_kind", "validation_engine_failed")
        issue["record_role"] = "operational_obligation"
        issue["engine_status"] = "failed"
        issue["validation_error"] = error
        return ValidationOutcome(
            report_bucket="observations",
            memory_status="engine_failed",
            verdict="engine_failed",
        )

    @staticmethod
    def _is_rollout_shadow_candidate(issue: Dict[str, Any]) -> bool:
        """Return true only for candidate-blind, shadow-only discoveries.

        A validation group may merge the same obligation from deterministic or
        backend producers.  Such a group must keep normal promotion authority;
        a shadow occurrence cannot suppress a real non-shadow candidate.
        """

        if str(issue.get("rollout_visibility") or "").lower() != "shadow":
            return False
        attribution = issue.get("attribution")
        discovered_by = attribution.get("discovered_by") if isinstance(attribution, dict) else None
        sources = {
            str(value).strip().lower()
            for value in (discovered_by if isinstance(discovered_by, list) else [])
            if str(value).strip()
        }
        if sources:
            return sources == {"llm_active_discovery"}
        return str(issue.get("candidate_source") or "").lower() == "active_discovery"

    @staticmethod
    def _has_confirmed_evidence(
        issue: Dict[str, Any],
        score_data: Dict[str, float],
        val_data: Dict[str, Any],
    ) -> bool:
        """Return whether a verified result has a complete promotion tier.

        A missing inter-procedural contract is not negative evidence.  The
        legacy score nevertheless assigns it the neutral value ``0.55`` and
        used to block every otherwise structured v3.1 verification.  Preserve
        the legacy tier for old candidates, and let v3.1 use an explicit,
        auditable tier that requires a hashed decision-fact slice and an
        explicit Validator statement that no *blocking* counter-fact exists.
        Free-form uncertainty remains reportable evidence; it is not treated
        as a deterministic contradiction.
        """
        try:
            final_score = float(score_data.get("final_score", 0.0) or 0.0)
            path = float(score_data.get("path_completeness", 0.0) or 0.0)
            contract = float(score_data.get("contract_consistency", 0.0) or 0.0)
            validator = float(score_data.get("validation_confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            return False
        negative = val_data.get("negative_evidence")
        has_negative = (
            bool(negative) if isinstance(negative, list) else bool(str(negative or "").strip())
        )
        if str(val_data.get("pass") or "") == "investigation_synthesis":
            closure = issue.get("v3_evidence_closure")
            if not isinstance(closure, dict) or closure.get("complete") is not True:
                return False
            closure_fact_uids = closure.get("fact_uids")
            resolved_kinds = closure.get("resolved_fact_kinds")
            if (
                not isinstance(closure_fact_uids, list)
                or not closure_fact_uids
                or not isinstance(resolved_kinds, list)
                or not resolved_kinds
            ):
                return False
        legacy_tier = bool(
            final_score >= 0.70
            and path >= 0.75
            and contract >= 0.70
            and validator >= 0.80
            and not has_negative
        )
        if legacy_tier:
            return True

        # v3.1 only: a structured fact slice means that a future report can
        # audit exactly the code snapshot that supported promotion.  Older
        # candidates cannot opt into this route by merely setting a score.
        if str(issue.get("decision_context_version") or "") not in {
            "zscope.decision-context.v3.1",
            "zscope.decision-context.v3.2",
            "zscope.decision-context.v3.3",
        }:
            return False
        fact_slice = issue.get("decision_fact_slice")
        if not isinstance(fact_slice, dict):
            return False
        fact_ids = fact_slice.get("fact_uids") or []
        code_hashes = fact_slice.get("dependency_code_hashes") or []
        coverage = str(issue.get("decision_fact_coverage") or fact_slice.get("coverage") or "")
        source = (
            issue.get("source_identity") or issue.get("canonical_source") or issue.get("source")
        )
        sink = issue.get("sink_identity") or issue.get("canonical_sink") or issue.get("sink")
        blocking = val_data.get("blocking_negative_evidence")
        if not isinstance(blocking, bool):
            return False
        return bool(
            final_score >= 0.75
            and path >= 0.75
            # 0.55 is the neutral default emitted when no cross-procedure
            # contract is available.  A lower value remains a negative signal.
            and contract >= 0.55
            and validator >= 0.80
            and blocking is False
            and coverage in {"complete", "partial"}
            and fact_ids
            and code_hashes
            and source not in (None, "", {}, [])
            and sink not in (None, "", {}, [])
            and not bool(issue.get("evidence_conflict"))
        )

    def _has_deterministic_rejection_proof(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> bool:
        verifier = self.deterministic_proof_verifier
        if verifier is None:
            return False
        try:
            return bool(verifier(issue, val_data))
        except Exception as exc:
            # A broken proof verifier must fail closed to needs_review.
            issue.setdefault("proof_verification_error", str(exc))
            return False

    @staticmethod
    def _final_score(score_data: Dict[str, float]) -> float:
        try:
            return float(score_data.get("final_score", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def _should_downgrade_structural_rejection(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> bool:
        category = self._normalized_category(issue)
        cwe = str(issue.get("cwe") or val_data.get("cwe") or "").lower()
        structural_categories = {
            "held_lock_callback",
            "size_limit_mismatch",
            "memory_leak",
            "double_free",
            "resource_lifecycle",
            "resource_leak",
            "resource_allocation_without_limits",
            "lock_protocol_violation",
            "unlock_without_lock",
            "fd_leak",
            "file_descriptor_leak",
            "missing_fd_release",
            "premature_destroy",
            "out_of_range_pointer_offset",
            "unsynchronized_shared_state",
            "state_inconsistency",
            "file_type_validation",
            "permission",
            "incorrect_permission_check",
            "deadlock",
            "race",
            "use_after_free",
            "protocol_validation",
            "bounds",
        }
        structural_cwes = {
            "cwe-772",
            "cwe-775",
            "cwe-832",
            "cwe-667",
            "cwe-770",
            "cwe-416",
            "cwe-823",
            "cwe-362",
            "cwe-732",
            "cwe-276",
            "cwe-20",
        }
        if category not in structural_categories and cwe not in structural_cwes:
            return False

        reason_text = self._flatten_for_validation(val_data)
        issue_text = self._flatten_for_validation(issue)
        combined = f"{reason_text}\n{issue_text}".lower()
        if self._has_strong_safety_disproof(category, combined):
            return False
        if category == "held_lock_callback" and not self._callback_under_lock_should_review(
            combined
        ):
            return False

        weak_reachability_reason = re.search(
            r"(?:current|currently|sample|example|specific caller|current caller|current callback|"
            r"not attacker[- ]controlled|cannot prove controll|no evidence of external|"
            r"当前|目前|样例|示例|当前调用|当前回调|不可控|无法证明|未证明|没有外部|缺少外部)",
            reason_text,
            re.IGNORECASE,
        )
        if not weak_reachability_reason:
            return False

        has_sink = self._has_concrete_sink(issue, val_data)
        has_path = self._has_reachable_path_evidence(issue)
        has_missing_guard_evidence = self._has_missing_guard_evidence(issue, val_data)
        if category in {
            "memory_leak",
            "resource_lifecycle",
            "resource_leak",
            "fd_leak",
            "file_descriptor_leak",
            "missing_fd_release",
        }:
            has_missing_guard_evidence = (
                has_missing_guard_evidence
                or "no matching" in issue_text
                or "without close" in issue_text
                or "without release" in issue_text
            )
        if category in {"lock_protocol_violation", "unlock_without_lock", "held_lock_callback"}:
            has_missing_guard_evidence = (
                has_missing_guard_evidence or "without" in issue_text or "under lock" in issue_text
            )
        if category == "file_type_validation":
            has_missing_guard_evidence = (
                has_missing_guard_evidence
                or "before type" in issue_text
                or "validation order" in issue_text
            )
        if category == "premature_destroy":
            has_missing_guard_evidence = (
                has_missing_guard_evidence or "active" in issue_text or "quiescence" in issue_text
            )
        if category in {"protocol_validation", "bounds"}:
            has_missing_guard_evidence = (
                has_missing_guard_evidence
                or "magic" in issue_text
                or "signature" in issue_text
                or "unchecked" in issue_text
            )
        if category in {"permission", "incorrect_permission_check"}:
            has_missing_guard_evidence = (
                has_missing_guard_evidence
                or "hard-coded mode" in issue_text
                or "requested permission" in issue_text
            )
        if category in {"unsynchronized_shared_state", "race", "deadlock"}:
            has_missing_guard_evidence = (
                has_missing_guard_evidence
                or "without" in issue_text
                or "lock" in issue_text
                or "synchronization" in issue_text
            )
        return bool(has_sink and has_path and has_missing_guard_evidence)

    def _should_keep_structural_uncertain_for_review(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> bool:
        category = self._normalized_category(issue)
        cwe = str(issue.get("cwe") or val_data.get("cwe") or "").lower()
        review_categories = {
            "premature_destroy",
            "resource_allocation_without_limits",
            "out_of_range_pointer_offset",
            "unsynchronized_shared_state",
            "state_inconsistency",
            "file_type_validation",
            "permission",
            "incorrect_permission_check",
            "deadlock",
            "race",
            "memory_leak",
            "resource_lifecycle",
            "double_free",
            "use_after_free",
            "protocol_validation",
            "bounds",
        }
        if category not in review_categories and cwe not in {
            "cwe-770",
            "cwe-772",
            "cwe-416",
            "cwe-823",
            "cwe-20",
            "cwe-362",
            "cwe-732",
            "cwe-276",
        }:
            return False
        combined = f"{self._flatten_for_validation(issue)}\n{self._flatten_for_validation(val_data)}".lower()
        if self._has_strong_safety_disproof(category, combined):
            return False
        has_missing_guard = self._has_missing_guard_evidence(issue, val_data)
        if category == "file_type_validation":
            has_missing_guard = (
                has_missing_guard or "before type" in combined or "validation order" in combined
            )
        if category == "premature_destroy":
            has_missing_guard = (
                has_missing_guard or "active" in combined or "quiescence" in combined
            )
        if category in {"protocol_validation", "bounds"}:
            has_missing_guard = (
                has_missing_guard
                or "magic" in combined
                or "signature" in combined
                or "unchecked" in combined
            )
        if category in {"permission", "incorrect_permission_check"}:
            has_missing_guard = (
                has_missing_guard
                or "hard-coded mode" in combined
                or "requested permission" in combined
            )
        if category in {"unsynchronized_shared_state", "race", "deadlock"}:
            has_missing_guard = (
                has_missing_guard
                or "without" in combined
                or "lock" in combined
                or "synchronization" in combined
            )
        return bool(
            self._has_concrete_sink(issue, val_data)
            and self._has_reachable_path_evidence(issue)
            and has_missing_guard
        )

    def _corrected_category_from_validator(
        self,
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> str:
        explicit = val_data.get("corrected_category")
        corrected_issue = val_data.get("corrected_issue")
        if not explicit and isinstance(corrected_issue, dict):
            explicit = corrected_issue.get("category") or corrected_issue.get("defect_class")
        explicit_category = self._normalize_corrected_category(explicit)
        if explicit_category:
            return explicit_category

        original = self._normalized_category(issue)
        text = self._flatten_for_validation(val_data).lower()
        if self._has_strong_safety_disproof(original, text) and not re.search(
            r"(?:actual|real|instead|rather than|实际|真正|而非|不是.*而是)",
            text,
            re.IGNORECASE,
        ):
            return ""

        if original == "alloc_free_mismatch" and re.search(
            r"(?:actual|real|instead|rather than|实际|真正|而非|不是.*而是|属于).*"
            r"(?:memory leak|leak|内存泄漏|未释放|不释放|no[- ]op free|noop_free|_noop_free|_runtime_noop_free)",
            text,
            re.IGNORECASE,
        ):
            return "memory_leak"
        if original in {"integer_overflow", "resource_allocation_without_limits"} and re.search(
            r"(?:actual|real|potential|instead|rather than|实际|真正|而非|不是.*而是).*"
            r"(?:heap buffer overflow|heap overflow|buffer overflow|堆.*溢出|缓冲区溢出)",
            text,
            re.IGNORECASE,
        ):
            return "heap_overflow"
        return ""

    @staticmethod
    def _normalize_corrected_category(value: Any) -> str:
        category = str(value or "").replace("-", "_").lower().strip()
        aliases = {
            "buffer_over_read": "buffer_overread",
            "buffer_under_read": "buffer_underread",
            "buffer_under_write": "buffer_underwrite",
            "resource_leak": "memory_leak",
        }
        category = aliases.get(category, category)
        return category if category in _CWE_BY_CORRECTED_CATEGORY else ""

    @staticmethod
    def _corrected_category_is_high_confidence(
        val_data: Dict[str, Any], final_score: float
    ) -> bool:
        text = ValidationPipeline._flatten_for_validation(val_data).lower()
        try:
            validator_confidence = float(val_data.get("confidence_score", 0) or 0)
        except (TypeError, ValueError):
            validator_confidence = 0.0
        strong_language = re.search(
            r"(?:confirmed|definite|actual|real|must|always|必然|明确|实际存在|真正存在|固定传入)",
            text,
            re.IGNORECASE,
        )
        return bool(strong_language and (validator_confidence >= 0.8 or final_score >= 0.72))

    def _normalized_category(self, issue: Dict[str, Any]) -> str:
        category = self.suppression_category(issue)
        return re.sub(r"[^a-z0-9]+", "_", category.lower()).strip("_")

    @staticmethod
    def _flatten_for_validation(value: Any) -> str:
        if isinstance(value, dict):
            return " ".join(
                ValidationPipeline._flatten_for_validation(item) for item in value.values()
            )
        if isinstance(value, list):
            return " ".join(ValidationPipeline._flatten_for_validation(item) for item in value)
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _has_concrete_sink(issue: Dict[str, Any], val_data: Dict[str, Any]) -> bool:
        evidence = _as_dict(issue.get("evidence_pack"))
        sink = _as_dict(evidence.get("sink"))
        sink_text = " ".join(
            str(value or "")
            for value in (
                issue.get("sink"),
                val_data.get("sink"),
                sink.get("operation"),
            )
        )
        if re.search(
            r"\b(?:free|close|unlock|pthread_mutex_unlock|memcpy|malloc|calloc|realloc|return|callback|->|\[|\*)",
            sink_text,
        ):
            return True
        return bool(sink_text.strip() and (issue.get("location") or sink.get("line")))

    @staticmethod
    def _has_reachable_path_evidence(issue: Dict[str, Any]) -> bool:
        evidence = _as_dict(issue.get("evidence_pack"))
        path = _as_dict(evidence.get("path"))
        if path.get("complete") is True or path.get("complete_in_function") is True:
            return True
        if path.get("current_analysis_entry") or path.get("entry") or path.get("function"):
            return True
        if issue.get("call_path") or issue.get("entry_func") or issue.get("function"):
            return True
        return bool(issue.get("location"))

    @staticmethod
    def _has_missing_guard_evidence(issue: Dict[str, Any], val_data: Dict[str, Any]) -> bool:
        evidence_text = " ".join(
            [
                ValidationPipeline._flatten_for_validation(issue.get("negative_evidence")),
                ValidationPipeline._flatten_for_validation(issue.get("positive_evidence")),
                ValidationPipeline._flatten_for_validation(val_data.get("guard_analysis")),
                ValidationPipeline._flatten_for_validation(issue.get("evidence_pack")),
            ]
        ).lower()
        return bool(
            re.search(
                r"(?:no |without |missing |lacks |lack |not checked|unchecked|no matching|"
                r"缺少|没有|未检查|无匹配|未释放|未关闭)",
                evidence_text,
            )
        )

    @staticmethod
    def _has_strong_safety_disproof(category: str, text: str) -> bool:
        generic_disproof = [
            r"\bno sink\b",
            r"\bsink (?:does not exist|is absent)\b",
            r"\bguard (?:dominates|covers|protects) all paths\b",
            r"\ball paths (?:are )?(?:guarded|protected|closed|released)\b",
            r"\bmatching (?:close|release|unlock)\b",
            r"\bownership (?:is )?(?:transferred|handed off|retained)\b",
            r"\bglobal owner\b",
            r"\blinked into (?:the )?global\b",
            r"\binserted into (?:the )?global\b",
            r"资源所有权.*(?:转移|保留)",
            r"所有路径.*(?:保护|释放|关闭|解锁)",
            r"guard.*支配",
            r"已插入.*全局",
            r"全局.*拥有",
        ]
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in generic_disproof):
            return True
        if category == "held_lock_callback":
            callback_disproof = [
                r"hardcoded empty callback",
                r"hard-coded empty callback",
                r"no-op callback",
                r"empty callback",
                r"callback is empty",
                r"empty and only local",
                r"callback .* only local",
                r"硬编码.*空回调",
                r"空回调",
                r"无外部替换路径",
            ]
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in callback_disproof):
                return True
        if category in {"lock_protocol_violation", "unlock_without_lock"}:
            lock_disproof = [
                r"caller (?:always )?holds (?:the )?lock",
                r"called only while .*lock.*held",
                r"same lock protocol is complete",
                r"调用者.*持有.*锁",
                r"同一锁协议.*完整",
            ]
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in lock_disproof):
                return True
        return False

    @staticmethod
    def _callback_under_lock_should_review(text: str) -> bool:
        if re.search(
            r"(?:hardcoded empty callback|hard-coded empty callback|no-op callback|empty callback|硬编码.*空回调|空回调)",
            text,
            re.IGNORECASE,
        ):
            return False
        return bool(
            re.search(
                r"(?:callback|handler|function pointer|registry|plugin|global function pointer|external parameter|"
                r"回调|函数指针|注册表|插件|外部参数|全局函数指针)",
                text,
                re.IGNORECASE,
            )
        )

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
        closure = issue.get("v3_evidence_closure")
        resolved = {
            str(value)
            for value in (
                (closure.get("resolved_fact_kinds") or []) if isinstance(closure, dict) else []
            )
            if str(value)
        }
        if (
            str(val_data.get("pass") or "") == "investigation_synthesis"
            and str(val_data.get("verdict") or "").lower() == "verified"
            and isinstance(closure, dict)
            and closure.get("complete") is True
            and "source_sink_reachability" in resolved
        ):
            # A cited, tool-backed V3 reachability fact is stronger than the
            # legacy source/sink-presence heuristic and must affect the policy
            # rerun that follows evidence closure.
            return 1.0
        evidence = _as_dict(issue.get("evidence_pack"))
        path = _as_dict(evidence.get("path"))
        if path.get("complete") is True or path.get("complete_in_function") is True:
            return 1.0
        if (issue.get("source") or val_data.get("source")) and (
            issue.get("sink") or val_data.get("sink")
        ):
            return 0.75
        if issue.get("evidence_refs"):
            return 0.7
        return 0.5

    @staticmethod
    def _contract_consistency_score(
        issue: Dict[str, Any],
        val_data: Dict[str, Any],
    ) -> float:
        closure = issue.get("v3_evidence_closure")
        resolved = {
            str(value)
            for value in (
                (closure.get("resolved_fact_kinds") or []) if isinstance(closure, dict) else []
            )
            if str(value)
        }
        contract_fact_kinds = {
            "caller_contract",
            "cleanup_coverage",
            "happens_before",
            "lockset",
            "ownership_transfer",
        }
        if (
            str(val_data.get("pass") or "") == "investigation_synthesis"
            and str(val_data.get("verdict") or "").lower() == "verified"
            and val_data.get("blocking_negative_evidence") is False
            and isinstance(closure, dict)
            and closure.get("complete") is True
            and bool(resolved & contract_fact_kinds)
            and not bool(issue.get("evidence_conflict"))
        ):
            # The V3 session has closed a concrete contract/protocol fact with
            # read-only tool evidence.  Leaving the score at the legacy 0.55
            # neutral default would mean the promotion-policy rerun ignores
            # the very facts it was asked to collect.
            return 0.8
        negative = issue.get("negative_evidence") or val_data.get("negative_evidence") or []
        if negative:
            return 0.55
        if (issue.get("source") or val_data.get("source")) and (
            issue.get("sink") or val_data.get("sink")
        ):
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


def preserve_issue_location(
    issue: Dict[str, Any],
    *extra_sources: Any,
) -> None:
    """Keep candidate source coordinates on observations after validation.

    Validator responses often only carry a verdict/reasoning.  The reportable
    object remains the original candidate, so recover missing top-level
    coordinates from its structured evidence before it is bucketed.
    """
    if not isinstance(issue, dict):
        return

    current = _location_from_issue(issue)
    sources: List[Any] = [issue]
    pack = issue.get("evidence_pack")
    if isinstance(pack, dict):
        sources.append(pack)
        candidate_evidence = pack.get("candidate_evidence")
        if isinstance(candidate_evidence, dict):
            sources.append(candidate_evidence)
    sources.extend(source for source in extra_sources if source)
    _preserve_location_detail_fields(issue, sources)

    recovered = current
    for candidate in _iter_location_candidates(sources):
        recovered = _merge_location(recovered, candidate)
        if recovered.file_path and recovered.start_line is not None:
            break

    if not recovered.file_path and current.file_path:
        recovered.file_path = current.file_path
    if recovered.start_line is None and current.start_line is not None:
        recovered.start_line = current.start_line
    if recovered.end_line is None and current.end_line is not None:
        recovered.end_line = current.end_line

    if recovered.file_path:
        if not issue.get("file"):
            issue["file"] = recovered.file_path
        if not issue.get("file_path"):
            issue["file_path"] = recovered.file_path
        if not issue.get("location") and recovered.start_line is not None:
            issue["location"] = _format_location(recovered)
    if recovered.start_line is not None:
        if not issue.get("line"):
            issue["line"] = recovered.start_line
        if not issue.get("start_line"):
            issue["start_line"] = recovered.start_line
    if recovered.end_line is not None:
        if not issue.get("end_line"):
            issue["end_line"] = recovered.end_line

    if issue.get("location"):
        parsed_file, parsed_line = parse_issue_location(str(issue.get("location") or ""))
        if parsed_file and parsed_line:
            if not issue.get("file"):
                issue["file"] = parsed_file
            if not issue.get("file_path"):
                issue["file_path"] = parsed_file
            if not issue.get("line"):
                issue["line"] = parsed_line
            if not issue.get("start_line"):
                issue["start_line"] = parsed_line


def _preserve_location_detail_fields(issue: Dict[str, Any], sources: Iterable[Any]) -> None:
    for field in LOCATION_STRING_FIELDS:
        if issue.get(field):
            continue
        value = _find_first_field(sources, field)
        if value not in (None, ""):
            issue[field] = value


def _find_first_field(values: Iterable[Any], field: str, *, depth: int = 0) -> Any:
    if depth > 5:
        return None
    for value in values:
        if isinstance(value, dict):
            if field in value and value.get(field) not in (None, ""):
                return value.get(field)
            found = _find_first_field(value.values(), field, depth=depth + 1)
            if found not in (None, ""):
                return found
        elif isinstance(value, list):
            found = _find_first_field(value[:40], field, depth=depth + 1)
            if found not in (None, ""):
                return found
    return None


@dataclass
class _LocationCandidate:
    file_path: str = ""
    start_line: Optional[int] = None
    end_line: Optional[int] = None


def _location_from_issue(issue: Dict[str, Any]) -> _LocationCandidate:
    location = _parse_location_text(str(issue.get("location") or ""))
    for key in LOCATION_FILE_FIELDS:
        file_value = _coerce_file(issue.get(key))
        if file_value and not location.file_path:
            location.file_path = file_value
    for key in LOCATION_LINE_FIELDS:
        line_value = _coerce_int(issue.get(key))
        if line_value is not None and location.start_line is None:
            location.start_line = line_value
    for key in LOCATION_END_LINE_FIELDS:
        line_value = _coerce_int(issue.get(key))
        if line_value is not None and location.end_line is None:
            location.end_line = line_value
    return location


def _iter_location_candidates(
    values: Iterable[Any], *, depth: int = 0
) -> Iterable[_LocationCandidate]:
    if depth > 5:
        return
    for value in values:
        if isinstance(value, dict):
            candidate = _location_from_mapping(value)
            if candidate.file_path or candidate.start_line is not None:
                yield candidate
            yield from _iter_location_candidates(value.values(), depth=depth + 1)
        elif isinstance(value, list):
            yield from _iter_location_candidates(value[:40], depth=depth + 1)
        elif isinstance(value, str):
            candidate = _parse_location_text(value)
            if candidate.file_path or candidate.start_line is not None:
                yield candidate


def _location_from_mapping(value: Dict[str, Any]) -> _LocationCandidate:
    candidate = _LocationCandidate()
    for key in LOCATION_STRING_FIELDS:
        if key in value:
            candidate = _merge_location(candidate, _parse_location_text(str(value.get(key) or "")))
    for key in LOCATION_FILE_FIELDS:
        file_value = _coerce_file(value.get(key))
        if file_value and not candidate.file_path:
            candidate.file_path = file_value
    for key in LOCATION_LINE_FIELDS:
        line_value = _coerce_int(value.get(key))
        if line_value is not None and candidate.start_line is None:
            candidate.start_line = line_value
    for key in LOCATION_END_LINE_FIELDS:
        line_value = _coerce_int(value.get(key))
        if line_value is not None and candidate.end_line is None:
            candidate.end_line = line_value
    return candidate


def _parse_location_text(value: str) -> _LocationCandidate:
    text = value.replace("\\", "/").strip()
    if not text:
        return _LocationCandidate()
    file_path, line = parse_issue_location(text)
    end_line = None
    if file_path and line is not None:
        match = re.search(r":\s*\d+\s*-\s*(\d+)", text)
        if match:
            end_line = _coerce_int(match.group(1))
        return _LocationCandidate(file_path=file_path, start_line=line, end_line=end_line)
    if line is not None:
        match = re.search(r"^\s*\d+\s*-\s*(\d+)\s*$", text)
        return _LocationCandidate(
            start_line=line, end_line=_coerce_int(match.group(1)) if match else None
        )

    match = re.search(
        r"((?:src|include|internal)/[A-Za-z0-9_./-]+\.[chp]+|[A-Za-z0-9_./-]+\.[chp]+)"
        r"(?:[^\d\n\r]{0,24})(\d+)(?:\s*-\s*(\d+))?",
        text,
        flags=re.IGNORECASE,
    )
    if match:
        return _LocationCandidate(
            file_path=match.group(1).lower(),
            start_line=_coerce_int(match.group(2)),
            end_line=_coerce_int(match.group(3)),
        )
    return _LocationCandidate()


def _merge_location(base: _LocationCandidate, incoming: _LocationCandidate) -> _LocationCandidate:
    return _LocationCandidate(
        file_path=base.file_path or incoming.file_path,
        start_line=base.start_line if base.start_line is not None else incoming.start_line,
        end_line=base.end_line if base.end_line is not None else incoming.end_line,
    )


def _format_location(location: _LocationCandidate) -> str:
    if location.start_line is None:
        return location.file_path
    if location.end_line is not None and location.end_line != location.start_line:
        return f"{location.file_path}:{location.start_line}-{location.end_line}"
    return f"{location.file_path}:{location.start_line}"


def _coerce_file(value: Any) -> str:
    text = str(value or "").replace("\\", "/").strip()
    if re.search(r"\.[chp]+$", text, flags=re.IGNORECASE):
        return text.lower()
    parsed_file, _line = parse_issue_location(text)
    return parsed_file


def _coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None
