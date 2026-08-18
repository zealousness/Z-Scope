"""Validation-stage suppression and review-memory helpers."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, cast

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
                        "Candidate was evaluated during semantic/discovery shadow rollout; "
                        "its proof result is retained as telemetry and cannot enter the "
                        "default finding view."
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
                    "validation_reasoning": (
                        "Conflicting complete deterministic confirmation and rejection proofs "
                        "require human review."
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
            or "static validation gate"
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
            issue["validation_reasoning"] = (
                "Shadow discovery candidate was retained without promotion because "
                "Validator was disabled."
            )
            return ValidationOutcome(
                report_bucket=None,
                verdict="shadow_observation",
                final_score=final_score,
            )
        issue["validation_status"] = "needs_review"
        issue["candidate_disposition"] = "needs_review"
        issue.setdefault("finding_kind", "needs_review")
        issue["score_components"] = score_data
        final_score = self._final_score(score_data)
        issue["final_score"] = final_score
        return ValidationOutcome(
            report_bucket="observations",
            verdict="needs_review",
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
        if confirmation_proof is not None and rejection_proof is not None:
            issue["validation_status"] = "needs_review"
            issue["candidate_disposition"] = "needs_review"
            issue["finding_kind"] = "needs_review"
            issue["evidence_conflict"] = True
            issue["validation_reasoning"] = (
                "Conflicting complete deterministic confirmation and rejection proofs "
                "require human review."
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
            issue["validation_reasoning"] = val_data.get("reasoning")
            preserve_issue_location(issue, val_data)
            return ValidationOutcome(
                report_bucket="observations",
                memory_status="needs_review",
                verdict=verdict,
                final_score=final_score,
            )

        if verdict == "uncertain":
            issue["validation_status"] = "needs_review"
            issue["candidate_disposition"] = "needs_review"
            issue["finding_kind"] = "needs_review"
            memory_status = "needs_review"
            issue["validation_reasoning"] = val_data.get("reasoning")
            self._copy_validator_detail_fields(issue, val_data)
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
            issue["validator_verdict"] = "corrected"
            issue["validation_reasoning"] = (
                "Validator rejected the original category but identified a concrete "
                f"`{corrected_category}` on the same code evidence. Original validator reasoning: "
                f"{str(val_data.get('reasoning') or '').strip()}"
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
            issue["rejection_source"] = "validator_structural_review"
            issue["validation_reasoning"] = (
                "Validator rejected this structural-risk candidate, but the candidate has "
                "concrete code evidence and the rejection is based on current controllability "
                f"rather than proof that the sink is safe. Original validator reasoning: {original_reason}"
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
        issue["rejection_source"] = "validator_without_deterministic_proof"
        issue["validation_reasoning"] = (
            "Validator proposed rejection without a deterministic contradiction; "
            "the candidate remains reviewable. " + str(val_data.get("reasoning") or "")
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
