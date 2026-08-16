"""Single terminal authority for validation-cluster dispositions.

This module does not trust a model verdict as proof.  It normalizes the
existing deterministic proof, evidence-closure, and promotion decisions into
one explicit stop/continue decision that can be replayed from frozen facts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Mapping, Optional


@dataclass(frozen=True)
class TerminalAuthorityDecision:
    terminal: bool
    disposition: str
    reason_code: str
    authority: str
    next_action: str = ""
    conflict_resolution: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProofConflictResolver:
    """Reject stale or scope-incompatible proofs; never let an LLM arbitrate."""

    def resolve(self, issue: Mapping[str, Any]) -> Dict[str, Any]:
        positive = self._proof(issue, "positive")
        negative = self._proof(issue, "negative")
        if positive is None or negative is None:
            return {"status": "not_applicable", "valid_positive": False, "valid_negative": False}
        positive_valid, positive_reason = self._valid_for_issue(positive, issue)
        negative_valid, negative_reason = self._valid_for_issue(negative, issue)
        status = "unresolved"
        winner = ""
        if positive_valid and not negative_valid:
            status, winner = "resolved", "positive"
        elif negative_valid and not positive_valid:
            status, winner = "resolved", "negative"
        elif not positive_valid and not negative_valid:
            status = "invalid_both"
        return {
            "status": status,
            "winner": winner,
            "valid_positive": positive_valid,
            "valid_negative": negative_valid,
            "positive_reason": positive_reason,
            "negative_reason": negative_reason,
            "subject_uid": str(issue.get("subject_uid") or issue.get("resource_identity") or ""),
            "decision_region_uid": str(issue.get("decision_region_uid") or ""),
        }

    @staticmethod
    def _proof(issue: Mapping[str, Any], polarity: str) -> Optional[Mapping[str, Any]]:
        keys = (
            ("positive_decision_proof", "confirmation_proof")
            if polarity == "positive"
            else ("negative_decision_proof", "rejection_proof", "counterproof")
        )
        for key in keys:
            value = issue.get(key)
            if isinstance(value, Mapping):
                return value
        proof = issue.get("decision_proof")
        if isinstance(proof, Mapping):
            proof_polarity = str(proof.get("polarity") or proof.get("decision") or "").lower()
            if polarity == "positive" and proof_polarity in {"positive", "confirm", "confirmed"}:
                return proof
            if polarity == "negative" and proof_polarity in {"negative", "reject", "rejected"}:
                return proof
        return None

    @staticmethod
    def _valid_for_issue(proof: Mapping[str, Any], issue: Mapping[str, Any]) -> tuple[bool, str]:
        coverage = str(proof.get("coverage") or proof.get("proof_coverage") or "").lower()
        if coverage != "complete":
            return False, "proof_incomplete"
        if proof.get("dependency_valid") is False or proof.get("scope_valid") is False:
            return False, "proof_scope_or_dependency_invalid"
        issue_subject = str(issue.get("subject_uid") or issue.get("resource_identity") or "")
        proof_subject = str(proof.get("subject_uid") or proof.get("resource_identity") or "")
        if issue_subject and proof_subject and issue_subject != proof_subject:
            return False, "proof_subject_mismatch"
        issue_region = str(issue.get("decision_region_uid") or "")
        proof_region = str(proof.get("decision_region_uid") or "")
        if issue_region and proof_region and issue_region != proof_region:
            return False, "proof_region_mismatch"
        issue_hash = str(issue.get("dependency_code_hash") or issue.get("code_snapshot_hash") or "")
        proof_hash = str(proof.get("dependency_code_hash") or proof.get("code_snapshot_hash") or "")
        if issue_hash and proof_hash and issue_hash != proof_hash:
            return False, "proof_dependency_hash_mismatch"
        return True, "valid"


class TerminalAuthorityEvaluator:
    """Return the first terminal authority or an explicit next action."""

    def __init__(self, conflict_resolver: Optional[ProofConflictResolver] = None) -> None:
        self.conflict_resolver = conflict_resolver or ProofConflictResolver()

    def evaluate(
        self,
        issue: Mapping[str, Any],
        *,
        model_result: Optional[Mapping[str, Any]] = None,
        has_executable_action: bool = False,
        protocol_or_engine_failure: bool = False,
    ) -> TerminalAuthorityDecision:
        conflict = bool(issue.get("evidence_conflict")) or self._has_both_proofs(issue)
        if conflict:
            resolution = self.conflict_resolver.resolve(issue)
            winner = str(resolution.get("winner") or "")
            if winner == "positive":
                return TerminalAuthorityDecision(
                    True,
                    "confirmed",
                    "CONFIRMED_DETERMINISTIC_PROOF",
                    "proof_conflict_resolver",
                    conflict_resolution=resolution,
                )
            if winner == "negative":
                return TerminalAuthorityDecision(
                    True,
                    "rejected_with_proof",
                    "REJECTED_DETERMINISTIC_COUNTERPROOF",
                    "proof_conflict_resolver",
                    conflict_resolution=resolution,
                )
            if has_executable_action:
                return TerminalAuthorityDecision(
                    False,
                    "needs_review",
                    "PROOF_CONFLICT",
                    "proof_conflict_resolver",
                    next_action="targeted_conflict_investigation",
                    conflict_resolution=resolution,
                )
            return TerminalAuthorityDecision(
                True,
                "needs_review",
                "NEEDS_REVIEW_EVIDENCE_CONFLICT",
                "proof_conflict_resolver",
                conflict_resolution=resolution,
            )

        proof = issue.get("decision_proof")
        proof = proof if isinstance(proof, Mapping) else {}
        proof_complete = (
            str(
                issue.get("proof_coverage")
                or proof.get("coverage")
                or proof.get("proof_coverage")
                or ""
            ).lower()
            == "complete"
        )
        disposition = str(issue.get("candidate_disposition") or "").lower()
        if proof_complete and disposition == "confirmed":
            return TerminalAuthorityDecision(
                True,
                "confirmed",
                "CONFIRMED_DETERMINISTIC_PROOF",
                "deterministic_proof",
            )
        if proof_complete and disposition == "rejected_with_proof":
            return TerminalAuthorityDecision(
                True,
                "rejected_with_proof",
                "REJECTED_DETERMINISTIC_COUNTERPROOF",
                "deterministic_counterproof",
            )

        result = model_result if isinstance(model_result, Mapping) else {}
        verdict = str(result.get("verdict") or issue.get("model_verdict") or "").lower()
        # Read-only compatibility for archived/third-party v2 adapters.  New
        # product calls always carry ValidatorResult v3 and therefore cannot
        # use this bridge to bypass evidence closure.
        if result and str(result.get("schema_version") or "") != "zscope.validator-result.v3":
            if disposition == "confirmed" and verdict in {"verified", "confirmed"}:
                return TerminalAuthorityDecision(
                    True,
                    "confirmed",
                    "CONFIRMED_VERIFIED_CLOSURE",
                    "legacy_validator_policy_compat",
                )
        closure = issue.get("v3_evidence_closure") or issue.get("evidence_closure_state")
        closure = closure if isinstance(closure, Mapping) else {}
        closure_complete = bool(closure.get("complete"))
        open_clauses = closure.get("remaining_fact_kinds") or issue.get("missing_fact_kinds") or []
        conflicting = closure.get("conflicting_fact_kinds") or []
        promotion = disposition == "confirmed" and not open_clauses and not conflicting
        if verdict == "verified" and closure_complete and promotion:
            return TerminalAuthorityDecision(
                True,
                "confirmed",
                "CONFIRMED_VERIFIED_CLOSURE",
                "verified_evidence_closure",
            )
        if has_executable_action:
            return TerminalAuthorityDecision(
                False,
                disposition or "needs_review",
                "V0_UNRESOLVED",
                "terminal_authority_evaluator",
                next_action="continue_validation",
            )
        if protocol_or_engine_failure:
            reason = "NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE"
        elif verdict == "rejected":
            reason = "NEEDS_REVIEW_MODEL_REJECT_NO_PROOF"
        elif verdict == "verified":
            reason = "NEEDS_REVIEW_VERIFIED_BUT_PROMOTION_BLOCKED"
        else:
            reason = "NEEDS_REVIEW_OPEN_CLAUSES"
        return TerminalAuthorityDecision(
            True,
            "needs_review",
            reason,
            "terminal_authority_evaluator",
        )

    def replay(self, issue: Mapping[str, Any], model_result: Mapping[str, Any]) -> Dict[str, Any]:
        return self.evaluate(issue, model_result=model_result).to_dict()

    @staticmethod
    def _has_both_proofs(issue: Mapping[str, Any]) -> bool:
        return bool(
            (issue.get("positive_decision_proof") or issue.get("confirmation_proof"))
            and (
                issue.get("negative_decision_proof")
                or issue.get("rejection_proof")
                or issue.get("counterproof")
            )
        )
