"""Single v4 terminal authority for validation-cluster dispositions.

Live and resume decisions require an exact content-addressed chain:
``FrozenProofState -> ProofClosureEvaluation -> PromotionCertificate``.
Legacy v3 decisions remain readable for offline audit, but can never authorize
a new terminal transition.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Literal, Mapping, Optional

from .proof_kernel.closure import (
    FrozenProofState,
    PromotionCertificate,
    ProofClosureEvaluation,
    validate_promotion_binding,
)


TERMINAL_AUTHORITY_DECISION_V4 = "zscope.terminal-authority-decision.v4"
LEGACY_TERMINAL_AUTHORITY_DECISION_V3 = "zscope.terminal-authority-decision.v3"

AuthorityOperation = Literal["live", "resume", "audit"]


@dataclass(frozen=True)
class TerminalAuthorityDecision:
    terminal: bool
    disposition: str
    reason_code: str
    authority: str
    next_action: str = ""
    conflict_resolution: Optional[Dict[str, Any]] = None
    checker_result_refs: tuple[str, ...] = ()
    proof_root_sha256: str = ""
    integrity_status: str = ""
    proof_state_sha256: str = ""
    closure_evaluation_sha256: str = ""
    obligation_uid: str = ""
    obligation_sha256: str = ""
    proof_ir_uid: str = ""
    proof_ir_sha256: str = ""
    validation_cluster_uid: str = ""
    promotion_certificate: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        value = {"schema_version": TERMINAL_AUTHORITY_DECISION_V4, **asdict(self)}
        # Terminal decisions are persisted in JSON and then audited again.
        # Keep the materialized projection JSON-canonical so a round trip does
        # not turn tuple-valued refs into a false integrity mismatch.
        value["checker_result_refs"] = list(self.checker_result_refs)
        return value


def terminal_decision_from_promotion(
    *,
    proof_kernel_input: Mapping[str, Any],
    frozen_state: FrozenProofState | Mapping[str, Any],
    closure_evaluation: ProofClosureEvaluation | Mapping[str, Any],
    promotion_certificate: PromotionCertificate | Mapping[str, Any],
) -> TerminalAuthorityDecision:
    """Build a v4 terminal only after independently re-running the reducer.

    Content hashes prove object integrity, not provenance.  A caller able to
    re-seal state, closure and promotion objects must therefore still fail
    unless the deterministic provider, Checker and reducer reproduce the same
    chain from the original sealed Proof IR, obligation and selection.
    """

    from .proof_kernel.engine import ProofKernelEngine

    recomputed = ProofKernelEngine().reevaluate_authority_input(proof_kernel_input)

    valid, reason = validate_promotion_binding(
        frozen_state=frozen_state,
        closure_evaluation=closure_evaluation,
        promotion_certificate=promotion_certificate,
    )
    if not valid:
        raise ValueError(reason)
    state = (
        frozen_state
        if isinstance(frozen_state, FrozenProofState)
        else FrozenProofState.from_mapping(frozen_state)
    )
    closure = (
        closure_evaluation
        if isinstance(closure_evaluation, ProofClosureEvaluation)
        else ProofClosureEvaluation.from_mapping(closure_evaluation)
    )
    promotion = (
        promotion_certificate
        if isinstance(promotion_certificate, PromotionCertificate)
        else PromotionCertificate.from_mapping(promotion_certificate)
    )
    if (
        state != recomputed.frozen_state
        or closure != recomputed.closure_evaluation
        or recomputed.promotion_certificate is None
        or promotion != recomputed.promotion_certificate
    ):
        raise ValueError("promotion_reducer_revalidation_mismatch")
    if promotion.disposition == "confirmed":
        reason_code = "CONFIRMED_DETERMINISTIC_PROOF"
    elif promotion.disposition == "rejected_with_proof":
        reason_code = "REJECTED_DETERMINISTIC_COUNTERPROOF"
    else:  # pragma: no cover - PromotionCertificate validates this first.
        raise ValueError("promotion_disposition_invalid")
    return TerminalAuthorityDecision(
        terminal=True,
        disposition=promotion.disposition,
        reason_code=reason_code,
        authority="zscope.proof-checker",
        checker_result_refs=promotion.checker_result_refs,
        proof_root_sha256=promotion.proof_root_sha256,
        integrity_status="verified",
        proof_state_sha256=state.content_sha256,
        closure_evaluation_sha256=closure.content_sha256,
        obligation_uid=promotion.obligation_uid,
        obligation_sha256=promotion.obligation_sha256,
        proof_ir_uid=promotion.proof_ir_uid,
        proof_ir_sha256=promotion.proof_ir_sha256,
        validation_cluster_uid=promotion.validation_cluster_uid,
        promotion_certificate=promotion.to_dict(),
    )


def _bound_incomplete_closure(
    state: FrozenProofState,
    closure: ProofClosureEvaluation,
) -> bool:
    return bool(
        closure.proof_state_sha256 == state.content_sha256
        and closure.obligation_uid == state.obligation_uid
        and closure.obligation_sha256 == state.obligation_sha256
        and closure.proof_ir_uid == state.proof_ir_uid
        and closure.proof_ir_sha256 == state.proof_ir_sha256
        and closure.proof_root_sha256 == state.root_manifest_sha256
        and closure.checker_result_refs == state.checker_result_refs
        and closure.disposition == "needs_review"
        and closure.complete is False
    )


class TerminalAuthorityEvaluator:
    """Authorize v4 promotion or return an explicit fail-closed decision."""

    def evaluate(
        self,
        issue: Mapping[str, Any],
        *,
        model_result: Optional[Mapping[str, Any]] = None,
        has_executable_action: bool = False,
        protocol_or_engine_failure: bool = False,
        operation: AuthorityOperation = "live",
    ) -> TerminalAuthorityDecision:
        if operation not in {"live", "resume", "audit"}:
            raise ValueError("terminal_authority_operation_invalid")

        raw_state = issue.get("proof_kernel_frozen_state")
        raw_closure = issue.get("proof_kernel_closure_evaluation")
        raw_promotion = issue.get("proof_kernel_promotion_certificate")
        raw_input = issue.get("proof_kernel_input")
        engine_decision = issue.get("proof_kernel_terminal_authority_decision")

        state: Optional[FrozenProofState] = None
        closure: Optional[ProofClosureEvaluation] = None
        try:
            if isinstance(raw_state, Mapping):
                state = FrozenProofState.from_mapping(raw_state)
            if isinstance(raw_closure, Mapping):
                closure = ProofClosureEvaluation.from_mapping(raw_closure)
        except (KeyError, TypeError, ValueError):
            protocol_or_engine_failure = True
            state = None
            closure = None

        if (
            state is not None or closure is not None or isinstance(raw_promotion, Mapping)
        ) and not (isinstance(raw_input, Mapping)):
            protocol_or_engine_failure = True

        if (
            state is not None
            and closure is not None
            and isinstance(raw_promotion, Mapping)
            and isinstance(raw_input, Mapping)
        ):
            try:
                authorized = terminal_decision_from_promotion(
                    proof_kernel_input=raw_input,
                    frozen_state=state,
                    closure_evaluation=closure,
                    promotion_certificate=raw_promotion,
                )
            except (KeyError, TypeError, ValueError):
                protocol_or_engine_failure = True
            else:
                # A materialized decision must be the exact deterministic
                # projection. A missing decision is fine: this evaluator owns
                # the projection from the promotion chain.
                if engine_decision is None or (
                    isinstance(engine_decision, Mapping)
                    and dict(engine_decision) == authorized.to_dict()
                ):
                    return authorized
                protocol_or_engine_failure = True

        reducer_bound_incomplete = False
        if (
            state is not None
            and closure is not None
            and isinstance(raw_input, Mapping)
            and not isinstance(raw_promotion, Mapping)
        ):
            try:
                from .proof_kernel.engine import ProofKernelEngine

                recomputed = ProofKernelEngine().reevaluate_authority_input(raw_input)
                reducer_bound_incomplete = bool(
                    recomputed.frozen_state == state
                    and recomputed.closure_evaluation == closure
                    and recomputed.promotion_certificate is None
                )
                if not reducer_bound_incomplete:
                    protocol_or_engine_failure = True
            except (KeyError, TypeError, ValueError):
                protocol_or_engine_failure = True

        if (
            isinstance(engine_decision, Mapping)
            and str(engine_decision.get("schema_version") or "")
            == LEGACY_TERMINAL_AUTHORITY_DECISION_V3
        ):
            return TerminalAuthorityDecision(
                terminal=True,
                disposition="needs_review",
                reason_code=(
                    "NEEDS_REVIEW_LEGACY_AUTHORITY_AUDIT_ONLY"
                    if operation == "audit"
                    else "NEEDS_REVIEW_LEGACY_AUTHORITY_NOT_AUTHORIZED"
                ),
                authority="terminal_authority_evaluator",
                integrity_status="legacy_audit_only",
                conflict_resolution={
                    "status": "historical_only",
                    "recorded_disposition": str(engine_decision.get("disposition") or ""),
                    "model_vote_used": False,
                },
            )

        if (
            state is not None
            and closure is not None
            and reducer_bound_incomplete
            and _bound_incomplete_closure(state, closure)
        ):
            if has_executable_action:
                return TerminalAuthorityDecision(
                    terminal=False,
                    disposition="needs_review",
                    reason_code="V0_UNRESOLVED",
                    authority="terminal_authority_evaluator",
                    next_action="continue_validation",
                    checker_result_refs=closure.checker_result_refs,
                    proof_root_sha256=closure.proof_root_sha256,
                    integrity_status=closure.integrity_status,
                    proof_state_sha256=state.content_sha256,
                    closure_evaluation_sha256=closure.content_sha256,
                    obligation_uid=state.obligation_uid,
                    obligation_sha256=state.obligation_sha256,
                    proof_ir_uid=state.proof_ir_uid,
                    proof_ir_sha256=state.proof_ir_sha256,
                    validation_cluster_uid=state.validation_cluster_uid,
                )
            reason_code = (
                "NEEDS_REVIEW_EVIDENCE_CONFLICT"
                if closure.reason_code == "programmatic_proof_conflict"
                else "NEEDS_REVIEW_OPEN_CLAUSES"
            )
            if closure.integrity_status != "verified" or closure.failure_codes:
                reason_code = "NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE"
            return TerminalAuthorityDecision(
                terminal=True,
                disposition="needs_review",
                reason_code=reason_code,
                authority="terminal_authority_evaluator",
                checker_result_refs=closure.checker_result_refs,
                proof_root_sha256=closure.proof_root_sha256,
                integrity_status=closure.integrity_status,
                proof_state_sha256=state.content_sha256,
                closure_evaluation_sha256=closure.content_sha256,
                obligation_uid=state.obligation_uid,
                obligation_sha256=state.obligation_sha256,
                proof_ir_uid=state.proof_ir_uid,
                proof_ir_sha256=state.proof_ir_sha256,
                validation_cluster_uid=state.validation_cluster_uid,
            )

        result = model_result if isinstance(model_result, Mapping) else {}
        verdict = str(result.get("verdict") or issue.get("model_verdict") or "").lower()
        if has_executable_action and not protocol_or_engine_failure:
            return TerminalAuthorityDecision(
                terminal=False,
                disposition="needs_review",
                reason_code="V0_UNRESOLVED",
                authority="terminal_authority_evaluator",
                next_action="continue_validation",
            )
        if protocol_or_engine_failure:
            reason = "NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE"
        elif verdict == "rejected":
            reason = "NEEDS_REVIEW_MODEL_REJECT_NO_PROOF"
        else:
            reason = "NEEDS_REVIEW_OPEN_CLAUSES"
        return TerminalAuthorityDecision(
            terminal=True,
            disposition="needs_review",
            reason_code=reason,
            authority="terminal_authority_evaluator",
        )

    def replay(self, issue: Mapping[str, Any], model_result: Mapping[str, Any]) -> Dict[str, Any]:
        return self.evaluate(issue, model_result=model_result, operation="audit").to_dict()


__all__ = [
    "LEGACY_TERMINAL_AUTHORITY_DECISION_V3",
    "TERMINAL_AUTHORITY_DECISION_V4",
    "TerminalAuthorityDecision",
    "TerminalAuthorityEvaluator",
    "terminal_decision_from_promotion",
]
