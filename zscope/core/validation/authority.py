"""Single terminal authority for validation-cluster dispositions.

This module does not trust a model verdict or a legacy proof field.  It accepts
only a strict decision emitted after the Proof Checker replays frozen facts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Dict, Mapping, Optional


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

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": "zscope.terminal-authority-decision.v3", **asdict(self)}


class TerminalAuthorityEvaluator:
    """Return the Proof Engine terminal or an explicit next action.

    Pre-P5 issue flags, model verdicts and legacy certificate previews are not
    proof.  Live callers must attach a programmatically constructed
    ``proof_kernel_terminal_authority_decision``.
    """

    def evaluate(
        self,
        issue: Mapping[str, Any],
        *,
        model_result: Optional[Mapping[str, Any]] = None,
        has_executable_action: bool = False,
        protocol_or_engine_failure: bool = False,
    ) -> TerminalAuthorityDecision:
        engine_decision = issue.get("proof_kernel_terminal_authority_decision")
        if isinstance(engine_decision, Mapping):
            schema_version = str(engine_decision.get("schema_version") or "")
            authority = str(engine_decision.get("authority") or "")
            disposition = str(engine_decision.get("disposition") or "")
            reason = str(engine_decision.get("reason_code") or "")
            terminal = engine_decision.get("terminal") is True
            checker_refs = tuple(
                str(value)
                for value in engine_decision.get("checker_result_refs") or []
                if str(value)
            )
            proof_root = str(engine_decision.get("proof_root_sha256") or "")
            integrity_status = str(engine_decision.get("integrity_status") or "")
            allowed = {
                "confirmed": "CONFIRMED_DETERMINISTIC_PROOF",
                "rejected_with_proof": "REJECTED_DETERMINISTIC_COUNTERPROOF",
                "needs_review": None,
            }
            reason_allowed = (
                reason == allowed.get(disposition)
                if allowed.get(disposition) is not None
                else reason
                in {
                    "NEEDS_REVIEW_OPEN_CLAUSES",
                    "NEEDS_REVIEW_EVIDENCE_CONFLICT",
                    "NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",
                }
            )
            proof_integrity_valid = bool(
                disposition == "needs_review"
                or (
                    integrity_status == "verified"
                    and checker_refs
                    and all(re.fullmatch(r"sha256:[0-9a-f]{64}", ref) for ref in checker_refs)
                    and re.fullmatch(r"[0-9a-f]{64}", proof_root)
                )
            )
            if (
                terminal
                and schema_version == "zscope.terminal-authority-decision.v3"
                and authority in {"zscope.proof-checker", "zscope.proof-checker-conflict-resolver"}
                and disposition in allowed
                and reason_allowed
                and proof_integrity_valid
            ):
                conflict = engine_decision.get("conflict_resolution")
                return TerminalAuthorityDecision(
                    True,
                    disposition,
                    reason,
                    authority,
                    conflict_resolution=(dict(conflict) if isinstance(conflict, Mapping) else None),
                    checker_result_refs=checker_refs,
                    proof_root_sha256=proof_root,
                    integrity_status=integrity_status,
                )

        result = model_result if isinstance(model_result, Mapping) else {}
        verdict = str(result.get("verdict") or issue.get("model_verdict") or "").lower()
        if has_executable_action:
            return TerminalAuthorityDecision(
                False,
                "needs_review",
                "V0_UNRESOLVED",
                "terminal_authority_evaluator",
                next_action="continue_validation",
            )
        if protocol_or_engine_failure:
            reason = "NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE"
        elif verdict == "rejected":
            reason = "NEEDS_REVIEW_MODEL_REJECT_NO_PROOF"
        elif verdict == "verified":
            reason = "NEEDS_REVIEW_OPEN_CLAUSES"
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
