"""Unified, model-independent Proof Engine shadow evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

from .checker import ProofChecker
from .lifecycle import PROOF_KERNEL_MODE, assert_shadow_mode
from .models import build_evidence_action, validate_obligation, validate_program_ir
from .provider import ProofProvider
from .registry import PREDICATE_REGISTRY
from .store import ProofArtifactStore


@dataclass(frozen=True)
class ProofKernelEvaluation:
    proof_kernel_mode: str
    shadow_decision: str
    reason_code: str
    actions: Tuple[Dict[str, Any], ...]
    certificates: Tuple[Dict[str, Any], ...]
    check_results: Tuple[Dict[str, Any], ...]
    artifact_refs: Tuple[str, ...]


class ProofKernelEngine:
    """Run every frozen clause through one registry, provider and checker."""

    def __init__(
        self,
        *,
        mode: str = PROOF_KERNEL_MODE,
        checker: Optional[ProofChecker] = None,
        provider: Optional[ProofProvider] = None,
        store: Optional[ProofArtifactStore] = None,
    ) -> None:
        assert_shadow_mode(mode)
        self.mode = mode
        self.checker = checker or ProofChecker()
        self.provider = provider or ProofProvider()
        self.store = store

    def evaluate(
        self,
        *,
        proof_ir: Mapping[str, Any],
        obligation: Mapping[str, Any],
    ) -> ProofKernelEvaluation:
        for value, validator in (
            (proof_ir, validate_program_ir),
            (obligation, validate_obligation),
        ):
            valid, reason = validator(value)
            if not valid:
                raise ValueError(reason)
        actions = []
        certificates = []
        results = []
        refs = []
        if self.store is not None:
            refs.append(self.store.put("program_proof_ir", proof_ir))
            refs.append(self.store.put("proof_obligation", obligation, dependency_refs=refs[:1]))
        for bucket in ("confirmation_clauses", "counterproof_clauses"):
            for clause in obligation.get(bucket) or []:
                spec = PREDICATE_REGISTRY.get(str(clause.get("predicate_id") or ""))
                if spec is None:
                    continue
                action = build_evidence_action(
                    obligation=obligation,
                    clause=clause,
                    proof_ir=proof_ir,
                    provider_id=spec.provider_id,
                    verifier_id=spec.verifier_id,
                )
                certificate = self.provider.produce(
                    proof_ir=proof_ir, obligation=obligation, action=action
                )
                result = self.checker.check(
                    proof_ir=proof_ir,
                    obligation=obligation,
                    action=action,
                    certificate=certificate,
                )
                actions.append(action)
                certificates.append(certificate)
                results.append(result)
                if self.store is not None:
                    action_ref = self.store.put("evidence_action", action, dependency_refs=refs[:2])
                    certificate_ref = self.store.put(
                        "evidence_certificate", certificate, dependency_refs=(action_ref,)
                    )
                    check_ref = self.store.put(
                        "proof_check_result", result, dependency_refs=(certificate_ref,)
                    )
                    refs.extend((action_ref, certificate_ref, check_ref))
        decision, reason = self._shadow_closure(obligation, tuple(results))
        if self.store is not None:
            self.store.write_root_manifest(refs)
        return ProofKernelEvaluation(
            proof_kernel_mode=self.mode,
            shadow_decision=decision,
            reason_code=reason,
            actions=tuple(actions),
            certificates=tuple(certificates),
            check_results=tuple(results),
            artifact_refs=tuple(refs),
        )

    @staticmethod
    def _shadow_closure(
        obligation: Mapping[str, Any], results: Tuple[Mapping[str, Any], ...]
    ) -> tuple[str, str]:
        accepted_confirmation = {
            str(value.get("clause_uid") or "")
            for value in results
            if value.get("status") == "accepted"
            and value.get("terminal_contribution") == "confirmation"
        }
        accepted_counterproof = {
            str(value.get("clause_uid") or "")
            for value in results
            if value.get("status") == "accepted"
            and value.get("terminal_contribution") == "counterproof"
        }
        required_confirmation = {
            str(value.get("clause_uid") or "")
            for value in obligation.get("confirmation_clauses") or []
            if value.get("required") is True
        }
        if accepted_confirmation and accepted_counterproof:
            return "needs_review", "programmatic_proof_conflict"
        if accepted_counterproof:
            return "rejected", "verified_counterproof"
        if obligation.get("open_clauses"):
            return "needs_review", "open_or_unknown_proof_clause"
        if required_confirmation and required_confirmation <= accepted_confirmation:
            return "confirmed", "verified_confirmation_proof"
        return "needs_review", "open_or_unknown_proof_clause"
