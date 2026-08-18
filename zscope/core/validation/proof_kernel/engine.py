"""Unified, model-independent authoritative Proof Engine evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .canonical import content_sha256
from .checker import ProofChecker
from .lifecycle import PROOF_KERNEL_MODE, require_authoritative_mode
from .models import build_evidence_action, validate_obligation, validate_program_ir
from .provider import ProofProvider
from .registry import PREDICATE_REGISTRY
from .store import ProofArtifactStore


@dataclass(frozen=True)
class ProofKernelEvaluation:
    schema_version: str
    proof_kernel_mode: str
    decision: str
    reason_code: str
    actions: Tuple[Dict[str, Any], ...]
    certificates: Tuple[Dict[str, Any], ...]
    check_results: Tuple[Dict[str, Any], ...]
    artifact_refs: Tuple[str, ...]
    checker_result_refs: Tuple[str, ...]
    root_manifest_sha256: str


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
        require_authoritative_mode(mode)
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
        """Evaluate every executable frozen clause (the P2 compatibility path)."""

        return self._evaluate(
            proof_ir=proof_ir,
            obligation=obligation,
            selected_action_uids=None,
        )

    def action_catalog(
        self,
        *,
        proof_ir: Mapping[str, Any],
        obligation: Mapping[str, Any],
    ) -> Tuple[Dict[str, Any], ...]:
        """Return the only EvidenceAction values a model may select."""

        for value, validator in (
            (proof_ir, validate_program_ir),
            (obligation, validate_obligation),
        ):
            valid, reason = validator(value)
            if not valid:
                raise ValueError(reason)
        actions = []
        for bucket in ("confirmation_clauses", "counterproof_clauses"):
            for clause in obligation.get(bucket) or []:
                spec = PREDICATE_REGISTRY.get(str(clause.get("predicate_id") or ""))
                if spec is None:
                    continue
                actions.append(
                    build_evidence_action(
                        obligation=obligation,
                        clause=clause,
                        proof_ir=proof_ir,
                        provider_id=spec.provider_id,
                        verifier_id=spec.verifier_id,
                    )
                )
        return tuple(actions)

    def evaluate_selected_actions(
        self,
        *,
        proof_ir: Mapping[str, Any],
        obligation: Mapping[str, Any],
        selected_action_uids: Sequence[str],
    ) -> ProofKernelEvaluation:
        """Execute only system-generated action IDs selected by the P4 Hunter.

        The input intentionally accepts identifiers rather than action objects,
        so a model cannot submit a predicate, fixed parameter or coverage claim.
        """

        normalized = [str(value) for value in selected_action_uids]
        if not normalized or any(not value for value in normalized):
            raise ValueError("selected_evidence_action_ids_required")
        if len(normalized) != len(set(normalized)):
            raise ValueError("duplicate_selected_evidence_action_id")
        return self._evaluate(
            proof_ir=proof_ir,
            obligation=obligation,
            selected_action_uids=tuple(normalized),
        )

    def _evaluate(
        self,
        *,
        proof_ir: Mapping[str, Any],
        obligation: Mapping[str, Any],
        selected_action_uids: Optional[Sequence[str]],
    ) -> ProofKernelEvaluation:
        catalog = self.action_catalog(proof_ir=proof_ir, obligation=obligation)
        by_uid = {str(value["action_uid"]): value for value in catalog}
        if selected_action_uids is None:
            executable = list(catalog)
        else:
            unknown = sorted(set(map(str, selected_action_uids)) - set(by_uid))
            if unknown:
                raise ValueError("selected_evidence_action_not_in_frozen_catalog")
            selected = set(map(str, selected_action_uids))
            # Preserve the deterministic obligation/clause order rather than
            # trusting model-provided ordering as execution policy.
            executable = [value for value in catalog if str(value["action_uid"]) in selected]

        actions = []
        certificates = []
        results = []
        refs = []
        checker_refs = []
        if self.store is not None:
            refs.append(self.store.put("program_proof_ir", proof_ir))
            refs.append(self.store.put("proof_obligation", obligation, dependency_refs=refs[:1]))
        for action in executable:
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
                checker_refs.append(check_ref)
        decision, reason = self._authoritative_closure(
            obligation,
            tuple(results),
            executable_action_uids={str(value["action_uid"]) for value in executable},
            catalog=tuple(catalog),
        )
        if self.store is not None:
            root_manifest = self.store.write_root_manifest(refs)
            root_manifest_sha256 = str(root_manifest["content_sha256"])
        else:
            # The caller may persist these objects in its own immutable trace
            # store.  Even without a filesystem CAS, the evaluation remains
            # content-addressed and its root is deterministic.
            refs = [
                "sha256:" + content_sha256(value)
                for value in (proof_ir, obligation, *actions, *certificates, *results)
            ]
            checker_refs = ["sha256:" + content_sha256(value) for value in results]
            root_manifest_sha256 = content_sha256(
                {
                    "schema_version": "zscope.proof-root-manifest.v1",
                    "artifact_refs": sorted(set(refs)),
                    "checker_result_refs": sorted(set(checker_refs)),
                }
            )
        return ProofKernelEvaluation(
            schema_version="zscope.proof-kernel-evaluation.v1",
            proof_kernel_mode=self.mode,
            decision=decision,
            reason_code=reason,
            actions=tuple(actions),
            certificates=tuple(certificates),
            check_results=tuple(results),
            artifact_refs=tuple(refs),
            checker_result_refs=tuple(checker_refs),
            root_manifest_sha256=root_manifest_sha256,
        )

    @staticmethod
    def _authoritative_closure(
        obligation: Mapping[str, Any],
        results: Tuple[Mapping[str, Any], ...],
        *,
        executable_action_uids: set[str],
        catalog: Tuple[Mapping[str, Any], ...],
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
        required_counterproof = {
            str(value.get("clause_uid") or "")
            for value in obligation.get("counterproof_clauses") or []
            if value.get("required") is True
        }
        required_executable = {
            str(value.get("clause_uid") or "")
            for value in catalog
            if str(value.get("action_uid") or "") in executable_action_uids
        }
        selected_result_clauses = {str(value.get("clause_uid") or "") for value in results}
        all_required_executable = {
            str(value.get("clause_uid") or "")
            for value in catalog
            if str(value.get("clause_uid") or "") in (required_confirmation | required_counterproof)
        }
        # A model selection cannot turn an omitted executable required clause
        # into an implicit success. Every required action must have a Checker
        # result before an authoritative closure is possible.
        if not all_required_executable.issubset(required_executable):
            return "needs_review", "required_executable_clause_not_selected"
        if not required_executable.issubset(selected_result_clauses):
            return "needs_review", "required_executable_clause_not_checked"
        if accepted_confirmation and accepted_counterproof:
            return "needs_review", "programmatic_proof_conflict"
        if accepted_counterproof:
            return "rejected_with_proof", "verified_counterproof"
        if obligation.get("open_clauses"):
            return "needs_review", "open_or_unknown_proof_clause"
        if required_confirmation and required_confirmation <= accepted_confirmation:
            return "confirmed", "verified_confirmation_proof"
        return "needs_review", "open_or_unknown_proof_clause"
