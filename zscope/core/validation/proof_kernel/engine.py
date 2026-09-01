"""Unified, model-independent authoritative Proof Engine evaluation."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, Mapping, MutableMapping, Optional, Sequence, Tuple

from .canonical import content_sha256
from .checker import ProofChecker
from .closure import (
    FrozenProofState,
    PromotionCertificate,
    ProofClosureEvaluation,
    freeze_proof_state,
    issue_promotion_certificate,
    reduce_proof_closure,
)
from .lifecycle import PROOF_KERNEL_MODE, require_authoritative_mode
from .models import build_evidence_action, validate_obligation, validate_program_ir
from .provider import ProofProvider
from .registry import PREDICATE_REGISTRY
from .store import ProofArtifactStore


PROOF_KERNEL_AUTHORITY_INPUT_VERSION = "zscope.proof-kernel-authority-input.v1"


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
    frozen_state: FrozenProofState
    closure_evaluation: ProofClosureEvaluation
    promotion_certificate: Optional[PromotionCertificate]
    proof_ir: Dict[str, Any]
    obligation: Dict[str, Any]
    selected_action_uids: Tuple[str, ...]

    def authority_inputs(self) -> Dict[str, Any]:
        """Return the exact v4 artifacts consumed by TerminalAuthority."""

        return {
            "proof_kernel_input": {
                "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
                "proof_ir": deepcopy(self.proof_ir),
                "proof_obligation": deepcopy(self.obligation),
                "selected_action_uids": list(self.selected_action_uids),
            },
            "proof_kernel_frozen_state": self.frozen_state.to_dict(),
            "proof_kernel_closure_evaluation": self.closure_evaluation.to_dict(),
            **(
                {"proof_kernel_promotion_certificate": (self.promotion_certificate.to_dict())}
                if self.promotion_certificate is not None
                else {}
            ),
        }

    def apply_to_issue(self, issue: MutableMapping[str, Any]) -> None:
        """Atomically replace stale authority inputs on a mutable issue.

        A non-terminal re-evaluation deliberately removes any older promotion
        and materialized authority decision so resume/V3 cannot retain a
        certificate issued for a different closure.
        """

        projected = self.authority_inputs()
        issue["proof_kernel_input"] = projected["proof_kernel_input"]
        issue["proof_kernel_frozen_state"] = projected["proof_kernel_frozen_state"]
        issue["proof_kernel_closure_evaluation"] = projected["proof_kernel_closure_evaluation"]
        if self.promotion_certificate is None:
            issue.pop("proof_kernel_promotion_certificate", None)
        else:
            issue["proof_kernel_promotion_certificate"] = projected[
                "proof_kernel_promotion_certificate"
            ]
        issue.pop("proof_kernel_terminal_authority_decision", None)


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

    def reevaluate_authority_input(
        self,
        value: Mapping[str, Any],
    ) -> ProofKernelEvaluation:
        """Re-run the deterministic provider, Checker and sole reducer.

        TerminalAuthority, resume and replay use this entry point instead of
        trusting a self-consistent set of caller-supplied state/closure hashes.
        The method deliberately accepts no stored action, certificate or
        Checker-result objects: all of them are regenerated from the sealed IR,
        obligation and exact selected action identities.
        """

        if set(value) != {
            "schema_version",
            "proof_ir",
            "proof_obligation",
            "selected_action_uids",
        }:
            raise ValueError("proof_kernel_authority_input_fields_invalid")
        if value.get("schema_version") != PROOF_KERNEL_AUTHORITY_INPUT_VERSION:
            raise ValueError("proof_kernel_authority_input_version_invalid")
        proof_ir = value.get("proof_ir")
        obligation = value.get("proof_obligation")
        selected = value.get("selected_action_uids")
        if not isinstance(proof_ir, Mapping) or not isinstance(obligation, Mapping):
            raise ValueError("proof_kernel_authority_input_artifacts_required")
        if not isinstance(selected, list) or any(not isinstance(item, str) for item in selected):
            raise ValueError("proof_kernel_authority_input_selection_invalid")
        normalized = tuple(str(item) for item in selected)
        if len(normalized) != len(set(normalized)):
            raise ValueError("proof_kernel_authority_input_selection_duplicate")
        return self._evaluate(
            proof_ir=proof_ir,
            obligation=obligation,
            selected_action_uids=normalized,
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
        frozen_state = freeze_proof_state(
            proof_ir=proof_ir,
            obligation=obligation,
            action_catalog=tuple(catalog),
            selected_action_uids=tuple(str(value["action_uid"]) for value in executable),
            check_results=tuple(results),
            checker_result_refs=tuple(checker_refs),
            root_manifest_sha256=root_manifest_sha256,
        )
        closure_evaluation = reduce_proof_closure(
            frozen_state=frozen_state,
            proof_ir=proof_ir,
            obligation=obligation,
            action_catalog=tuple(catalog),
            check_results=tuple(results),
        )
        promotion_certificate = None
        if closure_evaluation.complete:
            promotion_certificate = issue_promotion_certificate(
                frozen_state=frozen_state,
                closure_evaluation=closure_evaluation,
            )
        return ProofKernelEvaluation(
            schema_version="zscope.proof-kernel-evaluation.v1",
            proof_kernel_mode=self.mode,
            decision=closure_evaluation.disposition,
            reason_code=closure_evaluation.reason_code,
            actions=tuple(actions),
            certificates=tuple(certificates),
            check_results=tuple(results),
            artifact_refs=tuple(refs),
            checker_result_refs=tuple(checker_refs),
            root_manifest_sha256=root_manifest_sha256,
            frozen_state=frozen_state,
            closure_evaluation=closure_evaluation,
            promotion_certificate=promotion_certificate,
            proof_ir=deepcopy(dict(proof_ir)),
            obligation=deepcopy(dict(obligation)),
            selected_action_uids=tuple(str(value["action_uid"]) for value in executable),
        )
