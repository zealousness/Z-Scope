"""Deterministic certificate proposals for the finite P2 predicate registry."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from .canonical import seal_mapping
from .models import (
    EVIDENCE_CERTIFICATE_VERSION,
    PROTOCOL_REVISION,
    validate_action,
    validate_obligation,
    validate_program_ir,
)
from .registry import PREDICATE_REGISTRY, evaluate_predicate


class ProofProvider:
    """Propose a replayable certificate; never decide whether it is trusted."""

    provider_version = "v2"

    def produce(
        self,
        *,
        proof_ir: Mapping[str, Any],
        obligation: Mapping[str, Any],
        action: Mapping[str, Any],
    ) -> Dict[str, Any]:
        for value, validator in (
            (proof_ir, validate_program_ir),
            (obligation, validate_obligation),
            (action, validate_action),
        ):
            valid, reason = validator(value)
            if not valid:
                raise ValueError(reason)
        clause = self._clause(obligation, str(action["clause_uid"]))
        if clause is None:
            raise ValueError("action_clause_not_in_obligation")
        spec = PREDICATE_REGISTRY.get(str(action["predicate_id"]))
        if spec is None:
            raise ValueError("predicate_not_registered")
        evaluation = evaluate_predicate(proof_ir=proof_ir, clause=clause, action=action)
        functions = proof_ir.get("functions") or []
        summary = functions[0] if len(functions) == 1 and isinstance(functions[0], Mapping) else {}
        polarity = "supports" if clause.get("role") == "confirmation" else "refutes"
        payload = {
            "schema_version": EVIDENCE_CERTIFICATE_VERSION,
            "protocol_revision": PROTOCOL_REVISION,
            "action_uid": str(action["action_uid"]),
            "obligation_uid": str(obligation["obligation_uid"]),
            "clause_uid": str(clause["clause_uid"]),
            "proof_ir_uid": str(proof_ir["proof_ir_uid"]),
            "provider_family": spec.provider_family,
            "provider_id": spec.provider_id,
            "provider_version": self.provider_version,
            "verifier_id": spec.verifier_id,
            "predicate_id": spec.predicate_id,
            "fact_kind": spec.fact_kind,
            "status": evaluation.status,
            "predicate_polarity": polarity,
            "quantifier": spec.quantifier,
            "subject_uid": str(obligation["subject_uid"]),
            "decision_region_uid": str(obligation["decision_region_uid"]),
            "predicate_value": evaluation.predicate_value,
            "witness": evaluation.witness,
            "coverage": evaluation.coverage,
            "assumption_ids": list(evaluation.assumption_ids),
            "code_sha256": str(summary.get("code_sha256") or ""),
            "ir_sha256": str(proof_ir["content_sha256"]),
            "backend_sha256": str(summary.get("backend_sha256") or ""),
            "dependency_hashes": list(proof_ir.get("dependency_hashes") or []),
        }
        return seal_mapping(payload, uid_field="certificate_uid", prefix="CERT_")

    @staticmethod
    def _clause(obligation: Mapping[str, Any], clause_uid: str) -> Mapping[str, Any] | None:
        for bucket in ("confirmation_clauses", "counterproof_clauses"):
            for clause in obligation.get(bucket) or []:
                if isinstance(clause, Mapping) and clause.get("clause_uid") == clause_uid:
                    return clause
        return None
