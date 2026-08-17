"""Independent certificate checker for the P2 proof protocol."""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Sequence

from .canonical import seal_mapping
from .models import (
    PROOF_CHECK_RESULT_VERSION,
    PROTOCOL_REVISION,
    validate_action,
    validate_certificate_envelope,
    validate_obligation,
    validate_program_ir,
)
from .registry import (
    ALLOWED_ASSUMPTION_IDS,
    POLARITY_ROLE_TERMINAL_MATRIX,
    PREDICATE_REGISTRY,
    evaluate_predicate,
)


class ProofChecker:
    """Recompute a predicate and reject every identity or coverage mismatch."""

    checker_id = "zscope.proof-checker"
    checker_version = "v2"

    def check(
        self,
        *,
        proof_ir: Mapping[str, Any],
        obligation: Mapping[str, Any],
        action: Mapping[str, Any],
        certificate: Mapping[str, Any],
    ) -> Dict[str, Any]:
        certificate_uid = str(certificate.get("certificate_uid") or "")
        base = {
            "certificate_uid": certificate_uid,
            "action_uid": str(action.get("action_uid") or certificate.get("action_uid") or ""),
            "obligation_uid": str(
                obligation.get("obligation_uid") or certificate.get("obligation_uid") or ""
            ),
            "clause_uid": str(certificate.get("clause_uid") or action.get("clause_uid") or ""),
            "proof_ir_uid": str(
                proof_ir.get("proof_ir_uid") or certificate.get("proof_ir_uid") or ""
            ),
        }
        valid, reason = validate_program_ir(proof_ir)
        if not valid:
            return self._result(base, "rejected", "invalid", (reason,))
        valid, reason = validate_obligation(obligation)
        if not valid:
            return self._result(base, "rejected", "invalid", (reason,))
        valid, reason = validate_action(action)
        if not valid:
            return self._result(base, "rejected", "invalid", (reason,))
        valid, reason = validate_certificate_envelope(certificate)
        if not valid:
            status = "legacy_preview" if reason == "legacy_preview" else "invalid"
            return self._result(base, "rejected", status, (reason,))

        clause = self._clause(obligation, str(action.get("clause_uid") or ""))
        if clause is None:
            return self._result(base, "rejected", "invalid", ("action_clause_not_in_obligation",))
        identity_error = self._identity_error(proof_ir, obligation, clause, action, certificate)
        if identity_error:
            return self._result(base, "rejected", "invalid", (identity_error,))

        spec = PREDICATE_REGISTRY.get(str(action.get("predicate_id") or ""))
        if spec is None:
            return self._result(base, "rejected", "invalid", ("predicate_not_registered",))
        if (
            spec.provider_family != clause.get("provider_family")
            or spec.fact_kind != clause.get("fact_kind")
            or spec.quantifier != clause.get("quantifier")
            or spec.provider_id != action.get("provider_id")
            or spec.verifier_id != action.get("verifier_id")
            or certificate.get("provider_version") != "v2"
        ):
            return self._result(base, "rejected", "invalid", ("predicate_registry_mismatch",))
        parameters = action.get("fixed_parameters")
        if not isinstance(parameters, Mapping) or set(parameters) != set(spec.parameter_keys):
            return self._result(base, "rejected", "invalid", ("fixed_parameter_schema_mismatch",))
        if dict(parameters) != dict(clause.get("parameters") or {}):
            return self._result(base, "rejected", "invalid", ("fixed_parameter_clause_mismatch",))
        assumptions = [str(value) for value in certificate.get("assumption_ids") or []]
        if any(value not in ALLOWED_ASSUMPTION_IDS for value in assumptions):
            return self._result(base, "rejected", "invalid", ("assumption_not_allowlisted",))

        evaluation = evaluate_predicate(proof_ir=proof_ir, clause=clause, action=action)
        comparisons = {
            "status": evaluation.status,
            "predicate_value": evaluation.predicate_value,
            "witness": evaluation.witness,
            "coverage": evaluation.coverage,
            "assumption_ids": list(evaluation.assumption_ids),
        }
        for key, expected in comparisons.items():
            if certificate.get(key) != expected:
                return self._result(
                    base,
                    "rejected",
                    str(certificate.get("status") or "invalid"),
                    (f"certificate_{key}_recompute_mismatch",),
                    coverage=evaluation.coverage,
                )
        if evaluation.status == "unknown" and any(
            certificate.get("witness", {}).get(key)
            for key in ("cfg_nodes", "cfg_edges", "path_node_uids", "exit_node_uids", "values")
        ):
            return self._result(base, "rejected", "unknown", ("unknown_certificate_has_witness",))
        if evaluation.status != "verified_true" or evaluation.coverage.get("complete") is not True:
            status = "conflicting" if evaluation.status == "conflicting" else "unknown"
            return self._result(
                base,
                status,
                evaluation.status,
                (evaluation.reason_code,),
                coverage=evaluation.coverage,
            )

        role = str(clause.get("role") or "")
        expected_polarity = "supports" if role == "confirmation" else "refutes"
        if certificate.get("predicate_polarity") != expected_polarity:
            return self._result(base, "rejected", "verified_true", ("polarity_role_mismatch",))
        # RequiredFactPlan may ask the checker to capture a derived fact
        # without asserting how that fact decides the vulnerability. Such a
        # fact can close the fact request, but cannot become terminal proof.
        expected_value = clause.get("expected_value")
        derived_fact_only = (
            isinstance(expected_value, Mapping)
            and set(expected_value) == {"$derived"}
            and expected_value.get("$derived") is True
        )
        contribution = (
            "none"
            if derived_fact_only
            else POLARITY_ROLE_TERMINAL_MATRIX.get((role, expected_polarity), "none")
        )
        fact = {
            "fact_uid": "FACT_CERT_" + str(certificate["content_sha256"])[:32],
            "fact_kind": spec.fact_kind,
            "predicate_id": spec.predicate_id,
            "value": evaluation.predicate_value,
            "status": "verified_true",
            "subject_uid": str(obligation.get("subject_uid") or ""),
            "decision_region_uid": str(obligation.get("decision_region_uid") or ""),
            "provider_id": spec.provider_id,
            "verifier_id": self.checker_id,
            "certificate_sha256": str(certificate.get("content_sha256") or ""),
            "satisfies_fact_kinds": [spec.fact_kind],
            "origin": "proof_checker_v2",
        }
        return self._result(
            base,
            "accepted",
            "verified_true",
            (evaluation.reason_code,),
            contribution=contribution,
            coverage=evaluation.coverage,
            fact=fact,
        )

    def _result(
        self,
        base: Mapping[str, Any],
        status: str,
        certificate_status: str,
        reason_codes: Sequence[str],
        *,
        contribution: str = "none",
        coverage: Optional[Mapping[str, Any]] = None,
        fact: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "schema_version": PROOF_CHECK_RESULT_VERSION,
            "protocol_revision": PROTOCOL_REVISION,
            "checker_id": self.checker_id,
            "checker_version": self.checker_version,
            **dict(base),
            "status": status,
            "certificate_status": certificate_status,
            "reason_codes": sorted({str(value) for value in reason_codes if str(value)})
            or ["unknown"],
            "terminal_contribution": contribution,
            "recomputed_coverage": dict(coverage or {}),
            "accepted_fact": dict(fact) if fact is not None else None,
        }
        return seal_mapping(payload, uid_field="check_uid", prefix="PCHECK_")

    @staticmethod
    def _clause(obligation: Mapping[str, Any], clause_uid: str) -> Optional[Mapping[str, Any]]:
        for key in ("confirmation_clauses", "counterproof_clauses"):
            for value in obligation.get(key) or []:
                if isinstance(value, Mapping) and value.get("clause_uid") == clause_uid:
                    return value
        return None

    @staticmethod
    def _identity_error(
        proof_ir: Mapping[str, Any],
        obligation: Mapping[str, Any],
        clause: Mapping[str, Any],
        action: Mapping[str, Any],
        certificate: Mapping[str, Any],
    ) -> str:
        exact = {
            "proof_ir_uid": proof_ir.get("proof_ir_uid"),
            "obligation_uid": obligation.get("obligation_uid"),
            "clause_uid": clause.get("clause_uid"),
            "provider_family": clause.get("provider_family"),
            "predicate_id": clause.get("predicate_id"),
            "fact_kind": clause.get("fact_kind"),
            "quantifier": clause.get("quantifier"),
            "subject_uid": obligation.get("subject_uid"),
            "decision_region_uid": obligation.get("decision_region_uid"),
        }
        for key, expected in exact.items():
            if action.get(key) != expected or certificate.get(key) != expected:
                return f"{key}_identity_mismatch"
        action_exact = {
            "action_uid": action.get("action_uid"),
            "provider_id": action.get("provider_id"),
            "verifier_id": action.get("verifier_id"),
        }
        for key, expected in action_exact.items():
            if certificate.get(key) != expected:
                return f"certificate_{key}_mismatch"
        dependencies = sorted(str(value) for value in proof_ir.get("dependency_hashes") or [])
        if (
            sorted(str(value) for value in obligation.get("dependency_hashes") or [])
            != dependencies
        ):
            return "obligation_dependency_hash_mismatch"
        if sorted(str(value) for value in action.get("dependency_hashes") or []) != dependencies:
            return "action_dependency_hash_mismatch"
        if (
            sorted(str(value) for value in certificate.get("dependency_hashes") or [])
            != dependencies
        ):
            return "certificate_dependency_hash_mismatch"
        functions = proof_ir.get("functions") or []
        summary = functions[0] if len(functions) == 1 and isinstance(functions[0], Mapping) else {}
        if certificate.get("code_sha256") != summary.get("code_sha256"):
            return "certificate_code_hash_mismatch"
        if certificate.get("backend_sha256") != summary.get("backend_sha256"):
            return "certificate_backend_hash_mismatch"
        if certificate.get("ir_sha256") != proof_ir.get("content_sha256"):
            return "certificate_ir_hash_mismatch"
        return ""
