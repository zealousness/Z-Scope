"""Content-addressed proof closure and promotion contracts.

The proof checker owns facts, but a collection of accepted facts is not by
itself a terminal proof.  This module freezes the exact proof input and is the
single reducer allowed to turn checker results into a complete proof closure.
Only a complete, verified closure can mint a promotion certificate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping, Sequence, Tuple, TypeVar

from .canonical import SHA256_RE, content_sha256, seal_mapping, verify_sealed_mapping
from .models import (
    validate_action,
    validate_check_result,
    validate_obligation,
    validate_program_ir,
)


FROZEN_PROOF_STATE_VERSION = "zscope.frozen-proof-state.v1"
PROOF_CLOSURE_EVALUATION_VERSION = "zscope.proof-closure-evaluation.v1"
PROMOTION_CERTIFICATE_VERSION = "zscope.promotion-certificate.v1"

_CHECK_REF_PREFIX = "sha256:"

_STATE_KEYS = frozenset(
    {
        "schema_version",
        "proof_state_uid",
        "obligation_uid",
        "obligation_sha256",
        "proof_ir_uid",
        "proof_ir_sha256",
        "validation_cluster_uid",
        "subject_uid",
        "decision_region_uid",
        "proof_ir_dependency_hashes",
        "obligation_dependency_hashes",
        "required_confirmation_clause_uids",
        "required_counterproof_clause_uids",
        "open_clause_uids",
        "catalog_action_uids",
        "catalog_clause_uids",
        "selected_action_uids",
        "checker_result_sha256s",
        "checker_result_refs",
        "root_manifest_sha256",
        "content_sha256",
    }
)

_CLOSURE_KEYS = frozenset(
    {
        "schema_version",
        "closure_uid",
        "proof_state_sha256",
        "obligation_uid",
        "obligation_sha256",
        "proof_ir_uid",
        "proof_ir_sha256",
        "proof_root_sha256",
        "disposition",
        "reason_code",
        "complete",
        "accepted_confirmation_clause_uids",
        "accepted_counterproof_clause_uids",
        "checked_clause_uids",
        "missing_clause_uids",
        "conflicting_clause_uids",
        "checker_result_refs",
        "integrity_status",
        "failure_codes",
        "content_sha256",
    }
)

_PROMOTION_KEYS = frozenset(
    {
        "schema_version",
        "promotion_uid",
        "disposition",
        "reason_code",
        "proof_state_sha256",
        "closure_evaluation_sha256",
        "obligation_uid",
        "obligation_sha256",
        "proof_ir_uid",
        "proof_ir_sha256",
        "validation_cluster_uid",
        "subject_uid",
        "decision_region_uid",
        "proof_root_sha256",
        "checker_result_refs",
        "integrity_status",
        "content_sha256",
    }
)


def _tuple_strings(values: Iterable[Any]) -> Tuple[str, ...]:
    return tuple(str(value) for value in values)


def _sorted_unique(values: Iterable[Any]) -> Tuple[str, ...]:
    normalized = [str(value) for value in values if str(value)]
    if len(normalized) != len(set(normalized)):
        raise ValueError("proof_identity_values_not_unique")
    return tuple(sorted(normalized))


def _valid_sha256_ref(value: str) -> bool:
    return value.startswith(_CHECK_REF_PREFIX) and bool(SHA256_RE.fullmatch(value[7:]))


def _compound_family(defect_family: Any) -> str:
    normalized = str(defect_family or "").strip().lower().replace("-", "_")
    if any(value in normalized for value in ("race", "concurr", "thread", "lock")):
        return "race"
    if any(value in normalized for value in ("leak", "resource", "ownership", "acquire")):
        return "leak"
    if any(value in normalized for value in ("bound", "overflow", "length", "range")):
        return "bounds"
    if any(value in normalized for value in ("dataflow", "injection", "taint", "command")):
        return "dataflow"
    return ""


def _action_binding_failure(
    action: Mapping[str, Any],
    *,
    obligation: Mapping[str, Any],
    proof_ir: Mapping[str, Any],
) -> str:
    """Recompute action-to-obligation binding from the frozen objects.

    This intentionally does not consume a caller-provided ``matches`` flag.
    The obligation hash stored by :class:`FrozenProofState` freezes the family
    and every clause parameter; the reducer independently checks the exact
    subject, region and anchor tuple again before accepting checker output.
    """

    if str(action.get("subject_uid") or "") != str(obligation.get("subject_uid") or ""):
        return "catalog_action_subject_mismatch"
    if str(action.get("decision_region_uid") or "") != str(
        obligation.get("decision_region_uid") or ""
    ):
        return "catalog_action_region_mismatch"
    if tuple(sorted(map(str, action.get("dependency_hashes") or []))) != tuple(
        sorted(map(str, proof_ir.get("dependency_hashes") or []))
    ):
        return "catalog_action_dependency_mismatch"

    clauses = {
        str(clause.get("clause_uid") or ""): clause
        for bucket in ("confirmation_clauses", "counterproof_clauses", "open_clauses")
        for clause in obligation.get(bucket) or []
        if isinstance(clause, Mapping)
    }
    clause = clauses.get(str(action.get("clause_uid") or ""))
    if clause is None:
        return "catalog_action_clause_not_in_obligation"
    for action_key, clause_key in (
        ("provider_family", "provider_family"),
        ("predicate_id", "predicate_id"),
        ("fact_kind", "fact_kind"),
        ("quantifier", "quantifier"),
    ):
        if action.get(action_key) != clause.get(clause_key):
            return "catalog_action_clause_contract_mismatch"
    if dict(action.get("fixed_parameters") or {}) != dict(clause.get("parameters") or {}):
        return "catalog_action_anchor_mismatch"

    predicate_id = str(action.get("predicate_id") or "")
    prefix_contracts = {
        "qualified_race_": ("race", "object_uid"),
        "qualified_bounds_": ("bounds", "value_uid"),
        "qualified_command_": ("dataflow", "value_uid"),
        "qualified_leak_": ("leak", "resource_uid"),
    }
    matched = next(
        (value for prefix, value in prefix_contracts.items() if predicate_id.startswith(prefix)),
        None,
    )
    if matched is not None:
        expected_family, subject_parameter = matched
        if _compound_family(obligation.get("defect_family")) != expected_family:
            return "catalog_action_family_mismatch"
        parameters = action.get("fixed_parameters")
        parameters = parameters if isinstance(parameters, Mapping) else {}
        if str(parameters.get(subject_parameter) or "") != str(obligation.get("subject_uid") or ""):
            return "catalog_action_semantic_subject_mismatch"
    return ""


def _validate_string_tuple(
    values: Any,
    *,
    field: str,
    nonempty: bool = False,
    sha256_refs: bool = False,
) -> Tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise ValueError(f"{field}_must_be_array")
    normalized = _tuple_strings(values)
    if nonempty and not normalized:
        raise ValueError(f"{field}_required")
    if any(not value for value in normalized) or len(normalized) != len(set(normalized)):
        raise ValueError(f"{field}_invalid")
    if tuple(sorted(normalized)) != normalized:
        raise ValueError(f"{field}_must_be_sorted")
    if sha256_refs and any(not _valid_sha256_ref(value) for value in normalized):
        raise ValueError(f"{field}_invalid")
    return normalized


@dataclass(frozen=True)
class FrozenProofState:
    """Exact immutable identity of one proof obligation evaluation."""

    schema_version: str
    proof_state_uid: str
    obligation_uid: str
    obligation_sha256: str
    proof_ir_uid: str
    proof_ir_sha256: str
    validation_cluster_uid: str
    subject_uid: str
    decision_region_uid: str
    proof_ir_dependency_hashes: Tuple[str, ...]
    obligation_dependency_hashes: Tuple[str, ...]
    required_confirmation_clause_uids: Tuple[str, ...]
    required_counterproof_clause_uids: Tuple[str, ...]
    open_clause_uids: Tuple[str, ...]
    catalog_action_uids: Tuple[str, ...]
    catalog_clause_uids: Tuple[str, ...]
    selected_action_uids: Tuple[str, ...]
    checker_result_sha256s: Tuple[str, ...]
    checker_result_refs: Tuple[str, ...]
    root_manifest_sha256: str
    content_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        for key in (
            "proof_ir_dependency_hashes",
            "obligation_dependency_hashes",
            "required_confirmation_clause_uids",
            "required_counterproof_clause_uids",
            "open_clause_uids",
            "catalog_action_uids",
            "catalog_clause_uids",
            "selected_action_uids",
            "checker_result_sha256s",
            "checker_result_refs",
        ):
            payload[key] = list(payload[key])
        return payload

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "FrozenProofState":
        ok, reason = verify_sealed_mapping(
            raw,
            uid_field="proof_state_uid",
            prefix="PSTATE_",
            expected_keys=_STATE_KEYS,
        )
        if not ok:
            raise ValueError(reason)
        if raw.get("schema_version") != FROZEN_PROOF_STATE_VERSION:
            raise ValueError("unsupported_frozen_proof_state_schema")
        scalar_fields = (
            "obligation_uid",
            "proof_ir_uid",
            "validation_cluster_uid",
            "subject_uid",
            "decision_region_uid",
        )
        if any(not isinstance(raw.get(key), str) or not raw.get(key) for key in scalar_fields):
            raise ValueError("frozen_proof_state_identity_invalid")
        for key in (
            "obligation_sha256",
            "proof_ir_sha256",
            "root_manifest_sha256",
        ):
            if not SHA256_RE.fullmatch(str(raw.get(key) or "")):
                raise ValueError(f"{key}_invalid")
        tuple_fields = {
            "proof_ir_dependency_hashes": True,
            "obligation_dependency_hashes": True,
            "required_confirmation_clause_uids": False,
            "required_counterproof_clause_uids": False,
            "open_clause_uids": False,
            "catalog_action_uids": False,
            "catalog_clause_uids": False,
            "selected_action_uids": False,
            "checker_result_sha256s": False,
        }
        normalized: Dict[str, Tuple[str, ...]] = {}
        for field, nonempty in tuple_fields.items():
            normalized[field] = _validate_string_tuple(
                raw.get(field), field=field, nonempty=nonempty
            )
        checker_refs = _validate_string_tuple(
            raw.get("checker_result_refs"),
            field="checker_result_refs",
            sha256_refs=True,
        )
        if any(not SHA256_RE.fullmatch(value) for value in normalized["checker_result_sha256s"]):
            raise ValueError("checker_result_sha256s_invalid")
        if len(normalized["checker_result_sha256s"]) != len(checker_refs):
            raise ValueError("checker_result_reference_cardinality_mismatch")
        if not set(normalized["selected_action_uids"]) <= set(normalized["catalog_action_uids"]):
            raise ValueError("selected_action_not_in_frozen_catalog")
        if len(normalized["catalog_action_uids"]) != len(normalized["catalog_clause_uids"]):
            raise ValueError("frozen_catalog_action_clause_cardinality_mismatch")
        return cls(
            schema_version=str(raw["schema_version"]),
            proof_state_uid=str(raw["proof_state_uid"]),
            obligation_uid=str(raw["obligation_uid"]),
            obligation_sha256=str(raw["obligation_sha256"]),
            proof_ir_uid=str(raw["proof_ir_uid"]),
            proof_ir_sha256=str(raw["proof_ir_sha256"]),
            validation_cluster_uid=str(raw["validation_cluster_uid"]),
            subject_uid=str(raw["subject_uid"]),
            decision_region_uid=str(raw["decision_region_uid"]),
            proof_ir_dependency_hashes=normalized["proof_ir_dependency_hashes"],
            obligation_dependency_hashes=normalized["obligation_dependency_hashes"],
            required_confirmation_clause_uids=normalized["required_confirmation_clause_uids"],
            required_counterproof_clause_uids=normalized["required_counterproof_clause_uids"],
            open_clause_uids=normalized["open_clause_uids"],
            catalog_action_uids=normalized["catalog_action_uids"],
            catalog_clause_uids=normalized["catalog_clause_uids"],
            selected_action_uids=normalized["selected_action_uids"],
            checker_result_sha256s=normalized["checker_result_sha256s"],
            checker_result_refs=checker_refs,
            root_manifest_sha256=str(raw["root_manifest_sha256"]),
            content_sha256=str(raw["content_sha256"]),
        )


@dataclass(frozen=True)
class ProofClosureEvaluation:
    """Deterministic result of reducing one :class:`FrozenProofState`."""

    schema_version: str
    closure_uid: str
    proof_state_sha256: str
    obligation_uid: str
    obligation_sha256: str
    proof_ir_uid: str
    proof_ir_sha256: str
    proof_root_sha256: str
    disposition: str
    reason_code: str
    complete: bool
    accepted_confirmation_clause_uids: Tuple[str, ...]
    accepted_counterproof_clause_uids: Tuple[str, ...]
    checked_clause_uids: Tuple[str, ...]
    missing_clause_uids: Tuple[str, ...]
    conflicting_clause_uids: Tuple[str, ...]
    checker_result_refs: Tuple[str, ...]
    integrity_status: str
    failure_codes: Tuple[str, ...]
    content_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        for key in (
            "accepted_confirmation_clause_uids",
            "accepted_counterproof_clause_uids",
            "checked_clause_uids",
            "missing_clause_uids",
            "conflicting_clause_uids",
            "checker_result_refs",
            "failure_codes",
        ):
            payload[key] = list(payload[key])
        return payload

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ProofClosureEvaluation":
        ok, reason = verify_sealed_mapping(
            raw,
            uid_field="closure_uid",
            prefix="PCLOSURE_",
            expected_keys=_CLOSURE_KEYS,
        )
        if not ok:
            raise ValueError(reason)
        if raw.get("schema_version") != PROOF_CLOSURE_EVALUATION_VERSION:
            raise ValueError("unsupported_proof_closure_schema")
        if raw.get("disposition") not in {
            "confirmed",
            "rejected_with_proof",
            "needs_review",
        }:
            raise ValueError("proof_closure_disposition_invalid")
        if not isinstance(raw.get("complete"), bool):
            raise ValueError("proof_closure_complete_invalid")
        if raw.get("integrity_status") not in {"verified", "invalid"}:
            raise ValueError("proof_closure_integrity_status_invalid")
        scalar_fields = (
            "proof_state_sha256",
            "obligation_sha256",
            "proof_ir_sha256",
            "proof_root_sha256",
        )
        if any(not SHA256_RE.fullmatch(str(raw.get(key) or "")) for key in scalar_fields):
            raise ValueError("proof_closure_sha256_binding_invalid")
        if any(
            not isinstance(raw.get(key), str) or not raw.get(key)
            for key in ("obligation_uid", "proof_ir_uid", "reason_code")
        ):
            raise ValueError("proof_closure_identity_invalid")
        normalized: Dict[str, Tuple[str, ...]] = {}
        for field in (
            "accepted_confirmation_clause_uids",
            "accepted_counterproof_clause_uids",
            "checked_clause_uids",
            "missing_clause_uids",
            "conflicting_clause_uids",
            "failure_codes",
        ):
            normalized[field] = _validate_string_tuple(raw.get(field), field=field)
        checker_refs = _validate_string_tuple(
            raw.get("checker_result_refs"),
            field="checker_result_refs",
            sha256_refs=True,
        )
        if raw.get("complete") is True and (
            raw.get("disposition") == "needs_review"
            or normalized["missing_clause_uids"]
            or normalized["conflicting_clause_uids"]
            or normalized["failure_codes"]
            or raw.get("integrity_status") != "verified"
        ):
            raise ValueError("complete_proof_closure_is_not_clean")
        if raw.get("complete") is False and raw.get("disposition") != "needs_review":
            raise ValueError("incomplete_proof_closure_cannot_be_terminal")
        return cls(
            schema_version=str(raw["schema_version"]),
            closure_uid=str(raw["closure_uid"]),
            proof_state_sha256=str(raw["proof_state_sha256"]),
            obligation_uid=str(raw["obligation_uid"]),
            obligation_sha256=str(raw["obligation_sha256"]),
            proof_ir_uid=str(raw["proof_ir_uid"]),
            proof_ir_sha256=str(raw["proof_ir_sha256"]),
            proof_root_sha256=str(raw["proof_root_sha256"]),
            disposition=str(raw["disposition"]),
            reason_code=str(raw["reason_code"]),
            complete=bool(raw["complete"]),
            accepted_confirmation_clause_uids=normalized["accepted_confirmation_clause_uids"],
            accepted_counterproof_clause_uids=normalized["accepted_counterproof_clause_uids"],
            checked_clause_uids=normalized["checked_clause_uids"],
            missing_clause_uids=normalized["missing_clause_uids"],
            conflicting_clause_uids=normalized["conflicting_clause_uids"],
            checker_result_refs=checker_refs,
            integrity_status=str(raw["integrity_status"]),
            failure_codes=normalized["failure_codes"],
            content_sha256=str(raw["content_sha256"]),
        )


@dataclass(frozen=True)
class PromotionCertificate:
    """Content-addressed authorization input for TerminalAuthority v4."""

    schema_version: str
    promotion_uid: str
    disposition: str
    reason_code: str
    proof_state_sha256: str
    closure_evaluation_sha256: str
    obligation_uid: str
    obligation_sha256: str
    proof_ir_uid: str
    proof_ir_sha256: str
    validation_cluster_uid: str
    subject_uid: str
    decision_region_uid: str
    proof_root_sha256: str
    checker_result_refs: Tuple[str, ...]
    integrity_status: str
    content_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["checker_result_refs"] = list(payload["checker_result_refs"])
        return payload

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PromotionCertificate":
        ok, reason = verify_sealed_mapping(
            raw,
            uid_field="promotion_uid",
            prefix="PROMOTE_",
            expected_keys=_PROMOTION_KEYS,
        )
        if not ok:
            raise ValueError(reason)
        if raw.get("schema_version") != PROMOTION_CERTIFICATE_VERSION:
            raise ValueError("unsupported_promotion_certificate_schema")
        if raw.get("disposition") not in {"confirmed", "rejected_with_proof"}:
            raise ValueError("promotion_disposition_invalid")
        if raw.get("integrity_status") != "verified":
            raise ValueError("promotion_integrity_not_verified")
        for key in (
            "proof_state_sha256",
            "closure_evaluation_sha256",
            "obligation_sha256",
            "proof_ir_sha256",
            "proof_root_sha256",
        ):
            if not SHA256_RE.fullmatch(str(raw.get(key) or "")):
                raise ValueError(f"{key}_invalid")
        if any(
            not isinstance(raw.get(key), str) or not raw.get(key)
            for key in (
                "reason_code",
                "obligation_uid",
                "proof_ir_uid",
                "validation_cluster_uid",
                "subject_uid",
                "decision_region_uid",
            )
        ):
            raise ValueError("promotion_identity_invalid")
        checker_refs = _validate_string_tuple(
            raw.get("checker_result_refs"),
            field="checker_result_refs",
            nonempty=True,
            sha256_refs=True,
        )
        return cls(
            schema_version=str(raw["schema_version"]),
            promotion_uid=str(raw["promotion_uid"]),
            disposition=str(raw["disposition"]),
            reason_code=str(raw["reason_code"]),
            proof_state_sha256=str(raw["proof_state_sha256"]),
            closure_evaluation_sha256=str(raw["closure_evaluation_sha256"]),
            obligation_uid=str(raw["obligation_uid"]),
            obligation_sha256=str(raw["obligation_sha256"]),
            proof_ir_uid=str(raw["proof_ir_uid"]),
            proof_ir_sha256=str(raw["proof_ir_sha256"]),
            validation_cluster_uid=str(raw["validation_cluster_uid"]),
            subject_uid=str(raw["subject_uid"]),
            decision_region_uid=str(raw["decision_region_uid"]),
            proof_root_sha256=str(raw["proof_root_sha256"]),
            checker_result_refs=checker_refs,
            integrity_status=str(raw["integrity_status"]),
            content_sha256=str(raw["content_sha256"]),
        )


T = TypeVar("T", FrozenProofState, ProofClosureEvaluation, PromotionCertificate)


def _coerce(value: T | Mapping[str, Any], kind: type[T]) -> T:
    if isinstance(value, kind):
        return value
    if not isinstance(value, Mapping):
        raise ValueError(f"{kind.__name__}_mapping_required")
    return kind.from_mapping(value)


def freeze_proof_state(
    *,
    proof_ir: Mapping[str, Any],
    obligation: Mapping[str, Any],
    action_catalog: Sequence[Mapping[str, Any]],
    selected_action_uids: Sequence[str],
    check_results: Sequence[Mapping[str, Any]],
    checker_result_refs: Sequence[str],
    root_manifest_sha256: str,
) -> FrozenProofState:
    """Freeze the exact inputs and artifact root used by one closure pass."""

    for value, validator in (
        (proof_ir, validate_program_ir),
        (obligation, validate_obligation),
    ):
        valid, reason = validator(value)
        if not valid:
            raise ValueError(reason)
    if not SHA256_RE.fullmatch(str(root_manifest_sha256 or "")):
        raise ValueError("root_manifest_sha256_invalid")
    catalog = []
    for action in action_catalog:
        valid, reason = validate_action(action)
        if not valid:
            raise ValueError(reason)
        if action.get("obligation_uid") != obligation.get("obligation_uid"):
            raise ValueError("catalog_action_obligation_mismatch")
        if action.get("proof_ir_uid") != proof_ir.get("proof_ir_uid"):
            raise ValueError("catalog_action_proof_ir_mismatch")
        binding_failure = _action_binding_failure(
            action,
            obligation=obligation,
            proof_ir=proof_ir,
        )
        if binding_failure:
            raise ValueError(binding_failure)
        catalog.append(action)
    catalog_action_uids = _sorted_unique(action.get("action_uid") for action in catalog)
    catalog_clause_uids = _sorted_unique(action.get("clause_uid") for action in catalog)
    if len(catalog_action_uids) != len(catalog_clause_uids):
        raise ValueError("catalog_action_clause_cardinality_mismatch")
    selected = _sorted_unique(selected_action_uids)
    if not set(selected) <= set(catalog_action_uids):
        raise ValueError("selected_action_not_in_frozen_catalog")
    checker_refs = _sorted_unique(checker_result_refs)
    if any(not _valid_sha256_ref(value) for value in checker_refs):
        raise ValueError("checker_result_refs_invalid")
    checker_sha256s = []
    for result in check_results:
        valid, reason = validate_check_result(result)
        if not valid:
            raise ValueError(reason)
        checker_sha256s.append(content_sha256(result))
    checker_result_sha256s = _sorted_unique(checker_sha256s)
    if len(checker_result_sha256s) != len(checker_refs):
        raise ValueError("checker_result_reference_cardinality_mismatch")
    required_confirmation = _sorted_unique(
        value.get("clause_uid")
        for value in obligation.get("confirmation_clauses") or []
        if value.get("required") is True
    )
    required_counterproof = _sorted_unique(
        value.get("clause_uid")
        for value in obligation.get("counterproof_clauses") or []
        if value.get("required") is True
    )
    open_clause_uids = _sorted_unique(
        value.get("clause_uid") for value in obligation.get("open_clauses") or []
    )
    payload = {
        "schema_version": FROZEN_PROOF_STATE_VERSION,
        "obligation_uid": str(obligation["obligation_uid"]),
        "obligation_sha256": str(obligation["content_sha256"]),
        "proof_ir_uid": str(proof_ir["proof_ir_uid"]),
        "proof_ir_sha256": str(proof_ir["content_sha256"]),
        "validation_cluster_uid": str(obligation["validation_cluster_uid"]),
        "subject_uid": str(obligation["subject_uid"]),
        "decision_region_uid": str(obligation["decision_region_uid"]),
        "proof_ir_dependency_hashes": list(_sorted_unique(proof_ir.get("dependency_hashes") or [])),
        "obligation_dependency_hashes": list(
            _sorted_unique(obligation.get("dependency_hashes") or [])
        ),
        "required_confirmation_clause_uids": list(required_confirmation),
        "required_counterproof_clause_uids": list(required_counterproof),
        "open_clause_uids": list(open_clause_uids),
        "catalog_action_uids": list(catalog_action_uids),
        "catalog_clause_uids": list(catalog_clause_uids),
        "selected_action_uids": list(selected),
        "checker_result_sha256s": list(checker_result_sha256s),
        "checker_result_refs": list(checker_refs),
        "root_manifest_sha256": str(root_manifest_sha256),
    }
    return FrozenProofState.from_mapping(
        seal_mapping(payload, uid_field="proof_state_uid", prefix="PSTATE_")
    )


def _closure_payload(
    state: FrozenProofState,
    *,
    disposition: str,
    reason_code: str,
    complete: bool,
    accepted_confirmation: Iterable[str],
    accepted_counterproof: Iterable[str],
    checked: Iterable[str],
    missing: Iterable[str],
    conflicting: Iterable[str],
    integrity_status: str,
    failure_codes: Iterable[str],
) -> Dict[str, Any]:
    return {
        "schema_version": PROOF_CLOSURE_EVALUATION_VERSION,
        "proof_state_sha256": state.content_sha256,
        "obligation_uid": state.obligation_uid,
        "obligation_sha256": state.obligation_sha256,
        "proof_ir_uid": state.proof_ir_uid,
        "proof_ir_sha256": state.proof_ir_sha256,
        "proof_root_sha256": state.root_manifest_sha256,
        "disposition": disposition,
        "reason_code": reason_code,
        "complete": complete,
        "accepted_confirmation_clause_uids": list(_sorted_unique(accepted_confirmation)),
        "accepted_counterproof_clause_uids": list(_sorted_unique(accepted_counterproof)),
        "checked_clause_uids": list(_sorted_unique(checked)),
        "missing_clause_uids": list(_sorted_unique(missing)),
        "conflicting_clause_uids": list(_sorted_unique(conflicting)),
        "checker_result_refs": list(state.checker_result_refs),
        "integrity_status": integrity_status,
        "failure_codes": list(_sorted_unique(failure_codes)),
    }


def reduce_proof_closure(
    *,
    frozen_state: FrozenProofState | Mapping[str, Any],
    proof_ir: Mapping[str, Any],
    obligation: Mapping[str, Any],
    action_catalog: Sequence[Mapping[str, Any]],
    check_results: Sequence[Mapping[str, Any]],
) -> ProofClosureEvaluation:
    """Run the sole authoritative closure reducer.

    Binding or integrity failures are represented as a sealed fail-closed
    ``needs_review`` result.  They never mint a promotion certificate.
    """

    state = _coerce(frozen_state, FrozenProofState)
    required_confirmation = set(state.required_confirmation_clause_uids)
    required_counterproof = set(state.required_counterproof_clause_uids)
    all_required = required_confirmation | required_counterproof
    failures: set[str] = set()

    for value, validator, label in (
        (proof_ir, validate_program_ir, "proof_ir_invalid"),
        (obligation, validate_obligation, "obligation_invalid"),
    ):
        valid, _reason = validator(value)
        if not valid:
            failures.add(label)
    expected_bindings = {
        "obligation_uid": state.obligation_uid,
        "obligation_sha256": state.obligation_sha256,
        "proof_ir_uid": state.proof_ir_uid,
        "proof_ir_sha256": state.proof_ir_sha256,
        "validation_cluster_uid": state.validation_cluster_uid,
        "subject_uid": state.subject_uid,
        "decision_region_uid": state.decision_region_uid,
    }
    actual_bindings = {
        "obligation_uid": str(obligation.get("obligation_uid") or ""),
        "obligation_sha256": str(obligation.get("content_sha256") or ""),
        "proof_ir_uid": str(proof_ir.get("proof_ir_uid") or ""),
        "proof_ir_sha256": str(proof_ir.get("content_sha256") or ""),
        "validation_cluster_uid": str(obligation.get("validation_cluster_uid") or ""),
        "subject_uid": str(obligation.get("subject_uid") or ""),
        "decision_region_uid": str(obligation.get("decision_region_uid") or ""),
    }
    if actual_bindings != expected_bindings:
        failures.add("frozen_state_binding_mismatch")
    if tuple(sorted(map(str, proof_ir.get("dependency_hashes") or []))) != (
        state.proof_ir_dependency_hashes
    ):
        failures.add("proof_ir_dependency_binding_mismatch")
    if tuple(sorted(map(str, obligation.get("dependency_hashes") or []))) != (
        state.obligation_dependency_hashes
    ):
        failures.add("obligation_dependency_binding_mismatch")

    by_action_uid: Dict[str, Mapping[str, Any]] = {}
    for action in action_catalog:
        valid, _reason = validate_action(action)
        action_uid = str(action.get("action_uid") or "")
        if not valid or not action_uid or action_uid in by_action_uid:
            failures.add("action_catalog_integrity_failure")
            continue
        by_action_uid[action_uid] = action
        if (
            action.get("obligation_uid") != state.obligation_uid
            or action.get("proof_ir_uid") != state.proof_ir_uid
        ):
            failures.add("action_catalog_binding_mismatch")
        if _action_binding_failure(
            action,
            obligation=obligation,
            proof_ir=proof_ir,
        ):
            failures.add("action_catalog_semantic_binding_mismatch")
    if tuple(sorted(by_action_uid)) != state.catalog_action_uids:
        failures.add("action_catalog_identity_mismatch")
    if (
        tuple(sorted(str(value.get("clause_uid") or "") for value in by_action_uid.values()))
        != state.catalog_clause_uids
    ):
        failures.add("action_catalog_clause_mismatch")

    expected_checker_sha256s = tuple(
        sorted(content_sha256(value) for value in check_results if isinstance(value, Mapping))
    )
    if expected_checker_sha256s != state.checker_result_sha256s:
        failures.add("checker_result_content_mismatch")

    accepted_confirmation: set[str] = set()
    accepted_counterproof: set[str] = set()
    checked: set[str] = set()
    conflicting: set[str] = set()
    seen_checks: set[str] = set()
    for result in check_results:
        valid, _reason = validate_check_result(result)
        check_uid = str(result.get("check_uid") or "")
        action_uid = str(result.get("action_uid") or "")
        clause_uid = str(result.get("clause_uid") or "")
        bound_action = by_action_uid.get(action_uid)
        if not valid or not check_uid or check_uid in seen_checks:
            failures.add("checker_result_integrity_failure")
            continue
        seen_checks.add(check_uid)
        if (
            bound_action is None
            or action_uid not in state.selected_action_uids
            or result.get("obligation_uid") != state.obligation_uid
            or result.get("proof_ir_uid") != state.proof_ir_uid
            or clause_uid != str(bound_action.get("clause_uid") or "")
        ):
            failures.add("checker_result_binding_mismatch")
            continue
        checked.add(clause_uid)
        status = str(result.get("status") or "")
        contribution = str(result.get("terminal_contribution") or "")
        if status == "conflicting":
            conflicting.add(clause_uid)
        elif status == "accepted" and contribution == "confirmation":
            accepted_confirmation.add(clause_uid)
        elif status == "accepted" and contribution == "counterproof":
            accepted_counterproof.add(clause_uid)

    catalog_clause_uids = set(state.catalog_clause_uids)
    selected_clause_uids = {
        str(by_action_uid[value].get("clause_uid") or "")
        for value in state.selected_action_uids
        if value in by_action_uid
    }
    missing = set(state.open_clause_uids)
    if not all_required <= catalog_clause_uids:
        failures.add("required_clause_not_executable")
        missing.update(all_required - catalog_clause_uids)
    if not all_required <= selected_clause_uids:
        failures.add("required_executable_clause_not_selected")
        missing.update(all_required - selected_clause_uids)
    if not all_required <= checked:
        failures.add("required_executable_clause_not_checked")
        missing.update(all_required - checked)
    accepted = accepted_confirmation | accepted_counterproof
    missing.update(all_required - accepted)
    conflicting.update(accepted_confirmation & accepted_counterproof)

    if failures:
        disposition = "needs_review"
        reason_code = sorted(failures)[0]
        complete = False
        integrity_status = "invalid"
    elif conflicting or (accepted_confirmation and accepted_counterproof):
        disposition = "needs_review"
        reason_code = "programmatic_proof_conflict"
        complete = False
        integrity_status = "verified"
        conflicting.update(accepted_confirmation | accepted_counterproof)
    elif missing:
        disposition = "needs_review"
        reason_code = "open_or_unknown_proof_clause"
        complete = False
        integrity_status = "verified"
    elif required_counterproof and required_counterproof <= accepted_counterproof:
        disposition = "rejected_with_proof"
        reason_code = "verified_counterproof"
        complete = True
        integrity_status = "verified"
    elif required_confirmation and required_confirmation <= accepted_confirmation:
        disposition = "confirmed"
        reason_code = "verified_confirmation_proof"
        complete = True
        integrity_status = "verified"
    else:
        disposition = "needs_review"
        reason_code = "open_or_unknown_proof_clause"
        complete = False
        integrity_status = "verified"
    payload = _closure_payload(
        state,
        disposition=disposition,
        reason_code=reason_code,
        complete=complete,
        accepted_confirmation=accepted_confirmation,
        accepted_counterproof=accepted_counterproof,
        checked=checked,
        missing=missing,
        conflicting=conflicting,
        integrity_status=integrity_status,
        failure_codes=failures,
    )
    return ProofClosureEvaluation.from_mapping(
        seal_mapping(payload, uid_field="closure_uid", prefix="PCLOSURE_")
    )


def issue_promotion_certificate(
    *,
    frozen_state: FrozenProofState | Mapping[str, Any],
    closure_evaluation: ProofClosureEvaluation | Mapping[str, Any],
) -> PromotionCertificate:
    """Mint a promotion only from one exact, complete verified closure."""

    state = _coerce(frozen_state, FrozenProofState)
    closure = _coerce(closure_evaluation, ProofClosureEvaluation)
    if (
        closure.proof_state_sha256 != state.content_sha256
        or closure.obligation_uid != state.obligation_uid
        or closure.obligation_sha256 != state.obligation_sha256
        or closure.proof_ir_uid != state.proof_ir_uid
        or closure.proof_ir_sha256 != state.proof_ir_sha256
        or closure.proof_root_sha256 != state.root_manifest_sha256
        or closure.checker_result_refs != state.checker_result_refs
    ):
        raise ValueError("promotion_closure_binding_mismatch")
    if (
        not closure.complete
        or closure.integrity_status != "verified"
        or closure.failure_codes
        or closure.missing_clause_uids
        or closure.conflicting_clause_uids
        or closure.disposition not in {"confirmed", "rejected_with_proof"}
        or not closure.checker_result_refs
    ):
        raise ValueError("promotion_requires_complete_verified_closure")
    payload = {
        "schema_version": PROMOTION_CERTIFICATE_VERSION,
        "disposition": closure.disposition,
        "reason_code": closure.reason_code,
        "proof_state_sha256": state.content_sha256,
        "closure_evaluation_sha256": closure.content_sha256,
        "obligation_uid": state.obligation_uid,
        "obligation_sha256": state.obligation_sha256,
        "proof_ir_uid": state.proof_ir_uid,
        "proof_ir_sha256": state.proof_ir_sha256,
        "validation_cluster_uid": state.validation_cluster_uid,
        "subject_uid": state.subject_uid,
        "decision_region_uid": state.decision_region_uid,
        "proof_root_sha256": state.root_manifest_sha256,
        "checker_result_refs": list(state.checker_result_refs),
        "integrity_status": "verified",
    }
    return PromotionCertificate.from_mapping(
        seal_mapping(payload, uid_field="promotion_uid", prefix="PROMOTE_")
    )


def validate_promotion_binding(
    *,
    frozen_state: FrozenProofState | Mapping[str, Any],
    closure_evaluation: ProofClosureEvaluation | Mapping[str, Any],
    promotion_certificate: PromotionCertificate | Mapping[str, Any],
) -> Tuple[bool, str]:
    """Validate a v4 promotion chain without consulting model output."""

    try:
        state = _coerce(frozen_state, FrozenProofState)
        closure = _coerce(closure_evaluation, ProofClosureEvaluation)
        promotion = _coerce(promotion_certificate, PromotionCertificate)
        expected = issue_promotion_certificate(
            frozen_state=state,
            closure_evaluation=closure,
        )
    except (KeyError, TypeError, ValueError):
        return False, "promotion_contract_invalid"
    if promotion != expected:
        return False, "promotion_contract_binding_mismatch"
    return True, "valid"
