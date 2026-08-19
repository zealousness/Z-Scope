"""Strict content-addressed contracts for P4 hypothesis hunting."""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence, Tuple

from ...core.validation.proof_kernel.canonical import SHA256_RE, seal_mapping, verify_sealed_mapping
from ...core.validation.proof_kernel.models import (
    validate_action,
    validate_obligation,
    validate_program_ir,
)


PROTOCOL_REVISION = 2
LOCALIZED_COVERAGE_KEY_VERSION = "zscope.localized-coverage-key.v2"
ATTACK_SURFACE_AUDIT_UNIT_VERSION = "zscope.attack-surface-audit-unit.v2"
HYPOTHESIS_OFFER_VERSION = "zscope.hypothesis-offer.v2"
HYPOTHESIS_HUNT_REPORT_VERSION = "zscope.hypothesis-hunt-report.v2"
SECURITY_HYPOTHESIS_VERSION = "zscope.security-hypothesis.v2"
HYPOTHESIS_COVERAGE_OBSERVATION_VERSION = "zscope.hypothesis-coverage-observation.v1"

TRIGGER_KINDS = frozenset(
    {
        "external_reachable_sensitive",
        "security_spec_unknown",
        "security_spec_conflict",
        "dynamic_call_gap",
        "backend_coverage_gap",
        "localized_candidate_desert",
    }
)
COVERAGE_STATUSES = frozenset({"complete", "partial", "failed"})

LOCALIZED_KEY_FIELDS = frozenset(
    {
        "schema_version",
        "key_uid",
        "project_uid",
        "revision_uid",
        "function_uid",
        "defect_family",
        "subject_uid",
        "decision_region_uid",
        "structural_fingerprint_sha256",
        "content_sha256",
    }
)
AUDIT_UNIT_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "audit_unit_uid",
        "unit_fingerprint_sha256",
        "project_uid",
        "revision_uid",
        "risk_score",
        "trigger_kinds",
        "localized_coverage_key",
        "root_entry_uids",
        "member_function_uids",
        "event_refs",
        "security_spec_refs",
        "unknown_refs",
        "dependency_hashes",
        "backend_coverage",
        "content_sha256",
    }
)
LOCATION_FIELDS = frozenset({"file", "function_uid", "start_line", "end_line", "statement_uid"})
OFFER_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "offer_uid",
        "audit_unit_uid",
        "defect_family",
        "subject_uid",
        "decision_region_uid",
        "location",
        "source_ref",
        "sink_ref",
        "resource_ref",
        "proof_ir",
        "proof_obligation",
        "evidence_actions",
        "supporting_fact_refs",
        "opposing_fact_refs",
        "unknown_fact_refs",
        "evidence_refs",
        "dependency_hashes",
        "content_sha256",
    }
)
HYPOTHESIS_FIELDS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "hypothesis_uid",
        "audit_unit_uid",
        "offer_uid",
        "defect_family",
        "subject_uid",
        "decision_region_uid",
        "location",
        "source_ref",
        "sink_ref",
        "resource_ref",
        "confirmation_clauses",
        "counterproof_clauses",
        "open_clauses",
        "supporting_fact_refs",
        "opposing_fact_refs",
        "unknown_fact_refs",
        "evidence_action_uids",
        "evidence_refs",
        "dependency_hashes",
        "origin",
        "content_sha256",
    }
)
OBSERVATION_FIELDS = frozenset(
    {
        "schema_version",
        "observation_uid",
        "audit_unit_uid",
        "unit_fingerprint_sha256",
        "reason_code",
        "missing_fields",
        "evidence_refs",
        "dependency_hashes",
        "producer",
        "content_sha256",
    }
)
REPORT_FIELDS = frozenset(
    {
        "schema_version",
        "audit_unit_uid",
        "unit_fingerprint_sha256",
        "coverage_status",
        "selected_offers",
        "reviewed_evidence_refs",
        "unresolved_reasons",
    }
)
SELECTION_FIELDS = frozenset(
    {
        "offer_uid",
        "evidence_action_uids",
        "supporting_fact_refs",
        "opposing_fact_refs",
        "unknown_fact_refs",
        "evidence_refs",
    }
)


def _strings(values: Iterable[Any]) -> list[str]:
    return sorted({str(value) for value in values if str(value)})


def _hashes(values: Any, *, nonempty: bool = True) -> bool:
    return bool(
        isinstance(values, list)
        and (values or not nonempty)
        and len(values) == len(set(map(str, values)))
        and all(SHA256_RE.fullmatch(str(value)) for value in values)
    )


def _string_set(values: Any, *, nonempty: bool = False) -> bool:
    return bool(
        isinstance(values, list)
        and (values or not nonempty)
        and all(isinstance(value, str) and value for value in values)
        and len(values) == len(set(values))
    )


def _identity_fields(raw: Mapping[str, Any], names: Sequence[str]) -> Tuple[bool, str]:
    for name in names:
        if not isinstance(raw.get(name), str) or not str(raw.get(name)):
            return False, f"{name}_required"
    return True, "ok"


def _validate_location(raw: Any) -> Tuple[bool, str]:
    if not isinstance(raw, Mapping) or set(raw) != LOCATION_FIELDS:
        return False, "hypothesis_location_schema_mismatch"
    valid, reason = _identity_fields(raw, ("file", "function_uid", "statement_uid"))
    if not valid:
        return valid, reason
    try:
        start = int(raw.get("start_line") or 0)
        end = int(raw.get("end_line") or 0)
    except (TypeError, ValueError):
        return False, "hypothesis_location_line_invalid"
    if start <= 0 or end < start:
        return False, "hypothesis_location_line_invalid"
    return True, "ok"


def build_localized_coverage_key(
    *,
    project_uid: str,
    revision_uid: str,
    function_uid: str,
    defect_family: str,
    subject_uid: str,
    decision_region_uid: str,
    structural_fingerprint_sha256: str,
) -> dict[str, Any]:
    payload = {
        "schema_version": LOCALIZED_COVERAGE_KEY_VERSION,
        "project_uid": str(project_uid),
        "revision_uid": str(revision_uid),
        "function_uid": str(function_uid),
        "defect_family": str(defect_family),
        "subject_uid": str(subject_uid),
        "decision_region_uid": str(decision_region_uid),
        "structural_fingerprint_sha256": str(structural_fingerprint_sha256),
    }
    result = seal_mapping(payload, uid_field="key_uid", prefix="LCK_")
    valid, reason = validate_localized_coverage_key(result)
    if not valid:
        raise ValueError(reason)
    return result


def validate_localized_coverage_key(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="key_uid",
        prefix="LCK_",
        expected_keys=LOCALIZED_KEY_FIELDS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != LOCALIZED_COVERAGE_KEY_VERSION:
        return False, "unsupported_localized_coverage_key_schema"
    valid, reason = _identity_fields(
        raw,
        (
            "project_uid",
            "revision_uid",
            "function_uid",
            "defect_family",
            "subject_uid",
            "decision_region_uid",
        ),
    )
    if not valid:
        return valid, reason
    if SHA256_RE.fullmatch(str(raw.get("structural_fingerprint_sha256") or "")) is None:
        return False, "structural_fingerprint_sha256_invalid"
    return True, "ok"


def build_attack_surface_audit_unit(
    *,
    project_uid: str,
    revision_uid: str,
    risk_score: int,
    trigger_kinds: Iterable[str],
    localized_coverage_key: Mapping[str, Any],
    root_entry_uids: Iterable[str],
    member_function_uids: Iterable[str],
    event_refs: Iterable[str],
    security_spec_refs: Iterable[str],
    unknown_refs: Iterable[str],
    dependency_hashes: Iterable[str],
    backend_coverage: Mapping[str, Any],
) -> dict[str, Any]:
    payload = {
        "schema_version": ATTACK_SURFACE_AUDIT_UNIT_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "unit_fingerprint_sha256": str(localized_coverage_key.get("content_sha256") or ""),
        "project_uid": str(project_uid),
        "revision_uid": str(revision_uid),
        "risk_score": int(risk_score),
        "trigger_kinds": _strings(trigger_kinds),
        "localized_coverage_key": dict(localized_coverage_key),
        "root_entry_uids": _strings(root_entry_uids),
        "member_function_uids": _strings(member_function_uids),
        "event_refs": _strings(event_refs),
        "security_spec_refs": _strings(security_spec_refs),
        "unknown_refs": _strings(unknown_refs),
        "dependency_hashes": _strings(dependency_hashes),
        "backend_coverage": dict(backend_coverage),
    }
    result = seal_mapping(payload, uid_field="audit_unit_uid", prefix="HAU_")
    valid, reason = validate_attack_surface_audit_unit(result)
    if not valid:
        raise ValueError(reason)
    return result


def validate_attack_surface_audit_unit(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="audit_unit_uid",
        prefix="HAU_",
        expected_keys=AUDIT_UNIT_FIELDS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != ATTACK_SURFACE_AUDIT_UNIT_VERSION:
        return False, "unsupported_attack_surface_audit_unit_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    valid, reason = _identity_fields(raw, ("project_uid", "revision_uid"))
    if not valid:
        return valid, reason
    raw_risk_score = raw.get("risk_score")
    if isinstance(raw_risk_score, bool) or not isinstance(raw_risk_score, (int, str)):
        return False, "risk_score_invalid"
    try:
        risk_score = int(raw_risk_score)
    except ValueError:
        return False, "risk_score_invalid"
    if not 0 <= risk_score <= 100:
        return False, "risk_score_invalid"
    triggers = raw.get("trigger_kinds")
    if (
        not isinstance(triggers, list)
        or not _string_set(triggers, nonempty=True)
        or not set(triggers) <= TRIGGER_KINDS
    ):
        return False, "trigger_kinds_invalid"
    localized = raw.get("localized_coverage_key")
    if not isinstance(localized, Mapping):
        return False, "localized_coverage_key_required"
    valid, reason = validate_localized_coverage_key(localized)
    if not valid:
        return False, "localized_coverage_key_invalid:" + reason
    if raw.get("unit_fingerprint_sha256") != localized.get("content_sha256"):
        return False, "unit_fingerprint_binding_mismatch"
    for name, nonempty in (
        ("root_entry_uids", False),
        ("member_function_uids", True),
        ("event_refs", False),
        ("security_spec_refs", False),
        ("unknown_refs", False),
    ):
        if not _string_set(raw.get(name), nonempty=nonempty):
            return False, f"{name}_invalid"
    if not _hashes(raw.get("dependency_hashes")):
        return False, "dependency_hashes_invalid"
    if not isinstance(raw.get("backend_coverage"), Mapping):
        return False, "backend_coverage_not_object"
    return True, "ok"


def build_hypothesis_offer(
    *,
    audit_unit_uid: str,
    defect_family: str,
    subject_uid: str,
    decision_region_uid: str,
    location: Mapping[str, Any],
    source_ref: str | None,
    sink_ref: str | None,
    resource_ref: str | None,
    proof_ir: Mapping[str, Any],
    proof_obligation: Mapping[str, Any],
    evidence_actions: Sequence[Mapping[str, Any]],
    supporting_fact_refs: Iterable[str] = (),
    opposing_fact_refs: Iterable[str] = (),
    unknown_fact_refs: Iterable[str] = (),
    evidence_refs: Iterable[str],
    dependency_hashes: Iterable[str],
) -> dict[str, Any]:
    payload = {
        "schema_version": HYPOTHESIS_OFFER_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "audit_unit_uid": str(audit_unit_uid),
        "defect_family": str(defect_family),
        "subject_uid": str(subject_uid),
        "decision_region_uid": str(decision_region_uid),
        "location": dict(location),
        "source_ref": str(source_ref) if source_ref else None,
        "sink_ref": str(sink_ref) if sink_ref else None,
        "resource_ref": str(resource_ref) if resource_ref else None,
        "proof_ir": dict(proof_ir),
        "proof_obligation": dict(proof_obligation),
        "evidence_actions": [dict(value) for value in evidence_actions],
        "supporting_fact_refs": _strings(supporting_fact_refs),
        "opposing_fact_refs": _strings(opposing_fact_refs),
        "unknown_fact_refs": _strings(unknown_fact_refs),
        "evidence_refs": _strings(evidence_refs),
        "dependency_hashes": _strings(dependency_hashes),
    }
    result = seal_mapping(payload, uid_field="offer_uid", prefix="HOFFER_")
    valid, reason = validate_hypothesis_offer(result)
    if not valid:
        raise ValueError(reason)
    return result


def validate_hypothesis_offer(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="offer_uid",
        prefix="HOFFER_",
        expected_keys=OFFER_FIELDS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != HYPOTHESIS_OFFER_VERSION:
        return False, "unsupported_hypothesis_offer_schema"
    if raw.get("protocol_revision") != PROTOCOL_REVISION:
        return False, "unsupported_protocol_revision"
    valid, reason = _identity_fields(
        raw,
        ("audit_unit_uid", "defect_family", "subject_uid", "decision_region_uid"),
    )
    if not valid:
        return valid, reason
    valid, reason = _validate_location(raw.get("location"))
    if not valid:
        return valid, reason
    if not raw.get("resource_ref") and not (raw.get("source_ref") and raw.get("sink_ref")):
        return False, "offer_requires_source_sink_or_resource"
    proof_ir = raw.get("proof_ir")
    obligation = raw.get("proof_obligation")
    actions = raw.get("evidence_actions")
    if not isinstance(proof_ir, Mapping) or not isinstance(obligation, Mapping):
        return False, "offer_proof_artifacts_required"
    valid, reason = validate_program_ir(proof_ir)
    if not valid:
        return False, "offer_program_ir_invalid:" + reason
    valid, reason = validate_obligation(obligation)
    if not valid:
        return False, "offer_obligation_invalid:" + reason
    if not isinstance(actions, list) or not actions:
        return False, "offer_evidence_actions_required"
    action_ids: list[str] = []
    clause_uids = {
        str(value.get("clause_uid") or "")
        for name in ("confirmation_clauses", "counterproof_clauses")
        for value in obligation.get(name) or []
        if isinstance(value, Mapping)
    }
    for action in actions:
        if not isinstance(action, Mapping):
            return False, "offer_evidence_action_not_object"
        valid, reason = validate_action(action)
        if not valid:
            return False, "offer_evidence_action_invalid:" + reason
        if (
            action.get("obligation_uid") != obligation.get("obligation_uid")
            or action.get("proof_ir_uid") != proof_ir.get("proof_ir_uid")
            or action.get("clause_uid") not in clause_uids
            or action.get("subject_uid") != raw.get("subject_uid")
            or action.get("decision_region_uid") != raw.get("decision_region_uid")
        ):
            return False, "offer_evidence_action_binding_mismatch"
        action_ids.append(str(action.get("action_uid") or ""))
    if len(action_ids) != len(set(action_ids)):
        return False, "offer_evidence_action_uid_not_unique"
    if (
        obligation.get("subject_uid") != raw.get("subject_uid")
        or obligation.get("decision_region_uid") != raw.get("decision_region_uid")
        or obligation.get("defect_family") != raw.get("defect_family")
    ):
        return False, "offer_obligation_binding_mismatch"
    for name, nonempty in (
        ("supporting_fact_refs", False),
        ("opposing_fact_refs", False),
        ("unknown_fact_refs", False),
        ("evidence_refs", True),
    ):
        if not _string_set(raw.get(name), nonempty=nonempty):
            return False, f"offer_{name}_invalid"
    if not _hashes(raw.get("dependency_hashes")):
        return False, "offer_dependency_hashes_invalid"
    if set(raw.get("dependency_hashes") or []) != set(proof_ir.get("dependency_hashes") or []):
        return False, "offer_dependency_binding_mismatch"
    return True, "ok"


def validate_hunt_report(
    raw: Mapping[str, Any],
    *,
    audit_unit: Mapping[str, Any],
    offers: Sequence[Mapping[str, Any]],
) -> Tuple[bool, str]:
    if set(raw) != REPORT_FIELDS:
        return False, "hunt_report_schema_keys_mismatch"
    if raw.get("schema_version") != HYPOTHESIS_HUNT_REPORT_VERSION:
        return False, "unsupported_hunt_report_schema"
    if raw.get("audit_unit_uid") != audit_unit.get("audit_unit_uid") or raw.get(
        "unit_fingerprint_sha256"
    ) != audit_unit.get("unit_fingerprint_sha256"):
        return False, "hunt_report_audit_unit_identity_mismatch"
    if raw.get("coverage_status") not in COVERAGE_STATUSES:
        return False, "hunt_report_coverage_status_invalid"
    offer_by_uid = {str(value.get("offer_uid") or ""): value for value in offers}
    allowed_evidence = {
        str(ref) for offer in offers for ref in offer.get("evidence_refs") or [] if str(ref)
    }
    selected = raw.get("selected_offers")
    if not isinstance(selected, list):
        return False, "hunt_report_selected_offers_not_array"
    selected_ids: list[str] = []
    for item in selected:
        if not isinstance(item, Mapping) or set(item) != SELECTION_FIELDS:
            return False, "hunt_report_selection_schema_mismatch"
        offer_uid = str(item.get("offer_uid") or "")
        offer = offer_by_uid.get(offer_uid)
        if offer is None:
            return False, "hunt_report_unknown_offer_uid"
        selected_ids.append(offer_uid)
        allowed_actions = {
            str(value.get("action_uid") or "") for value in offer.get("evidence_actions") or []
        }
        allowed_facts = {
            name: set(map(str, offer.get(name) or []))
            for name in (
                "supporting_fact_refs",
                "opposing_fact_refs",
                "unknown_fact_refs",
            )
        }
        if not _string_set(item.get("evidence_action_uids"), nonempty=True):
            return False, "hunt_report_action_ids_invalid"
        if not set(item.get("evidence_action_uids") or []) <= allowed_actions:
            return False, "hunt_report_action_not_offered"
        for name, allowed in allowed_facts.items():
            if not _string_set(item.get(name)) or not set(item.get(name) or []) <= allowed:
                return False, "hunt_report_fact_ref_not_offered"
        if not _string_set(item.get("evidence_refs"), nonempty=True):
            return False, "hunt_report_evidence_refs_invalid"
        if not set(item.get("evidence_refs") or []) <= set(offer.get("evidence_refs") or []):
            return False, "hunt_report_evidence_ref_not_offered"
    if len(selected_ids) != len(set(selected_ids)):
        return False, "hunt_report_offer_uid_not_unique"
    if (
        not _string_set(raw.get("reviewed_evidence_refs"))
        or not set(raw.get("reviewed_evidence_refs") or []) <= allowed_evidence
    ):
        return False, "hunt_report_reviewed_evidence_ref_not_offered"
    if not _string_set(raw.get("unresolved_reasons")):
        return False, "hunt_report_unresolved_reasons_invalid"
    return True, "ok"


def materialize_security_hypothesis(
    *,
    offer: Mapping[str, Any],
    selection: Mapping[str, Any],
) -> dict[str, Any]:
    obligation = offer.get("proof_obligation")
    if not isinstance(obligation, Mapping):
        raise ValueError("offer_proof_obligation_required")
    payload = {
        "schema_version": SECURITY_HYPOTHESIS_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "audit_unit_uid": str(offer.get("audit_unit_uid") or ""),
        "offer_uid": str(offer.get("offer_uid") or ""),
        "defect_family": str(offer.get("defect_family") or ""),
        "subject_uid": str(offer.get("subject_uid") or ""),
        "decision_region_uid": str(offer.get("decision_region_uid") or ""),
        "location": dict(offer.get("location") or {}),
        "source_ref": offer.get("source_ref"),
        "sink_ref": offer.get("sink_ref"),
        "resource_ref": offer.get("resource_ref"),
        "confirmation_clauses": [
            dict(value) for value in obligation.get("confirmation_clauses") or []
        ],
        "counterproof_clauses": [
            dict(value) for value in obligation.get("counterproof_clauses") or []
        ],
        "open_clauses": [dict(value) for value in obligation.get("open_clauses") or []],
        "supporting_fact_refs": _strings(selection.get("supporting_fact_refs") or []),
        "opposing_fact_refs": _strings(selection.get("opposing_fact_refs") or []),
        "unknown_fact_refs": _strings(selection.get("unknown_fact_refs") or []),
        "evidence_action_uids": _strings(selection.get("evidence_action_uids") or []),
        "evidence_refs": _strings(selection.get("evidence_refs") or []),
        "dependency_hashes": _strings(offer.get("dependency_hashes") or []),
        "origin": "hypothesis_hunter",
    }
    result = seal_mapping(payload, uid_field="hypothesis_uid", prefix="HYP_")
    valid, reason = validate_security_hypothesis(result, offer=offer)
    if not valid:
        raise ValueError(reason)
    return result


def validate_security_hypothesis(
    raw: Mapping[str, Any],
    *,
    offer: Mapping[str, Any] | None = None,
) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="hypothesis_uid",
        prefix="HYP_",
        expected_keys=HYPOTHESIS_FIELDS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != SECURITY_HYPOTHESIS_VERSION:
        return False, "unsupported_security_hypothesis_schema"
    if (
        raw.get("protocol_revision") != PROTOCOL_REVISION
        or raw.get("origin") != "hypothesis_hunter"
    ):
        return False, "security_hypothesis_protocol_or_origin_invalid"
    valid, reason = _identity_fields(
        raw,
        (
            "audit_unit_uid",
            "offer_uid",
            "defect_family",
            "subject_uid",
            "decision_region_uid",
        ),
    )
    if not valid:
        return valid, reason
    valid, reason = _validate_location(raw.get("location"))
    if not valid:
        return valid, reason
    if not raw.get("resource_ref") and not (raw.get("source_ref") and raw.get("sink_ref")):
        return False, "hypothesis_requires_source_sink_or_resource"
    for name, nonempty in (
        ("supporting_fact_refs", False),
        ("opposing_fact_refs", False),
        ("unknown_fact_refs", False),
        ("evidence_action_uids", True),
        ("evidence_refs", True),
    ):
        if not _string_set(raw.get(name), nonempty=nonempty):
            return False, f"hypothesis_{name}_invalid"
    if not _hashes(raw.get("dependency_hashes")):
        return False, "hypothesis_dependency_hashes_invalid"
    for name in ("confirmation_clauses", "counterproof_clauses", "open_clauses"):
        values = raw.get(name)
        if not isinstance(values, list) or any(not isinstance(value, Mapping) for value in values):
            return False, f"hypothesis_{name}_invalid"
    if offer is None:
        return True, "ok"
    valid, reason = validate_hypothesis_offer(offer)
    if not valid:
        return False, "hypothesis_offer_invalid:" + reason
    for name in (
        "audit_unit_uid",
        "offer_uid",
        "defect_family",
        "subject_uid",
        "decision_region_uid",
        "location",
        "source_ref",
        "sink_ref",
        "resource_ref",
        "dependency_hashes",
    ):
        if raw.get(name) != offer.get(name):
            return False, "hypothesis_offer_binding_mismatch:" + name
    obligation = offer.get("proof_obligation") or {}
    for name in ("confirmation_clauses", "counterproof_clauses", "open_clauses"):
        if raw.get(name) != obligation.get(name):
            return False, "hypothesis_clause_binding_mismatch:" + name
    allowed_actions = {
        str(value.get("action_uid") or "") for value in offer.get("evidence_actions") or []
    }
    if not set(raw.get("evidence_action_uids") or []) <= allowed_actions:
        return False, "hypothesis_action_not_offered"
    for name in (
        "supporting_fact_refs",
        "opposing_fact_refs",
        "unknown_fact_refs",
        "evidence_refs",
    ):
        if not set(raw.get(name) or []) <= set(offer.get(name) or []):
            return False, "hypothesis_reference_not_offered:" + name
    return True, "ok"


def build_coverage_observation(
    *,
    audit_unit_uid: str,
    unit_fingerprint_sha256: str,
    reason_code: str,
    missing_fields: Iterable[str] = (),
    evidence_refs: Iterable[str] = (),
    dependency_hashes: Iterable[str],
) -> dict[str, Any]:
    payload = {
        "schema_version": HYPOTHESIS_COVERAGE_OBSERVATION_VERSION,
        "audit_unit_uid": str(audit_unit_uid),
        "unit_fingerprint_sha256": str(unit_fingerprint_sha256),
        "reason_code": str(reason_code),
        "missing_fields": _strings(missing_fields),
        "evidence_refs": _strings(evidence_refs),
        "dependency_hashes": _strings(dependency_hashes),
        "producer": "hypothesis_hunter",
    }
    result = seal_mapping(payload, uid_field="observation_uid", prefix="HOBS_")
    valid, reason = validate_coverage_observation(result)
    if not valid:
        raise ValueError(reason)
    return result


def validate_coverage_observation(raw: Mapping[str, Any]) -> Tuple[bool, str]:
    ok, reason = verify_sealed_mapping(
        raw,
        uid_field="observation_uid",
        prefix="HOBS_",
        expected_keys=OBSERVATION_FIELDS,
    )
    if not ok:
        return ok, reason
    if raw.get("schema_version") != HYPOTHESIS_COVERAGE_OBSERVATION_VERSION:
        return False, "unsupported_coverage_observation_schema"
    if raw.get("producer") != "hypothesis_hunter":
        return False, "coverage_observation_producer_invalid"
    valid, reason = _identity_fields(
        raw,
        ("audit_unit_uid", "unit_fingerprint_sha256", "reason_code"),
    )
    if not valid:
        return valid, reason
    if SHA256_RE.fullmatch(str(raw.get("unit_fingerprint_sha256") or "")) is None:
        return False, "coverage_observation_fingerprint_invalid"
    if not _string_set(raw.get("missing_fields")) or not _string_set(raw.get("evidence_refs")):
        return False, "coverage_observation_reference_set_invalid"
    if not _hashes(raw.get("dependency_hashes")):
        return False, "coverage_observation_dependency_hashes_invalid"
    return True, "ok"
