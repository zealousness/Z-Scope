"""Strict builders and validators for SecuritySpec v2 artifacts."""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .canonical import SHA256_RE, content_sha256, seal, verify_seal
from .registry import PREDICATE_REGISTRY, validate_parameters, validate_scope, validate_subject


SECURITY_SPEC_VERSION = "zscope.security-spec.v2"
REVIEW_EVENT_VERSION = "zscope.security-spec-review-event.v2"
QUALIFICATION_VERSION = "zscope.security-spec-qualification.v1"
COMPILED_SPEC_VERSION = "zscope.compiled-security-spec.v2"
COMPILATION_MANIFEST_VERSION = "zscope.security-spec-compilation-manifest.v2"
PROTOCOL_REVISION = 2

SPEC_UID_RE = re.compile(r"^SPEC_[0-9a-f]{32}$")
EVENT_UID_RE = re.compile(r"^SPECREV_[0-9a-f]{32}$")
QUALIFICATION_UID_RE = re.compile(r"^SPECQUAL_[0-9a-f]{32}$")
STATUSES = frozenset(
    {
        "observation",
        "proposed",
        "verified_scoped",
        "project_active",
        "stable",
        "conflicting",
        "rejected",
        "quarantined",
    }
)
ORIGINS = frozenset({"program", "user_config", "llm", "qualification"})
REVIEW_ACTIONS = frozenset({"approve-scoped", "narrow", "reject", "defer", "reverify", "revoke"})
STATE_TRANSITIONS = {
    "observation": frozenset({"proposed", "rejected", "quarantined"}),
    "proposed": frozenset({"verified_scoped", "rejected", "conflicting", "quarantined"}),
    "verified_scoped": frozenset(
        {"project_active", "stable", "rejected", "conflicting", "quarantined"}
    ),
    "project_active": frozenset({"stable", "rejected", "conflicting", "quarantined"}),
    "stable": frozenset({"rejected", "conflicting", "quarantined"}),
    "conflicting": frozenset({"verified_scoped", "rejected", "quarantined"}),
    "rejected": frozenset(),
    "quarantined": frozenset({"proposed", "verified_scoped", "rejected"}),
}

SPEC_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "spec_uid",
        "revision",
        "kind",
        "subject",
        "scope",
        "predicate",
        "parameters",
        "evidence_refs",
        "dependency_hashes",
        "origin",
        "confidence",
        "status",
        "conflicts",
        "supersedes",
        "qualification_ref",
        "review_ref",
        "explanation",
        "impact_preview",
        "content_sha256",
    }
)
REVIEW_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "event_uid",
        "spec_uid",
        "spec_revision",
        "reviewer_identity",
        "reviewed_at",
        "reason",
        "action",
        "before_spec_sha256",
        "after_spec_sha256",
        "scope_override",
        "dependency_impact",
        "previous_event_sha256",
        "content_sha256",
    }
)
QUALIFICATION_KEYS = frozenset(
    {
        "schema_version",
        "protocol_revision",
        "qualification_uid",
        "registry_sha256",
        "compiler_sha256",
        "corpus_sha256",
        "qualified_predicates",
        "source_projects",
        "metrics",
        "environment",
        "content_sha256",
    }
)


def _strings(values: Sequence[Any], *, nonempty: bool = False) -> list[str]:
    result = [str(value) for value in values]
    if any(not value for value in result) or len(result) != len(set(result)):
        raise ValueError("values_must_be_unique_nonempty_strings")
    if nonempty and not result:
        raise ValueError("values_must_not_be_empty")
    return sorted(result)


def _hashes(values: Any, *, nonempty: bool = True) -> bool:
    return bool(
        isinstance(values, list)
        and (values or not nonempty)
        and len(values) == len(set(map(str, values)))
        and all(SHA256_RE.fullmatch(str(value)) for value in values)
    )


def _spec_uid(subject: Mapping[str, Any], scope: Mapping[str, Any], predicate: str) -> str:
    return (
        "SPEC_"
        + content_sha256({"subject": dict(subject), "scope": dict(scope), "predicate": predicate})[
            :32
        ]
    )


def build_security_spec(
    *,
    subject: Mapping[str, Any],
    scope: Mapping[str, Any],
    predicate: str,
    parameters: Mapping[str, Any],
    evidence_refs: Sequence[str],
    dependency_hashes: Sequence[str],
    origin: str,
    confidence: float,
    status: str,
    revision: int = 1,
    spec_uid: str = "",
    conflicts: Sequence[str] = (),
    supersedes: Sequence[str] = (),
    qualification_ref: str = "",
    review_ref: str = "",
    explanation: str = "",
    impact_preview: Sequence[str] = (),
) -> dict[str, Any]:
    uid = str(spec_uid or _spec_uid(subject, scope, predicate))
    payload = {
        "schema_version": SECURITY_SPEC_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "spec_uid": uid,
        "revision": int(revision),
        "kind": str(predicate),
        "subject": dict(subject),
        "scope": dict(scope),
        "predicate": str(predicate),
        "parameters": dict(parameters),
        "evidence_refs": _strings(evidence_refs, nonempty=True),
        "dependency_hashes": _strings(dependency_hashes, nonempty=True),
        "origin": str(origin),
        "confidence": float(confidence),
        "status": str(status),
        "conflicts": _strings(conflicts),
        "supersedes": _strings(supersedes),
        "qualification_ref": str(qualification_ref),
        "review_ref": str(review_ref),
        "explanation": str(explanation),
        "impact_preview": _strings(impact_preview),
    }
    result = seal(payload)
    valid, reason = validate_security_spec(result)
    if not valid:
        raise ValueError(reason)
    return result


def validate_security_spec(raw: Mapping[str, Any]) -> tuple[bool, str]:
    if set(raw) != set(SPEC_KEYS):
        return False, "security_spec_schema_keys_mismatch"
    valid, reason = verify_seal(raw)
    if not valid:
        return False, reason
    if raw.get("schema_version") != SECURITY_SPEC_VERSION or raw.get("protocol_revision") != 2:
        return False, "unsupported_security_spec_version"
    if SPEC_UID_RE.fullmatch(str(raw.get("spec_uid") or "")) is None:
        return False, "invalid_spec_uid"
    if not isinstance(raw.get("revision"), int) or int(raw["revision"]) < 1:
        return False, "invalid_spec_revision"
    predicate = str(raw.get("predicate") or "")
    if predicate not in PREDICATE_REGISTRY or raw.get("kind") != predicate:
        return False, "predicate_not_registered"
    valid, reason = validate_subject(raw.get("subject"))
    if not valid:
        return False, reason
    valid, reason = validate_scope(raw.get("scope"))
    if not valid:
        return False, reason
    valid, reason = validate_parameters(predicate, raw.get("parameters"))
    if not valid:
        return False, reason
    evidence = raw.get("evidence_refs")
    if (
        not isinstance(evidence, list)
        or not evidence
        or len(evidence) != len(set(map(str, evidence)))
    ):
        return False, "invalid_evidence_refs"
    if not _hashes(raw.get("dependency_hashes")):
        return False, "invalid_dependency_hashes"
    if raw.get("origin") not in ORIGINS or raw.get("status") not in STATUSES:
        return False, "invalid_origin_or_status"
    raw_confidence = raw.get("confidence")
    if not isinstance(raw_confidence, (int, float)) or isinstance(raw_confidence, bool):
        return False, "invalid_confidence"
    confidence = float(raw_confidence)
    if not 0.0 <= confidence <= 1.0:
        return False, "invalid_confidence"
    for name in ("conflicts", "supersedes", "impact_preview"):
        value = raw.get(name)
        if not isinstance(value, list) or len(value) != len(set(map(str, value))):
            return False, f"invalid_{name}"
    if any(SPEC_UID_RE.fullmatch(str(value)) is None for value in raw["conflicts"]):
        return False, "invalid_conflict_spec_uid"
    if any(SHA256_RE.fullmatch(str(value)) is None for value in raw["supersedes"]):
        return False, "invalid_superseded_spec_hash"
    qualification_ref = str(raw.get("qualification_ref") or "")
    review_ref = str(raw.get("review_ref") or "")
    if qualification_ref and SHA256_RE.fullmatch(qualification_ref) is None:
        return False, "invalid_qualification_ref"
    if review_ref and SHA256_RE.fullmatch(review_ref) is None:
        return False, "invalid_review_ref"
    if qualification_ref and review_ref:
        return False, "ambiguous_activation_authority"
    status = str(raw.get("status"))
    if status in {"project_active", "stable"} and not (qualification_ref or review_ref):
        return False, "active_spec_requires_review_or_qualification"
    if raw.get("origin") == "llm" and status not in {
        "observation",
        "proposed",
        "conflicting",
        "quarantined",
    }:
        return False, "llm_spec_cannot_activate"
    if status in {"project_active", "stable"} and (
        not str(raw.get("explanation") or "") or not raw.get("impact_preview")
    ):
        return False, "active_spec_requires_explanation_and_impact"
    return True, "ok"


def transition_allowed(before: str, after: str) -> bool:
    return str(after) in STATE_TRANSITIONS.get(str(before), frozenset())


def build_review_event(
    *,
    spec_uid: str,
    spec_revision: int,
    reviewer_identity: str,
    reviewed_at: str,
    reason: str,
    action: str,
    before_spec_sha256: str,
    after_spec_sha256: str,
    scope_override: Mapping[str, Any],
    dependency_impact: Sequence[str],
    previous_event_sha256: str,
) -> dict[str, Any]:
    body = {
        "schema_version": REVIEW_EVENT_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "spec_uid": spec_uid,
        "spec_revision": int(spec_revision),
        "reviewer_identity": reviewer_identity,
        "reviewed_at": reviewed_at,
        "reason": reason,
        "action": action,
        "before_spec_sha256": before_spec_sha256,
        "after_spec_sha256": after_spec_sha256,
        "scope_override": dict(scope_override),
        "dependency_impact": _strings(dependency_impact),
        "previous_event_sha256": previous_event_sha256,
    }
    event_uid = "SPECREV_" + content_sha256(body)[:32]
    result = seal({**body, "event_uid": event_uid})
    valid, reason_code = validate_review_event(result)
    if not valid:
        raise ValueError(reason_code)
    return result


def validate_review_event(raw: Mapping[str, Any]) -> tuple[bool, str]:
    if set(raw) != set(REVIEW_KEYS):
        return False, "review_event_schema_keys_mismatch"
    valid, reason = verify_seal(raw)
    if not valid:
        return False, reason
    if raw.get("schema_version") != REVIEW_EVENT_VERSION or raw.get("protocol_revision") != 2:
        return False, "unsupported_review_event_version"
    if EVENT_UID_RE.fullmatch(str(raw.get("event_uid") or "")) is None:
        return False, "invalid_review_event_uid"
    if SPEC_UID_RE.fullmatch(str(raw.get("spec_uid") or "")) is None:
        return False, "invalid_review_spec_uid"
    if not str(raw.get("reviewer_identity") or "") or not str(raw.get("reason") or ""):
        return False, "review_identity_and_reason_required"
    if raw.get("action") not in REVIEW_ACTIONS:
        return False, "invalid_review_action"
    for name in (
        "before_spec_sha256",
        "after_spec_sha256",
        "previous_event_sha256",
    ):
        if SHA256_RE.fullmatch(str(raw.get(name) or "")) is None:
            return False, f"invalid_{name}"
    scope = raw.get("scope_override")
    if scope and validate_scope(scope)[0] is False:
        return False, "invalid_review_scope_override"
    return True, "ok"


def build_qualification(
    *,
    registry_sha256: str,
    compiler_sha256: str,
    corpus_sha256: str,
    qualified_predicates: Sequence[str],
    source_projects: Sequence[str],
    metrics: Mapping[str, Any],
    environment: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema_version": QUALIFICATION_VERSION,
        "protocol_revision": PROTOCOL_REVISION,
        "registry_sha256": registry_sha256,
        "compiler_sha256": compiler_sha256,
        "corpus_sha256": corpus_sha256,
        "qualified_predicates": _strings(qualified_predicates, nonempty=True),
        "source_projects": _strings(source_projects, nonempty=True),
        "metrics": dict(metrics),
        "environment": dict(environment),
    }
    uid = "SPECQUAL_" + content_sha256(body)[:32]
    result = seal({**body, "qualification_uid": uid})
    valid, reason = validate_qualification(result)
    if not valid:
        raise ValueError(reason)
    return result


def validate_qualification(raw: Mapping[str, Any]) -> tuple[bool, str]:
    if set(raw) != set(QUALIFICATION_KEYS):
        return False, "qualification_schema_keys_mismatch"
    valid, reason = verify_seal(raw)
    if not valid:
        return False, reason
    if raw.get("schema_version") != QUALIFICATION_VERSION or raw.get("protocol_revision") != 2:
        return False, "unsupported_qualification_version"
    if QUALIFICATION_UID_RE.fullmatch(str(raw.get("qualification_uid") or "")) is None:
        return False, "invalid_qualification_uid"
    for name in ("registry_sha256", "compiler_sha256", "corpus_sha256"):
        if SHA256_RE.fullmatch(str(raw.get(name) or "")) is None:
            return False, f"invalid_{name}"
    predicates = raw.get("qualified_predicates")
    if (
        not isinstance(predicates, list)
        or not predicates
        or any(value not in PREDICATE_REGISTRY for value in predicates)
        or len(predicates) != len(set(predicates))
    ):
        return False, "invalid_qualified_predicates"
    projects = raw.get("source_projects")
    if not isinstance(projects, list) or len(projects) < 3 or len(projects) != len(set(projects)):
        return False, "qualification_requires_three_projects"
    metrics = raw.get("metrics")
    required_metrics = {
        "case_count",
        "key_contract_recall",
        "positive_unsupported_rate",
        "safe_false_activation_count",
        "evidence_resolution_rate",
        "second_scan_llm_reduction",
    }
    if not isinstance(metrics, Mapping) or set(metrics) != required_metrics:
        return False, "invalid_qualification_metrics"
    if int(metrics.get("case_count", 0)) < 120:
        return False, "qualification_case_count_below_120"
    if float(metrics.get("key_contract_recall", 0.0)) < 0.85:
        return False, "qualification_recall_below_threshold"
    if float(metrics.get("positive_unsupported_rate", 1.0)) > 0.05:
        return False, "qualification_unsupported_above_threshold"
    if int(metrics.get("safe_false_activation_count", 1)) != 0:
        return False, "qualification_safe_false_activation_nonzero"
    if float(metrics.get("evidence_resolution_rate", 0.0)) != 1.0:
        return False, "qualification_evidence_not_fully_resolved"
    if float(metrics.get("second_scan_llm_reduction", 0.0)) < 0.8:
        return False, "qualification_llm_reduction_below_threshold"
    return True, "ok"
