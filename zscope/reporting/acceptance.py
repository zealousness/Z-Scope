"""Conservative acceptance and coverage projection over persisted reports.

This module answers one question per finding: what does the *current program
adjudication* already say?  It is a read-only projection over the report's
own fields and re-derivable decision records.  It never runs the Validator,
never replays native facts, never consults model text, scores or confidence,
and never mints new proof authority:

* ``confirmed`` requires ``deterministic_decision_proof(issue, "confirm")``
  to re-derive a complete proof from the issue's own records *and* the
  pipeline adjudication to agree (``validated`` / ``confirmed``).  Process
  attested receipts (dynamic witnesses, compiler review receipts, protocol
  business declarations) do not survive serialization, so findings depending
  on them stay ``pending`` on a loaded report even when the persisted status
  says ``validated``.
* ``ruled_out`` is the symmetric case for ``outcome="reject"``.
* ``business_conditional`` is only projected for object-protocol candidates
  whose persisted review sub-state *and* serialized assessment agree that
  the technical witness was current, no technical gap is open, and only
  business premises stay unconfirmed.  Any technical gap, denied premise,
  stale binding or missing receipt degrades the row to ``pending``.
* Model verdicts (``verified``/``rejected``), high scores, confidence,
  labels, missing dynamic triggers, suppression, shadow telemetry and human
  dispositions never promote a finding.

Severity, coverage, suppression and shadow observations stay independent
axes; nothing here merges them into the adjudication state.  The projection
is bounded in length and copies neither evidence packs nor protocol paths.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..common.issue_identity import issue_build_context_id
from ..core.validation.proofs import deterministic_decision_proof

ACCEPTANCE_PROJECTION_SCHEMA = "zscope.acceptance-projection.v1"

STATE_CONFIRMED = "confirmed"
STATE_BUSINESS_CONDITIONAL = "business_conditional"
STATE_PENDING = "pending"
STATE_RULED_OUT = "ruled_out"
ACCEPTANCE_STATES = frozenset(
    {STATE_CONFIRMED, STATE_BUSINESS_CONDITIONAL, STATE_PENDING, STATE_RULED_OUT}
)

# Suppression decisions are operator/baseline inputs, not programmatic
# adjudication; they must never read as a proof-backed rejection.
_SUPPRESSION_SOURCES = frozenset({"user_config", "finding_baseline", "static_analysis"})

_DEFERRED_DISPOSITIONS = frozenset({"deferred_budget", "engine_failed", "interrupted"})

# Display vocabulary for the persisted dynamic-reproduction outcome.  Mirrors
# ``RESULT_OUTCOME_BY_PROVIDER_OUTCOME`` in
# ``zscope/core/validation/dynamic_reproduction.py``; a reproduction status is
# never an adjudication input, so an unmapped outcome degrades to "unknown".
_REPRODUCTION_STATUS_BY_OUTCOME = {
    "witness_observed": "reproduced",
    "reproduced": "reproduced",
    "not_reproduced": "not_reproduced",
    "inconclusive": "inconclusive",
    "failed": "failed",
    "engine_failed": "failed",
    "unsupported": "inconclusive",
    "cancelled": "inconclusive",
}

_TEXT_LIMIT = 240
_RESOURCE_LABEL_LIMIT = 160
_MAX_GAP_ENTRIES = 16
_MAX_BUILD_COVERAGE_REASONS = 8
_MAX_BUILD_COVERAGE_INSTANCES = 32


def acceptance_for_issue(
    issue: Any,
    report_context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Project the conservative acceptance state of one report finding.

    ``issue`` must be the *full* finding mapping (the compact dashboard
    projection drops ``evidence_pack`` and proof records, which the
    re-derivation checks need).  ``report_context`` is the mapping returned
    by :func:`report_context_for`; unknown/legacy report vintages force
    ``pending`` for every row.  Unknown display fields stay ``None``.
    """

    record = issue if isinstance(issue, Mapping) else {}
    state, reason = _adjudication_state(record, report_context)
    return {
        "state": state,
        "reason": reason,
        "resource_label": _resource_label(record),
        "build_context_id": _build_context(record),
        "trigger_summary": _trigger_summary(record),
        "reproduction": _reproduction(record),
        "sources_count": _sources_count(record),
    }


def report_context_for(report: Any) -> Dict[str, Any]:
    """Build the per-report context shared by all per-issue projections."""

    data = report if isinstance(report, Mapping) else {}
    return {"schema_version": data.get("schema_version")}


def acceptance_coverage(report: Any) -> Dict[str, Any]:
    """Project report-level coverage: completeness, build coverage, gaps.

    Every value comes from the report's own metadata.  Unknown or
    unmeasured signals stay ``None`` (never ``0`` or ``False``), and
    truncation keeps a visible marker instead of silently dropping gaps.
    """

    data = report if isinstance(report, Mapping) else {}
    metadata = data.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    completeness = str(data.get("completeness") or "").strip() or None
    build_source = metadata.get("build_coverage")
    gaps = _coverage_gaps(data, metadata, build_source, completeness)
    return {
        "completeness": completeness,
        "build_coverage": _build_coverage_projection(build_source),
        "gaps": gaps,
        "deferred_count": _deferred_count(data, metadata),
    }


def _adjudication_state(
    issue: Mapping[str, Any],
    report_context: Optional[Mapping[str, Any]],
) -> Tuple[str, str]:
    if not issue:
        return STATE_PENDING, "invalid_issue_payload"
    if _legacy_report(report_context):
        return STATE_PENDING, "legacy_report_schema"
    if _is_shadow(issue):
        # Shadow rows keep their proof records as telemetry only.
        return STATE_PENDING, "shadow_observation_not_adjudication"
    if issue.get("evidence_conflict") is True:
        return STATE_PENDING, "conflicting_programmatic_proofs"
    status = str(issue.get("validation_status") or "").strip().lower()
    disposition = str(issue.get("candidate_disposition") or "").strip().lower()
    if _is_protocol_candidate(issue):
        return _protocol_state(issue, status, disposition)
    if status == "validated" or disposition == "confirmed":
        return _confirmed_state(issue)
    if status == "rejected" or disposition == "rejected_with_proof":
        return _rejected_state(issue)
    return _open_state(issue, status, disposition)


def _confirmed_state(issue: Mapping[str, Any]) -> Tuple[str, str]:
    proof = deterministic_decision_proof(issue, outcome="confirm")
    if proof is not None:
        return STATE_CONFIRMED, "deterministic_confirmation_proof_current"
    if isinstance(issue.get("decision_proof"), Mapping):
        # A serialized proof record that cannot be re-derived here (dynamic
        # witness attestations, protocol receipts, ...) is not current
        # authority, however complete it looked at scan time.
        return STATE_PENDING, "proof_not_replayable_from_report"
    promotion = str(issue.get("promotion_reason") or "")
    if promotion == "model_high_confidence_confirmation" or issue.get("confirmed_via"):
        return STATE_PENDING, "model_verdict_without_proof"
    return STATE_PENDING, "policy_confirmation_without_proof"


def _rejected_state(issue: Mapping[str, Any]) -> Tuple[str, str]:
    source = str(issue.get("rejection_source") or "").strip().lower()
    if source in _SUPPRESSION_SOURCES:
        return STATE_PENDING, "suppression_not_adjudication"
    proof = deterministic_decision_proof(issue, outcome="reject")
    if proof is not None:
        return STATE_RULED_OUT, "deterministic_rejection_proof_current"
    return STATE_PENDING, "rejection_without_replayable_proof"


def _open_state(issue: Mapping[str, Any], status: str, disposition: str) -> Tuple[str, str]:
    if status in {"engine_failed", "operational"} or disposition in _DEFERRED_DISPOSITIONS:
        return STATE_PENDING, "validation_not_completed"
    sub_state = str(issue.get("needs_review_sub_state") or "").strip().lower()
    if sub_state == "model_rejected_unproven":
        return STATE_PENDING, "model_rejection_without_proof"
    if sub_state == "policy_pending_promotion":
        return STATE_PENDING, "pending_policy_promotion"
    if sub_state == "model_uncertain" or status == "uncertain":
        return STATE_PENDING, "model_uncertain"
    if sub_state in {"business_conditional", "protocol_pending"}:
        # A protocol sub-state on a non-protocol row is inconsistent data,
        # not a business adjudication.
        return STATE_PENDING, "protocol_assessment_not_current"
    if status in {"pending", "unvalidated", ""}:
        return STATE_PENDING, "validation_not_completed"
    if status == "needs_review" or disposition == "needs_review":
        return STATE_PENDING, "adjudication_incomplete"
    return STATE_PENDING, "adjudication_unknown"


def _protocol_state(issue: Mapping[str, Any], status: str, disposition: str) -> Tuple[str, str]:
    if status == "validated" or disposition == "confirmed":
        # ``protocol_confirmation`` requires the live checked receipt; a
        # persisted report can never re-supply it, so even an established
        # scan-time confirmation stays unconfirmed here.
        return STATE_PENDING, "protocol_confirmation_requires_current_replay"
    if status == "rejected" or disposition == "rejected_with_proof":
        source = str(issue.get("rejection_source") or "").strip().lower()
        if source in _SUPPRESSION_SOURCES:
            return STATE_PENDING, "suppression_not_adjudication"
        return STATE_PENDING, "rejection_without_replayable_proof"
    sub_state = str(issue.get("needs_review_sub_state") or "").strip().lower()
    assessment = issue.get("protocol_assessment")
    if sub_state == "business_conditional" and _serialized_assessment_consistent(issue, assessment):
        return STATE_BUSINESS_CONDITIONAL, "business_premises_unconfirmed"
    if sub_state == "protocol_pending" or _assessment_has_technical_gaps(assessment):
        return STATE_PENDING, "technical_gaps_open"
    return STATE_PENDING, "protocol_assessment_not_current"


def _serialized_assessment_consistent(issue: Mapping[str, Any], assessment: Any) -> bool:
    """Whether a serialized assessment still matches the issue it bound.

    The process-local replay receipt cannot survive JSON, so this checks
    internal consistency of the persisted payload plus the candidate
    binding recomputed from the current issue identity.  It never upgrades
    the row; it only refuses to echo a stale or forged ``conditional``.
    """

    if not isinstance(assessment, Mapping):
        return False
    if not str(assessment.get("schema") or "").startswith("zscope.protocol-assessment."):
        return False
    if str(assessment.get("state") or "") != "conditional":
        return False
    if assessment.get("technical_witness_current") is not True:
        return False
    if _assessment_has_technical_gaps(assessment):
        return False
    assumptions = assessment.get("assumptions")
    if not isinstance(assumptions, list) or not assumptions:
        return False
    for assumption in assumptions:
        if not isinstance(assumption, Mapping):
            return False
        if str(assumption.get("status") or "") not in {"unconfirmed", "accepted"}:
            return False
    if issue.get("blocking_negative_evidence") is True:
        return False
    binding = _protocol_candidate_binding(issue)
    return bool(binding) and str(assessment.get("candidate_binding") or "") == binding


def _assessment_has_technical_gaps(assessment: Any) -> bool:
    if not isinstance(assessment, Mapping):
        return False
    gaps = assessment.get("technical_gaps")
    return isinstance(gaps, list) and bool(gaps)


def _protocol_candidate_binding(issue: Mapping[str, Any]) -> str:
    """Recompute the assessment candidate binding for the current issue.

    Reuses the assessment module's own identity recipe so the check cannot
    drift from the producer; any failure stays closed (empty string).
    """

    try:
        from ..core.validation import protocol_assessment

        identity = getattr(protocol_assessment, "_identity", None)
        if callable(identity):
            return str(identity(dict(issue)) or "")
    except Exception:
        pass
    return ""


def _is_protocol_candidate(issue: Mapping[str, Any]) -> bool:
    try:
        from ..core.validation.protocol_assessment import is_protocol_candidate

        return bool(is_protocol_candidate(dict(issue)))
    except Exception:
        return False


def _is_shadow(issue: Mapping[str, Any]) -> bool:
    return (
        str(issue.get("validation_status") or "").strip().lower() == "shadow"
        or str(issue.get("candidate_disposition") or "").strip().lower() == "shadow_observation"
        or str(issue.get("finding_kind") or "").strip().lower() == "rollout_shadow_observation"
    )


def _legacy_report(report_context: Optional[Mapping[str, Any]]) -> bool:
    """Old or unknown report vintages stay pending; only v2+ rows adjudicate."""

    if not isinstance(report_context, Mapping) or "schema_version" not in report_context:
        return False
    from .schema import REPORT_SCHEMA_VERSION

    raw_version: Any = report_context.get("schema_version")
    try:
        version = int(raw_version)
    except (TypeError, ValueError):
        return True
    required: int = REPORT_SCHEMA_VERSION
    return version < required


def _resource_label(issue: Mapping[str, Any]) -> Optional[str]:
    pack = issue.get("evidence_pack")
    pack = pack if isinstance(pack, Mapping) else {}
    for value in (
        issue.get("resource_identity"),
        pack.get("resource_identity"),
        issue.get("resource_signature"),
        pack.get("resource_signature"),
        issue.get("owner_object"),
    ):
        text = str(value or "").strip()
        if text:
            return _bounded(text, _RESOURCE_LABEL_LIMIT)
    return None


def _build_context(issue: Mapping[str, Any]) -> Optional[str]:
    value = issue_build_context_id(issue)
    if value:
        return value
    assessment = issue.get("protocol_assessment")
    if isinstance(assessment, Mapping):
        recorded = str(assessment.get("build_context_id") or "").strip()
        if recorded:
            return recorded
    return None


def _trigger_summary(issue: Mapping[str, Any]) -> Optional[str]:
    value = issue.get("trigger_condition")
    if not isinstance(value, str) or not value.strip():
        return None
    return _bounded(value.strip(), _TEXT_LIMIT)


def _reproduction(issue: Mapping[str, Any]) -> Dict[str, Any]:
    record = issue.get("dynamic_reproduction")
    outcome = ""
    provider = ""
    detail = ""
    if isinstance(record, Mapping):
        outcome = str(record.get("provider_outcome") or "").strip()
        provider = str(record.get("provider") or "").strip()
        detail = str(record.get("provider_detail") or "").strip()
    if not outcome:
        outcome = str(issue.get("dynamic_reproduction_outcome") or "").strip()
    if not outcome:
        return {"status": "not_measured", "summary": None}
    status = _REPRODUCTION_STATUS_BY_OUTCOME.get(outcome, "unknown")
    parts = [part for part in (provider, outcome, detail) if part]
    summary = _bounded("; ".join(parts), _TEXT_LIMIT) if parts else None
    return {"status": status, "summary": summary}


def _sources_count(issue: Mapping[str, Any]) -> Optional[int]:
    value = issue.get("evidence_sources")
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return None
    unique = {str(item).strip() for item in value if str(item).strip()}
    return len(unique) if unique else None


def _build_coverage_projection(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    raw_reasons = value.get("reasons")
    reasons: List[str] = []
    if isinstance(raw_reasons, list):
        for reason in raw_reasons:
            text = str(reason or "").strip()
            if text:
                reasons.append(text)
    view = str(value.get("view") or "").strip()
    pinned = str(value.get("pinned_build_context_id") or "").strip()
    scan_complete = (
        value.get("scan_complete") if isinstance(value.get("scan_complete"), bool) else None
    )
    if view == "instance":
        # A per-entry view is pinned to one instance and counts that source's
        # siblings around it; it never stands for scan coverage.
        scan_complete = False
    projection: Dict[str, Any] = {
        "status": str(value.get("status") or "").strip() or None,
        "extraction_complete": (
            value.get("extraction_complete")
            if isinstance(value.get("extraction_complete"), bool)
            else None
        ),
        "scan_complete": scan_complete,
        "instances": _optional_int(value.get("instances")),
        "sources": _optional_int(value.get("sources")),
        "reasons": reasons[:_MAX_BUILD_COVERAGE_REASONS],
    }
    uncurrent = value.get("uncurrent_instances")
    if isinstance(uncurrent, list):
        projection["uncurrent_instances"] = [
            str(item) for item in uncurrent if str(item or "").strip()
        ][:_MAX_BUILD_COVERAGE_INSTANCES]
    input_status = value.get("instance_input_status")
    if isinstance(input_status, Mapping):
        projection["instance_input_status"] = {
            str(build): str(status)
            for build, status in list(input_status.items())[:_MAX_BUILD_COVERAGE_INSTANCES]
            if str(build or "").strip()
        }
    if view:
        projection["view"] = view
    if pinned:
        projection["pinned_build_context_id"] = pinned
    return projection


def _coverage_gaps(
    report: Mapping[str, Any],
    metadata: Mapping[str, Any],
    build_source: Any,
    completeness: Optional[str],
) -> List[Dict[str, Any]]:
    gaps: List[Dict[str, Any]] = []
    if completeness is not None and completeness != "complete":
        gaps.append({"kind": "scan_completeness", "detail": completeness})
    entry_plan = metadata.get("entry_instances")
    if isinstance(entry_plan, Mapping) and entry_plan.get("scan_coverage_complete") is False:
        gaps.append(
            {
                "kind": "entry_instance_coverage_incomplete",
                "detail": "compile-instance scan coverage remains incomplete",
            }
        )
        for gap in entry_plan.get("gaps") or []:
            if isinstance(gap, Mapping):
                gaps.append(
                    {
                        "kind": str(gap.get("reason") or "entry_instance_unverified"),
                        "detail": str(gap.get("detail") or "") or None,
                    }
                )
    if isinstance(build_source, Mapping):
        raw_reasons = build_source.get("reasons")
        reasons = (
            [str(reason or "").strip() for reason in raw_reasons]
            if isinstance(raw_reasons, list)
            else []
        )
        failed = build_source.get("failed_instances")
        failed_count = len(failed) if isinstance(failed, list) else 0
        emitted_instance_gap = False
        for reason in reasons:
            if not reason:
                continue
            detail: Optional[str] = None
            if reason == "incomplete_compilation_instances":
                emitted_instance_gap = True
                detail = f"count={failed_count}" if failed_count else None
            gaps.append({"kind": reason, "detail": detail})
        if failed_count and not emitted_instance_gap:
            gaps.append(
                {"kind": "incomplete_compilation_instances", "detail": f"count={failed_count}"}
            )
    governance = report.get("needs_review_governance")
    if isinstance(governance, Mapping):
        for key, kind in (
            ("validation_not_completed_count", "validation_not_completed"),
            ("pending_validation_count", "pending_validation"),
        ):
            count = _optional_int(governance.get(key))
            if count:
                gaps.append({"kind": kind, "detail": f"count={count}"})
    if len(gaps) > _MAX_GAP_ENTRIES:
        omitted = len(gaps) - _MAX_GAP_ENTRIES + 1
        gaps = gaps[: _MAX_GAP_ENTRIES - 1]
        gaps.append({"kind": "additional_gaps_omitted", "detail": f"count={omitted}"})
    return gaps


def _deferred_count(report: Mapping[str, Any], metadata: Mapping[str, Any]) -> Optional[int]:
    """Count real deferred work items; unmeasured collections stay ``None``."""

    collections = (report.get("candidate_terminal_states"), metadata.get("audit_observations"))
    if not any(isinstance(collection, list) for collection in collections):
        return None
    seen: set = set()
    count = 0
    for collection in collections:
        if not isinstance(collection, list):
            continue
        for item in collection:
            if not isinstance(item, Mapping):
                continue
            disposition = str(
                item.get("candidate_disposition") or item.get("disposition") or ""
            ).lower()
            if disposition not in _DEFERRED_DISPOSITIONS:
                continue
            uid = str(item.get("candidate_uid") or item.get("occurrence_uid") or "")
            if uid:
                if uid in seen:
                    continue
                seen.add(uid)
            count += 1
    return count


def _optional_int(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _bounded(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"
