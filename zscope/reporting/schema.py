"""Report schema v3 authority, manifest, and exit-policy helpers."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from copy import deepcopy
from typing import Any, Dict, Iterable, Mapping, Sequence

from ..orchestration.candidate_envelope import CANDIDATE_SCHEMA_VERSION
from ..orchestration.proof_promotion_qualification import (
    load_runtime_successor_qualification as load_successor_qualification,
)
from ..orchestration.successor_runtime_review_status import (
    SUCCESSOR_RUNTIME_REVIEW_MANIFEST,
    validate_current_successor_runtime_review_status,
    validate_successor_runtime_review_status,
)
from ..orchestration.runtime_authority import (
    P5_RELEASE_STATUS,
    RUNTIME_CACHE_EPOCH,
    current_successor_reviewed,
    validate_runtime_authority_manifest,
)


REPORT_SCHEMA_VERSION = 3
RUN_MANIFEST_SCHEMA_VERSION = "zscope.run-manifest.v3"
# A report produced before the current deterministic successor was projected
# into its manifest must never become reusable merely because it happens to
# share the broader runtime-authority cache epoch.
REPORT_REUSE_EPOCH = "zscope.report-reuse.successor-bound.v1"
FINDING_STATUSES = {"clean", "needs_review", "confirmed"}
COMPLETENESS_STATUSES = {"complete", "partial", "degraded", "failed", "interrupted"}
EXIT_POLICIES = {"review", "confirmed", "legacy"}
NON_REVIEW_TERMINAL_DISPOSITIONS = {
    "confirmed",
    "rejected_with_proof",
    "deduplicated_alias",
    "shadow_observation",
}


def terminal_candidate_identity(item: Mapping[str, Any]) -> str:
    """Identity for a single evidence/context occurrence terminal."""

    validation_cluster_uid = str(item.get("validation_cluster_uid") or "")
    if validation_cluster_uid:
        return "|".join(("validation_cluster", validation_cluster_uid))
    occurrence_uid = str(item.get("occurrence_uid") or "")
    candidate_uid = str(item.get("candidate_uid") or "")
    evidence_hash = str(item.get("evidence_hash") or "")
    context_signature = str(item.get("context_signature") or "")
    if occurrence_uid and evidence_hash and context_signature:
        return "|".join(("occurrence", occurrence_uid, evidence_hash, context_signature))
    if candidate_uid and evidence_hash and context_signature:
        return "|".join(("candidate", candidate_uid, evidence_hash, context_signature))
    if occurrence_uid and evidence_hash:
        return "|".join(("occurrence", occurrence_uid, evidence_hash))
    if candidate_uid and evidence_hash:
        return "|".join(("candidate", candidate_uid, evidence_hash))
    return ""


def coalesce_terminal_candidates(
    items: Iterable[Any],
) -> list[Any]:
    """Coalesce exact terminal identities, retaining the safest disposition."""

    result: list[Any] = []
    positions: Dict[str, int] = {}
    priority = {
        "deduplicated_alias": 10,
        "rejected_with_proof": 20,
        "confirmed": 30,
        "needs_review": 40,
        "deferred_budget": 50,
        "engine_failed": 60,
        "interrupted": 70,
        "shadow_observation": 5,
    }

    def item_priority(item: Mapping[str, Any]) -> int:
        disposition = str(
            item.get("candidate_disposition") or item.get("disposition") or item.get("status") or ""
        ).lower()
        value = priority.get(disposition, 0)
        engine_status = str(item.get("engine_status") or "").lower()
        if engine_status == "interrupted":
            return max(value, 70)
        if engine_status == "failed":
            return max(value, 60)
        if engine_status in {"degraded", "pending"}:
            return max(value, 50)
        return value

    for raw in items:
        if not isinstance(raw, Mapping):
            result.append(raw)
            continue
        item = dict(raw)
        identity = terminal_candidate_identity(item)
        if not identity:
            result.append(item)
            continue
        position = positions.get(identity)
        if position is None:
            positions[identity] = len(result)
            result.append(item)
            continue

        existing = result[position]
        if not isinstance(existing, Mapping):
            result.append(item)
            continue
        existing_dict = dict(existing)
        winner, loser = (
            (item, existing_dict)
            if item_priority(item) > item_priority(existing_dict)
            else (existing_dict, item)
        )
        conflicts = {
            str(value)
            for value in (
                existing_dict.get("candidate_disposition"),
                existing_dict.get("status"),
                item.get("candidate_disposition"),
                item.get("status"),
            )
            if value
        }
        merged = dict(loser)
        merged.update(
            {key: value for key, value in winner.items() if value not in (None, "", [], {})}
        )
        if len(conflicts) > 1:
            merged["terminal_conflicts"] = sorted(conflicts)
        result[position] = merged
    return result


def _dict_items(items: Iterable[Any]) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for item in items or []:
        if isinstance(item, Mapping):
            result.append(item)
        elif hasattr(item, "to_dict"):
            value = item.to_dict()
            if isinstance(value, Mapping):
                result.append(value)
    return result


def engine_failure_terminal_states(
    capabilities: Any,
    *,
    scope: str = "",
) -> list[Dict[str, Any]]:
    """Convert non-complete engine states into visible terminal obligations."""

    terminal: list[Dict[str, Any]] = []

    def visit(value: Any, path: list[str]) -> None:
        if isinstance(value, Mapping):
            status = str(value.get("status") or "").lower()
            if status in {
                "degraded",
                "failed",
                "interrupted",
                "unavailable",
                "fallback",
                "pending",
                "partial",
                "budget_limited",
                "skipped_budget",
                "planned_no_llm_client",
            }:
                engine = ".".join(path) or "unknown"
                payload = {
                    "scope": scope,
                    "engine": engine,
                    "status": status,
                    "reason": str(value.get("reason") or ""),
                }
                digest = hashlib.sha256(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest()[:24]
                disposition = (
                    "interrupted"
                    if status == "interrupted"
                    else (
                        "deferred_budget"
                        if status
                        in {
                            "partial",
                            "budget_limited",
                            "skipped_budget",
                            "planned_no_llm_client",
                        }
                        else "engine_failed"
                    )
                )
                terminal.append(
                    {
                        "candidate_uid": f"ENGINE_{digest}",
                        "occurrence_uid": f"ENGINE_OCC_{digest}",
                        "operational_uid": f"OP_{digest}",
                        "record_role": "operational_obligation",
                        "candidate_disposition": disposition,
                        "status": disposition,
                        "engine": engine,
                        "engine_status": status,
                        "reason": payload["reason"],
                    }
                )
            for key, nested in value.items():
                if isinstance(nested, (Mapping, list, tuple)):
                    visit(nested, path + [str(key)])
        elif isinstance(value, (list, tuple)):
            for index, nested in enumerate(value):
                visit(nested, path + [str(index)])

    visit(capabilities, [])
    return terminal


def finding_status(
    issues: Iterable[Any],
    observations: Iterable[Any] = (),
) -> str:
    issue_dicts = [
        issue
        for issue in _dict_items(issues)
        if str(issue.get("record_role") or "") != "operational_obligation"
        and str(issue.get("candidate_disposition") or "").lower()
        not in {"deferred_budget", "engine_failed", "interrupted"}
    ]
    if any(
        str(issue.get("candidate_disposition") or "").lower() == "confirmed"
        or str(issue.get("validation_status") or "").lower()
        in {"validated", "verified", "confirmed"}
        for issue in issue_dicts
    ):
        return "confirmed"
    # Legacy reportable issues are confirmed unless explicitly routed elsewhere.
    if any(
        str(issue.get("candidate_disposition") or "").lower()
        not in {
            "needs_review",
            "deferred_budget",
            "engine_failed",
            "interrupted",
            "rejected_with_proof",
            "deduplicated_alias",
            "shadow_observation",
        }
        for issue in issue_dicts
    ):
        return "confirmed"
    if issue_dicts:
        return "needs_review"
    if any(
        str(item.get("record_role") or "") != "operational_obligation"
        and str(item.get("candidate_disposition") or "").lower()
        not in {"deferred_budget", "engine_failed", "interrupted"}
        | NON_REVIEW_TERMINAL_DISPOSITIONS
        and (
            str(item.get("candidate_disposition") or "").lower() == "needs_review"
            or str(item.get("validation_status") or "").lower()
            in {"needs_review", "uncertain", "unvalidated"}
        )
        for item in _dict_items(observations)
    ):
        return "needs_review"
    return "clean"


def needs_review_count(
    observations: Iterable[Any] = (),
    terminal_candidates: Iterable[Any] = (),
) -> int:
    """Count unique actionable review obligations across report projections.

    Candidate terminal states normally repeat observations.  Counting stable
    candidate/occurrence identities prevents that projection detail from
    inflating the public ``needs_review`` metric while still accounting for
    ledger-only deferred and engine-failed work.
    """

    identities: set[tuple[str, str]] = set()

    def add(item: Mapping[str, Any], *, fallback: str) -> None:
        disposition = str(
            item.get("candidate_disposition") or item.get("disposition") or ""
        ).lower()
        validation = str(item.get("validation_status") or "").lower()
        if str(item.get("record_role") or "") == "operational_obligation":
            return
        if disposition in {"deferred_budget", "engine_failed", "interrupted"}:
            return
        if disposition in NON_REVIEW_TERMINAL_DISPOSITIONS:
            return
        if disposition != "needs_review" and validation not in {
            "needs_review",
            "uncertain",
            "unvalidated",
        }:
            return
        for field in (
            "validation_cluster_uid",
            "occurrence_uid",
            "candidate_uid",
            "candidate_id",
            "dedup_key",
        ):
            value = str(item.get(field) or "")
            if value:
                identities.add((field, value))
                return
        identities.add(("fallback", fallback))

    for index, item in enumerate(_dict_items(observations)):
        add(item, fallback=f"observation:{index}")
    for index, item in enumerate(_dict_items(terminal_candidates)):
        add(item, fallback=f"terminal:{index}")
    return len(identities)


def unresolved_obligation_count(
    observations: Iterable[Any] = (),
    terminal_candidates: Iterable[Any] = (),
) -> int:
    """Count security-review and operational obligations without conflating them."""

    identities: set[tuple[str, str]] = set()
    for index, item in enumerate(_dict_items(observations) + _dict_items(terminal_candidates)):
        disposition = str(
            item.get("candidate_disposition") or item.get("disposition") or ""
        ).lower()
        validation = str(item.get("validation_status") or "").lower()
        if disposition not in {
            "needs_review",
            "deferred_budget",
            "engine_failed",
            "interrupted",
        } and validation not in {"needs_review", "uncertain", "unvalidated", "pending"}:
            continue
        if disposition in NON_REVIEW_TERMINAL_DISPOSITIONS:
            continue
        for field in (
            "operational_uid",
            "validation_cluster_uid",
            "occurrence_uid",
            "candidate_uid",
            "candidate_id",
        ):
            value = str(item.get(field) or "")
            if value:
                identities.add((field, value))
                break
        else:
            identities.add(("fallback", str(index)))
    return len(identities)


def completeness_status(
    state: Mapping[str, Any],
    candidates: Iterable[Any] = (),
) -> str:
    if state.get("interrupted") or state.get("_interrupted"):
        return "interrupted"
    if state.get("any_failure"):
        return "failed"
    ledger_summary = state.get("candidate_ledger_summary")
    if isinstance(ledger_summary, Mapping) and ledger_summary.get("incomplete"):
        return "degraded"
    capability_values: list[str] = []
    capabilities = state.get("engine_capabilities") or state.get("backend_capabilities")
    security_runtime = state.get("security_runtime")

    def collect_capability_statuses(value: Any) -> None:
        if isinstance(value, Mapping):
            status = str(value.get("status") or "").lower()
            if status:
                capability_values.append(status)
            for nested in value.values():
                if isinstance(nested, (Mapping, list, tuple)):
                    collect_capability_statuses(nested)
        elif isinstance(value, (list, tuple)):
            for nested in value:
                collect_capability_statuses(nested)

    collect_capability_statuses(capabilities)
    collect_capability_statuses(security_runtime)
    if "interrupted" in capability_values:
        return "interrupted"
    if any(
        value
        in {
            "partial",
            "budget_limited",
            "skipped_budget",
            "planned_no_llm_client",
        }
        for value in capability_values
    ):
        return "partial"
    if "failed" in capability_values:
        return "degraded"
    if any(
        value in {"degraded", "unavailable", "fallback", "pending"} for value in capability_values
    ):
        return "degraded"
    explicit = str(state.get("completeness") or state.get("scan_completeness") or "").lower()
    if explicit in COMPLETENESS_STATUSES:
        return explicit

    dispositions = {
        str(item.get("candidate_disposition") or item.get("disposition") or "").lower()
        for item in _dict_items(candidates)
    }
    if dispositions & {"deferred_budget", "engine_failed", "interrupted"}:
        if "interrupted" in dispositions:
            return "interrupted"
        return "degraded"
    return "complete"


def scan_outcome(finding: str, completeness: str) -> str:
    if completeness != "complete":
        return "incomplete"
    return finding if finding in FINDING_STATUSES else "clean"


def current_successor_runtime_binding() -> Dict[str, str]:
    """Load the exact fresh deterministic successor identity.

    This deliberately uses the strict qualification loader rather than the
    review-status projection.  An ``in_progress`` successor may produce a
    non-release report, while a stale/malformed qualification cannot be used
    to bind either a new report or a historical reuse decision.
    """

    successor = load_successor_qualification()
    implementation_root = str(successor["implementation_root_sha256"])
    qualification_sha256 = str(successor["content_sha256"])
    review_status = SUCCESSOR_RUNTIME_REVIEW_MANIFEST
    valid_review, reason = validate_successor_runtime_review_status(
        review_status,
        expected_implementation_root_sha256=implementation_root,
        expected_successor_qualification_sha256=qualification_sha256,
    )
    if not valid_review:
        raise ValueError(reason)
    current_review, current_reason = validate_current_successor_runtime_review_status(review_status)
    if review_status.get("status") == "reviewed":
        if not current_review:
            raise ValueError(current_reason)
    elif current_review or current_reason != "successor_review_in_progress":
        raise ValueError(current_reason)
    return {
        "successor_implementation_root_sha256": str(implementation_root),
        "successor_qualification_sha256": qualification_sha256,
        "successor_review_status": str(review_status["status"]),
        "successor_review_status_content_sha256": str(review_status["content_sha256"]),
        "successor_review_set_sha256": str(review_status["review_set_sha256"]),
    }


def report_reuse_blockers(
    report: Mapping[str, Any],
    *,
    expected_manifest: Mapping[str, Any] | None = None,
) -> list[str]:
    """Explain why a historical report cannot safely short-circuit analysis."""

    blockers: list[str] = []
    try:
        schema_version = int(report.get("schema_version") or 0)
    except (TypeError, ValueError):
        schema_version = 0
    if schema_version < REPORT_SCHEMA_VERSION:
        blockers.append("legacy_schema")
    if str(report.get("completeness") or "").lower() != "complete":
        blockers.append("scan_incomplete")
    if str(report.get("finding_status") or "").lower() == "needs_review":
        blockers.append("finding_needs_review")

    manifest = report.get("run_manifest")
    if not isinstance(manifest, Mapping) or manifest.get("valid") is not True:
        blockers.append("invalid_or_missing_manifest")
        manifest = {}
    if str(manifest.get("candidate_schema_version") or "") != CANDIDATE_SCHEMA_VERSION:
        blockers.append("candidate_schema_mismatch")
    if str(manifest.get("schema_version") or "") != RUN_MANIFEST_SCHEMA_VERSION:
        blockers.append("run_manifest_schema_mismatch")
    if str(manifest.get("report_reuse_epoch") or "") != REPORT_REUSE_EPOCH:
        blockers.append("report_reuse_epoch_mismatch")
    if str(manifest.get("cache_epoch") or "") != RUNTIME_CACHE_EPOCH:
        blockers.append("cache_epoch_mismatch")
    authority_manifest = manifest.get("runtime_authority_manifest")
    if not isinstance(authority_manifest, Mapping):
        blockers.append("runtime_authority_manifest_missing")
    else:
        valid_authority, _reason = validate_runtime_authority_manifest(authority_manifest)
        if not valid_authority:
            blockers.append("runtime_authority_manifest_invalid")
    trace = manifest.get("decision_trace")
    if not isinstance(trace, Mapping) or trace.get("complete") is not True:
        blockers.append("decision_trace_incomplete")

    try:
        current_successor = current_successor_runtime_binding()
    except (KeyError, OSError, TypeError, ValueError):
        blockers.append("successor_qualification_not_current")
        current_successor = {}
    for key in (
        "successor_implementation_root_sha256",
        "successor_qualification_sha256",
        "successor_review_status",
        "successor_review_status_content_sha256",
        "successor_review_set_sha256",
    ):
        expected = str(current_successor.get(key) or "")
        actual = str(manifest.get(key) or "")
        if key not in manifest:
            blockers.append(f"successor_binding_missing:{key}")
        elif actual != expected:
            blockers.append(f"successor_binding_mismatch:{key}")

    unresolved_dispositions = {
        "needs_review",
        "deferred_budget",
        "engine_failed",
        "interrupted",
    }
    unresolved_validation = {
        "needs_review",
        "uncertain",
        "unvalidated",
        "pending",
    }
    candidate_collections = [
        report.get("issues"),
        report.get("observations"),
        report.get("candidate_terminal_states"),
    ]
    metadata = report.get("metadata")
    if isinstance(metadata, Mapping):
        candidate_collections.append(metadata.get("audit_observations"))
    for collection in candidate_collections:
        for item in _dict_items(collection or []):
            disposition = str(
                item.get("candidate_disposition") or item.get("disposition") or ""
            ).lower()
            validation = str(item.get("validation_status") or "").lower()
            if disposition in unresolved_dispositions or validation in unresolved_validation:
                blockers.append("unresolved_candidate_terminal")
                break
        if "unresolved_candidate_terminal" in blockers:
            break

    if expected_manifest:
        for key in (
            "source_revision",
            "source_tree_hash",
            "config_hash",
            "model_manifest_hash",
            "knowledge_db_version",
            "effective_rules_sha256",
            "cache_epoch",
            "runtime_authority_sha256",
            "report_reuse_epoch",
            "successor_implementation_root_sha256",
            "successor_qualification_sha256",
            "successor_review_status",
            "successor_review_status_content_sha256",
            "successor_review_set_sha256",
        ):
            expected = str(expected_manifest.get(key) or "")
            if not expected:
                continue
            actual = str(manifest.get(key) or "")
            if actual != expected:
                blockers.append(f"manifest_mismatch:{key}")
    return list(dict.fromkeys(blockers))


def report_is_reusable(
    report: Mapping[str, Any],
    *,
    expected_manifest: Mapping[str, Any] | None = None,
) -> bool:
    return not report_reuse_blockers(
        report,
        expected_manifest=expected_manifest,
    )


def build_run_manifest(
    metadata: Mapping[str, Any],
    *,
    entry_function: str,
    finding: str,
    completeness: str,
    issue_count: int,
    needs_review_count: int,
    review_governance: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    governance = dict(review_governance or {})
    successor_binding = current_successor_runtime_binding()
    return {
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "report_reuse_epoch": REPORT_REUSE_EPOCH,
        **successor_binding,
        "run_id": metadata.get("run_id") or "",
        "entry_function": entry_function,
        "project_id": metadata.get("project_id") or "",
        "project_root": metadata.get("repo") or metadata.get("project_root") or "",
        "source_root": metadata.get("source_root") or "",
        "source_revision": metadata.get("commit_sha") or metadata.get("source_revision") or "",
        "source_tree_hash": metadata.get("source_tree_hash") or "",
        "config_hash": metadata.get("config_hash") or "",
        "model_manifest_hash": metadata.get("model_manifest_hash") or "",
        "effective_rules_sha256": metadata.get("effective_rules_sha256") or "",
        "rule_catalog": metadata.get("rule_catalog") or {},
        "rule_candidate_counts": metadata.get("rule_candidate_counts") or {},
        "workflow": metadata.get("workflow") or "",
        "scan_depth": metadata.get("scan_depth") or "fast",
        "effective_scan": metadata.get("effective_scan")
        or {
            "depth": metadata.get("scan_depth") or "fast",
            "rollout": metadata.get("rollout") or {},
        },
        "rollout": metadata.get("rollout") or {},
        "llm_usage": metadata.get("llm_usage") or {},
        "llm_usage_attribution": (
            (metadata.get("llm_usage") or {}).get("usage_attribution")
            if isinstance(metadata.get("llm_usage"), Mapping)
            else {}
        ),
        "knowledge_db_version": metadata.get("knowledge_db_version") or "",
        "candidate_schema_version": CANDIDATE_SCHEMA_VERSION,
        "cache_epoch": RUNTIME_CACHE_EPOCH,
        "runtime_authority_manifest": metadata.get("runtime_authority_manifest") or {},
        "runtime_authority_sha256": (
            (metadata.get("runtime_authority_manifest") or {}).get("content_sha256", "")
            if isinstance(metadata.get("runtime_authority_manifest"), Mapping)
            else ""
        ),
        "finding_status": finding,
        "completeness": completeness,
        "issue_count": int(issue_count),
        "needs_review_count": int(needs_review_count),
        "raw_occurrence_count": int(governance.get("raw_occurrence_count") or 0),
        "raw_projection_count": int(governance.get("raw_projection_count") or 0),
        "unique_security_obligation_count": int(
            governance.get("unique_security_obligation_count") or needs_review_count or 0
        ),
        "operational_obligation_count": int(governance.get("operational_obligation_count") or 0),
        "displayed_review_count": int(
            governance.get("displayed_review_count") or needs_review_count or 0
        ),
        "unresolved_obligation_count": int(
            governance.get("unique_security_obligation_count") or needs_review_count or 0
        )
        + int(governance.get("operational_obligation_count") or 0),
        "grouped_alias_count": int(governance.get("grouped_alias_count") or 0),
        "attached_to_confirmed_count": int(governance.get("attached_to_confirmed_count") or 0),
        "validation_not_completed_count": int(
            governance.get("validation_not_completed_count") or 0
        ),
        "pending_validation_count": int(governance.get("pending_validation_count") or 0),
        "valid": completeness == "complete",
        "resume_lineage": metadata.get("resume_lineage") or [],
        "engine_capabilities": metadata.get("engine_capabilities") or {},
        "timestamp": metadata.get("timestamp") or "",
    }


def apply_report_schema_v2(
    report: Dict[str, Any],
    *,
    state: Mapping[str, Any],
    issues: Sequence[Any],
    observations: Sequence[Any],
    metadata: Mapping[str, Any],
    entry_function: str,
) -> Dict[str, Any]:
    from .views import build_report_views, review_governance_summary

    raw_terminal_candidates = state.get("candidate_terminal_states")
    terminal_candidates = (
        list(raw_terminal_candidates) if isinstance(raw_terminal_candidates, (list, tuple)) else []
    )
    terminal_candidates.extend(
        engine_failure_terminal_states(
            state.get("engine_capabilities") or state.get("backend_capabilities") or {},
            scope=entry_function,
        )
    )
    terminal_candidates = coalesce_terminal_candidates(terminal_candidates)
    canonical_projection = bool(state.get("canonical_outcome_projection"))
    finding = finding_status(issues, list(observations) + list(terminal_candidates))
    completeness = completeness_status(
        state,
        list(issues) + list(observations) + list(terminal_candidates),
    )
    review_count = needs_review_count(
        observations,
        () if canonical_projection else terminal_candidates,
    )
    operational_terminal = [
        item
        for item in terminal_candidates
        if str(item.get("record_role") or "") == "operational_obligation"
        or str(item.get("candidate_disposition") or "").lower()
        in {"deferred_budget", "engine_failed", "interrupted"}
    ]
    governance = review_governance_summary(
        list(observations)
        + (operational_terminal if canonical_projection else list(terminal_candidates)),
        canonical_review=(
            [dict(item) for item in observations if isinstance(item, Mapping)]
            if canonical_projection
            else None
        ),
    )
    raw_views = report.get("report_views")
    default_items: Any = None
    with_review_items: Any = None
    if isinstance(raw_views, Mapping):
        raw_default = raw_views.get("default")
        raw_with_review = raw_views.get("with_needs_review")
        default_items = raw_default.get("issues") if isinstance(raw_default, Mapping) else None
        with_review_items = (
            raw_with_review.get("issues") if isinstance(raw_with_review, Mapping) else None
        )
    if not isinstance(default_items, list) or not isinstance(with_review_items, list):
        raw_views = build_report_views(
            [dict(item) for item in issues if isinstance(item, Mapping)],
            [dict(item) for item in observations if isinstance(item, Mapping)],
            canonical_projection=canonical_projection,
        )
        report["report_views"] = raw_views
        raw_default = raw_views.get("default")
        raw_with_review = raw_views.get("with_needs_review")
        default_items = raw_default.get("issues") if isinstance(raw_default, Mapping) else None
        with_review_items = (
            raw_with_review.get("issues") if isinstance(raw_with_review, Mapping) else None
        )
    invariant = report_invariant_status(
        issues,
        observations,
        terminal_candidates,
        canonical_projection=canonical_projection,
        default_items=(default_items if isinstance(default_items, list) else None),
        with_needs_review_items=(
            with_review_items if isinstance(with_review_items, list) else None
        ),
    )
    if "validation_queue_drained" in state and not bool(state.get("validation_queue_drained")):
        invariant["valid"] = False
        invariant["validation_queue_drained"] = False
    else:
        invariant["validation_queue_drained"] = True
    if not invariant["valid"] and completeness == "complete":
        completeness = "degraded"
    report.update(
        {
            "schema_version": REPORT_SCHEMA_VERSION,
            "finding_status": finding,
            "completeness": completeness,
            "scan_outcome": scan_outcome(finding, completeness),
            "candidate_terminal_states": list(terminal_candidates),
            "needs_review_governance": governance,
            "run_manifest": build_run_manifest(
                metadata,
                entry_function=entry_function,
                finding=finding,
                completeness=completeness,
                issue_count=len(issues),
                needs_review_count=review_count,
                review_governance=governance,
            ),
        }
    )
    report["run_manifest"]["canonical_validation_group_count"] = int(
        invariant["canonical_validation_group_count"]
    )
    report["run_manifest"].update(
        {
            key: int(invariant.get(key) or 0)
            for key in (
                "validation_group_alias_count",
                "validator_invocation_count",
                "rejected_with_proof_count",
                "deduplicated_alias_count",
                "shadow_observation_count",
                "audit_observation_count",
                "operational_obligation_count",
                "terminal_outcome_count",
                "unknown_terminal_disposition_count",
                "cluster_fragmentation_count",
            )
        }
    )
    report["run_manifest"]["report_invariant_status"] = invariant
    report["run_manifest"]["finding_root_count"] = int(state.get("finding_root_count", 0) or 0)
    report["run_manifest"]["finding_root_alias_count"] = int(
        state.get("finding_root_alias_count", 0) or 0
    )
    report["run_manifest"]["finding_root_projection"] = dict(
        state.get("finding_root_projection_summary") or {}
    )
    trace_manifest = state.get("decision_trace_manifest")
    if isinstance(trace_manifest, dict):
        report["run_manifest"]["decision_trace"] = {
            key: deepcopy(trace_manifest.get(key))
            for key in (
                "schema_version",
                "manifest_path",
                "manifest_sha256",
                "trace_count",
                "coverage_trace_count",
                "evidence_object_count",
                "model_event_count",
                "complete",
                "errors",
            )
        }
    for key in (
        "validator_session_count",
        "validator_api_call_count",
        "evidence_slice_token_count",
        "multi_turn_outlier_count",
        "snapshot_model_call_count",
        "fact_query_cache_hit_count",
    ):
        report["run_manifest"][key] = int(state.get(key, 0) or 0)
    report["run_manifest"]["validator_turn_distribution"] = dict(
        state.get("validator_turn_distribution") or {}
    )
    report["run_manifest"]["validator_prompt_tokens_by_stage"] = dict(
        state.get("validator_prompt_tokens_by_stage") or {}
    )
    report["run_manifest"]["budget_exhaustion_policy"] = str(
        state.get("budget_exhaustion_policy") or "observe"
    )
    report["run_manifest"]["validation_queue_drained"] = bool(
        state.get("validation_queue_drained", False)
    )
    release_blockers = []
    if not report["run_manifest"]["validation_queue_drained"]:
        release_blockers.append("validation_queue_not_drained")
    if report["run_manifest"]["budget_exhaustion_policy"] != "observe":
        release_blockers.append("budget_policy_not_observe_only")
    if not invariant["valid"]:
        release_blockers.append("report_invariant_failed")
    if P5_RELEASE_STATUS != "complete":
        release_blockers.append("p5_stage_not_complete")
    if not current_successor_reviewed():
        release_blockers.append("successor_review_not_current")
    authority_manifest = report["run_manifest"].get("runtime_authority_manifest")
    authority_valid = isinstance(authority_manifest, Mapping) and (
        validate_runtime_authority_manifest(authority_manifest)[0]
    )
    if not authority_valid:
        release_blockers.append("runtime_authority_manifest_invalid")
    trace = report["run_manifest"].get("decision_trace")
    if not isinstance(trace, Mapping) or trace.get("complete") is not True:
        release_blockers.append("decision_trace_incomplete")
    report["run_manifest"]["release_gate_status"] = {
        "runtime_valid": not release_blockers,
        "quality_evaluation_pending": True,
        "blockers": release_blockers,
    }
    return report


def report_invariant_status(
    issues: Sequence[Any],
    observations: Sequence[Any],
    terminal_candidates: Sequence[Any],
    *,
    canonical_projection: bool,
    default_items: Sequence[Any] | None = None,
    with_needs_review_items: Sequence[Any] | None = None,
) -> Dict[str, Any]:
    """Check that public report projections share one terminal source of truth."""

    issue_items = _dict_items(issues)
    observation_items = _dict_items(observations)
    terminal_items = _dict_items(terminal_candidates)
    confirmed_items = [
        item
        for item in issue_items
        if str(item.get("candidate_disposition") or "").lower() == "confirmed"
        or str(item.get("validation_status") or "").lower()
        in {"validated", "verified", "confirmed"}
    ]
    review_items = [
        item
        for item in observation_items
        if (
            str(item.get("candidate_disposition") or "").lower()
            not in NON_REVIEW_TERMINAL_DISPOSITIONS
            and (
                str(item.get("candidate_disposition") or "").lower() == "needs_review"
                or str(item.get("validation_status") or "").lower()
                in {"needs_review", "uncertain", "unvalidated"}
            )
        )
    ]
    terminal_confirmed_items = [
        item
        for item in terminal_items
        if str(item.get("candidate_disposition") or "").lower() == "confirmed"
    ]
    terminal_review_items = [
        item
        for item in terminal_items
        if str(item.get("candidate_disposition") or "").lower() == "needs_review"
    ]
    confirmed = len(confirmed_items)
    review = len(review_items)
    terminal_confirmed = len(terminal_confirmed_items)
    terminal_review = len(terminal_review_items)
    security_terminal = [
        item
        for item in terminal_items
        if str(item.get("record_role") or "") != "operational_obligation"
        and str(item.get("candidate_disposition") or "").lower() != "shadow_observation"
    ]
    clusters = {
        str(item.get("validation_cluster_uid") or "")
        for item in security_terminal
        if item.get("validation_cluster_uid")
    }
    terminal_dispositions = Counter(
        str(
            item.get("candidate_disposition")
            or item.get("terminal_disposition")
            or item.get("status")
            or ""
        ).lower()
        for item in terminal_items
    )
    known_dispositions = {
        "confirmed",
        "needs_review",
        "rejected_with_proof",
        "deduplicated_alias",
        "shadow_observation",
        "deferred_budget",
        "engine_failed",
        "interrupted",
    }
    unknown_terminal_count = sum(
        count
        for disposition, count in terminal_dispositions.items()
        if disposition not in known_dispositions
    )
    disposition_conservation = (
        sum(terminal_dispositions.values()) == len(terminal_items) and unknown_terminal_count == 0
    )
    open_completion_count = sum(
        1
        for item in terminal_items
        if str(item.get("evidence_completion_status") or "").lower()
        in {"requested", "running", "queued"}
        or str(item.get("evidence_completion_terminal_status") or "").lower()
        in {"requested", "running", "queued"}
    )
    open_validation_count = sum(
        1
        for item in terminal_items
        if str(item.get("status") or "").lower() in {"pending", "queued", "planned", "running"}
    )
    obligation_uids = {
        str(item.get("obligation_uid") or item.get("candidate_uid") or "")
        for item in security_terminal
    }

    def identity_projection(
        values: Sequence[Mapping[str, Any]],
    ) -> tuple[list[str], set[str], bool]:
        projected = [terminal_candidate_identity(item) for item in values]
        return projected, set(projected), all(projected)

    issue_identity_list, top_level_issue_identities, issue_identities_nonempty = (
        identity_projection(issue_items)
    )
    review_identity_list, review_identities, review_identities_nonempty = identity_projection(
        review_items
    )
    actual_default_items = _dict_items(default_items or ())
    actual_with_review_items = _dict_items(with_needs_review_items or ())
    actual_default_identity_list, actual_default_identities, actual_default_nonempty = (
        identity_projection(actual_default_items)
    )
    actual_with_review_identity_list, with_review_identities, actual_with_review_nonempty = (
        identity_projection(actual_with_review_items)
    )
    terminal_confirmed_identity_list, terminal_confirmed_identities, terminal_confirmed_nonempty = (
        identity_projection(terminal_confirmed_items)
    )
    terminal_review_identity_list, terminal_review_identities, terminal_review_nonempty = (
        identity_projection(terminal_review_items)
    )
    view_projection_available = default_items is not None and with_needs_review_items is not None
    view_item_shapes_valid = (
        view_projection_available
        and len(actual_default_items) == len(default_items or ())
        and len(actual_with_review_items) == len(with_needs_review_items or ())
    )
    top_level_only_confirmed = len(confirmed_items) == len(issue_items)
    identities_nonempty = all(
        (
            issue_identities_nonempty,
            review_identities_nonempty,
            actual_default_nonempty,
            actual_with_review_nonempty,
            terminal_confirmed_nonempty,
            terminal_review_nonempty,
        )
    )
    identities_unique = all(
        len(projected) == len(set(projected))
        for projected in (
            issue_identity_list,
            review_identity_list,
            actual_default_identity_list,
            actual_with_review_identity_list,
            terminal_confirmed_identity_list,
            terminal_review_identity_list,
        )
    )
    expected_with_review_identities = terminal_confirmed_identities | terminal_review_identities
    actual_default_exact = (
        view_projection_available
        and actual_default_identities == top_level_issue_identities == terminal_confirmed_identities
    )
    actual_with_review_exact = (
        view_projection_available and with_review_identities == expected_with_review_identities
    )
    view_conservation = bool(
        len(top_level_issue_identities) == confirmed
        and len(review_identities) == review
        and top_level_only_confirmed
        and top_level_issue_identities == terminal_confirmed_identities
        and review_identities == terminal_review_identities
        and view_projection_available
        and view_item_shapes_valid
        and identities_nonempty
        and identities_unique
        and actual_default_exact
        and actual_with_review_exact
    )
    default_subset = (
        view_projection_available and actual_default_identities <= with_review_identities
    )
    all_review_included = (
        view_projection_available and terminal_review_identities <= with_review_identities
    )
    valid = not canonical_projection or (
        confirmed == terminal_confirmed
        and review == terminal_review
        and len(clusters) == len(security_terminal)
        and open_completion_count == 0
        and open_validation_count == 0
        and disposition_conservation
        and view_conservation
        and default_subset
        and all_review_included
    )
    return {
        "valid": valid,
        "canonical_projection": canonical_projection,
        "default_confirmed_count": confirmed,
        "terminal_confirmed_count": terminal_confirmed,
        "displayed_review_count": review,
        "terminal_review_count": terminal_review,
        "shadow_observation_count": terminal_dispositions["shadow_observation"],
        "audit_observation_count": terminal_dispositions["shadow_observation"],
        "deduplicated_alias_count": terminal_dispositions["deduplicated_alias"],
        "operational_obligation_count": sum(
            terminal_dispositions[value]
            for value in ("deferred_budget", "engine_failed", "interrupted")
        ),
        "terminal_outcome_count": len(terminal_items),
        "terminal_disposition_counts": dict(sorted(terminal_dispositions.items())),
        "unknown_terminal_disposition_count": unknown_terminal_count,
        "terminal_outcome_conservation_passed": disposition_conservation,
        "view_membership_conservation_passed": view_conservation,
        "view_membership_item_shapes_valid": view_item_shapes_valid,
        "top_level_issues_are_terminal_confirmed": top_level_only_confirmed,
        "view_membership_identities_nonempty": identities_nonempty,
        "view_membership_identities_unique": identities_unique,
        "actual_default_membership_exact": actual_default_exact,
        "actual_with_needs_review_membership_exact": actual_with_review_exact,
        "default_is_with_needs_review_subset": default_subset,
        "all_canonical_needs_review_included": all_review_included,
        "canonical_validation_group_count": len(clusters),
        "validation_group_alias_count": sum(
            len(item.get("alias_occurrence_uids") or []) for item in terminal_items
        ),
        "validator_invocation_count": sum(
            int(item.get("validation_attempt_count") or 0) for item in terminal_items
        ),
        "rejected_with_proof_count": terminal_dispositions["rejected_with_proof"],
        "cluster_fragmentation_count": max(0, len(clusters) - len(obligation_uids)),
        "open_evidence_completion_count": open_completion_count,
        "open_validation_group_count": open_validation_count,
    }


def exit_code_for_report(
    report: Mapping[str, Any],
    *,
    policy: str = "review",
    legacy_issue_count: int = 0,
) -> int:
    policy = str(policy or "review").lower()
    if policy not in EXIT_POLICIES:
        raise ValueError(f"Unsupported exit policy: {policy}")
    completeness = str(report.get("completeness") or "complete").lower()
    if completeness != "complete":
        return 2
    if policy == "legacy":
        return 1 if int(legacy_issue_count or 0) > 0 else 0
    finding = str(
        report.get("finding_status")
        or ("confirmed" if int(legacy_issue_count or 0) > 0 else "clean")
    ).lower()
    if finding == "confirmed":
        return 1
    if policy == "review" and finding == "needs_review":
        return 1
    return 0
