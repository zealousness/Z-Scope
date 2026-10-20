"""Report schema v2 status, manifest, and exit-policy helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, Mapping, Sequence

from ..orchestration.candidate_envelope import CANDIDATE_SCHEMA_VERSION
from ..common.validator_protocol import VALIDATION_POLICY_VERSION

REPORT_SCHEMA_VERSION = 2
FINDING_STATUSES = {"clean", "needs_review", "confirmed"}
COMPLETENESS_STATUSES = {"complete", "partial", "degraded", "failed", "interrupted"}
EXIT_POLICIES = {"review", "confirmed", "legacy"}


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
    active_discovery = state.get("active_discovery")

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
    collect_capability_statuses(active_discovery)
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


def report_reuse_blockers(
    report: Mapping[str, Any],
    *,
    expected_manifest: Mapping[str, Any] | None = None,
    business_answer_store: Any = None,
) -> list[str]:
    """Explain why a historical report cannot safely short-circuit analysis."""

    blockers: list[str] = []
    from ..semantics.business_assumptions import feedback_reuse_problem

    feedback_problem = feedback_reuse_problem(report, business_answer_store)
    if feedback_problem:
        blockers.append(feedback_problem)
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
    if str(manifest.get("validation_policy_version") or "") != VALIDATION_POLICY_VERSION:
        blockers.append("validation_policy_mismatch")

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
    return {
        "schema_version": "zscope.run-manifest.v1",
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
        "validation_policy_version": VALIDATION_POLICY_VERSION,
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
        "wiki_telemetry": metadata.get("wiki_telemetry")
        or {
            "effective_mode": "off",
            "active_effective_mode": False,
            "wiki_context_injected": False,
            "resolution_count": 0,
            "wiki_resolution_count": 0,
            "source_fallback_count": 0,
            "none_count": 0,
            "knowledge_context_tokens": 0,
            "incremental_fact_count": 0,
            "selected_constraint_ids": {},
            "selected_source_ref_ids": {},
            "fallback_reasons": {},
        },
        "interface_probe": metadata.get("interface_probe")
        or {
            "probed": 0,
            "classified": 0,
            "declined": 0,
            "skipped_budget": 0,
            "skipped_known_role": 0,
            "skipped_external": 0,
            "skipped_no_client": 0,
            "errors": 0,
            "roles": {},
            "classified_functions": [],
        },
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
    from .views import review_governance_summary

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
    invariant = report_invariant_status(
        issues,
        observations,
        terminal_candidates,
        canonical_projection=canonical_projection,
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
                "cluster_fragmentation_count",
            )
        }
    )
    report["run_manifest"]["report_invariant_status"] = invariant
    report["run_manifest"]["finding_root_count"] = int(state.get("finding_root_count", 0) or 0)
    report["run_manifest"]["finding_root_alias_count"] = int(
        state.get("finding_root_alias_count", 0) or 0
    )
    report["run_manifest"]["aggregation_count"] = int(state.get("aggregation_count", 0) or 0)
    report["run_manifest"]["aggregation_alias_count"] = int(
        state.get("aggregation_alias_count", 0) or 0
    )
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
) -> Dict[str, Any]:
    """Check that public report projections share one terminal source of truth."""

    confirmed = sum(
        1
        for item in _dict_items(issues)
        if str(item.get("candidate_disposition") or "").lower() == "confirmed"
        or str(item.get("validation_status") or "").lower()
        in {"validated", "verified", "confirmed"}
    )
    review = sum(
        1
        for item in _dict_items(observations)
        if str(item.get("candidate_disposition") or "").lower() == "needs_review"
        or str(item.get("validation_status") or "").lower()
        in {"needs_review", "uncertain", "unvalidated"}
    )
    terminal_confirmed = sum(
        1
        for item in _dict_items(terminal_candidates)
        if str(item.get("candidate_disposition") or "").lower() == "confirmed"
    )
    terminal_review = sum(
        1
        for item in _dict_items(terminal_candidates)
        if str(item.get("candidate_disposition") or "").lower() == "needs_review"
    )
    security_terminal = [
        item
        for item in _dict_items(terminal_candidates)
        if str(item.get("record_role") or "") != "operational_obligation"
        and str(item.get("candidate_disposition") or "").lower() != "shadow_observation"
    ]
    clusters = {
        str(item.get("validation_cluster_uid") or "")
        for item in security_terminal
        if item.get("validation_cluster_uid")
    }
    terminal_items = _dict_items(terminal_candidates)
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
    valid = not canonical_projection or (
        confirmed == terminal_confirmed
        and review == terminal_review
        and len(clusters) == len(security_terminal)
        and open_completion_count == 0
        and open_validation_count == 0
    )
    return {
        "valid": valid,
        "canonical_projection": canonical_projection,
        "default_confirmed_count": confirmed,
        "terminal_confirmed_count": terminal_confirmed,
        "displayed_review_count": review,
        "terminal_review_count": terminal_review,
        "shadow_observation_count": sum(
            1
            for item in terminal_items
            if str(item.get("candidate_disposition") or "").lower() == "shadow_observation"
        ),
        "canonical_validation_group_count": len(clusters),
        "validation_group_alias_count": sum(
            len(item.get("alias_occurrence_uids") or []) for item in terminal_items
        ),
        "validator_invocation_count": sum(
            int(item.get("validation_attempt_count") or 0) for item in terminal_items
        ),
        "rejected_with_proof_count": sum(
            1
            for item in terminal_items
            if str(item.get("candidate_disposition") or "").lower() == "rejected_with_proof"
        ),
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
