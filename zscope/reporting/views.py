"""Helpers for exposing alternate report views."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..common.issue_identity import (
    canonical_category,
    canonical_issue_key,
    deduplicate_issues,
    flatten_issue_text,
    issue_call_path_signature,
    issue_resource_signature,
    issue_sink_signature,
    normalize_issue_fields,
    parse_issue_location,
    report_cluster_category,
    root_cause_token,
)
from ..core.validation.evidence import compact_validation_evidence_pack

DEFAULT_REPORT_VIEW = "default"
WITH_NEEDS_REVIEW_REPORT_VIEW = "with_needs_review"
NEEDS_REVIEW_STATUSES = {
    "needs_review",
    "uncertain",
    "unvalidated",
}
NEEDS_REVIEW_DISPOSITIONS = {
    "needs_review",
}
OPERATIONAL_DISPOSITIONS = {
    "deferred_budget",
    "engine_failed",
    "interrupted",
}


def issue_dicts(items: Iterable[Any]) -> List[Dict[str, Any]]:
    """Return dict copies for report-like issue objects."""
    result: List[Dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, dict):
            result.append(deepcopy(item))
        elif hasattr(item, "to_dict"):
            value = item.to_dict()
            if isinstance(value, dict):
                result.append(deepcopy(value))
    return result


def needs_review_observations(items: Iterable[Any]) -> List[Dict[str, Any]]:
    """Filter audit observations that should appear in the review-inclusive view."""
    observations = issue_dicts(items)
    return [
        issue
        for issue in observations
        if (
            str(issue.get("record_role") or "") != "operational_obligation"
            and str(issue.get("candidate_disposition") or "").lower()
            not in OPERATIONAL_DISPOSITIONS
            and (
                str(issue.get("validation_status") or "").lower()
                in NEEDS_REVIEW_STATUSES
                or str(issue.get("candidate_disposition") or "").lower()
                in NEEDS_REVIEW_DISPOSITIONS
            )
        )
    ]


def _review_cluster_key(issue: Dict[str, Any]) -> Tuple[str, ...]:
    validation_cluster_uid = str(issue.get("validation_cluster_uid") or "")
    if validation_cluster_uid:
        return ("validation_cluster", validation_cluster_uid)
    candidate_uid = str(issue.get("candidate_uid") or "")
    decision_hash = str(issue.get("decision_evidence_hash") or "")
    if candidate_uid and decision_hash:
        return ("candidate_decision", candidate_uid, decision_hash)
    # Legacy observations do not contain enough information for cross-entry
    # verdict sharing.  Keep their conservative issue identity.
    return ("legacy", canonical_issue_key(issue))


def _list_values(issue: Dict[str, Any], *names: str) -> List[Any]:
    values: List[Any] = []
    for name in names:
        raw = issue.get(name)
        if isinstance(raw, list):
            values.extend(raw)
        elif raw not in (None, ""):
            values.append(raw)
    return values


def coalesce_review_observations(
    items: Iterable[Any],
) -> List[Dict[str, Any]]:
    """Return one actionable row per structural validation obligation.

    Occurrences and provenance are unioned onto the canonical row.  This is a
    structured lifecycle projection; it never uses prose similarity.
    """

    review_items = needs_review_observations(items)
    buckets: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
    for issue in review_items:
        normalize_issue_fields(issue)
        buckets.setdefault(_review_cluster_key(issue), []).append(issue)

    result: List[Dict[str, Any]] = []
    for key in sorted(buckets):
        group = sorted(
            buckets[key],
            key=lambda item: (
                _record_fingerprint(item),
                str(item.get("id") or ""),
            ),
        )
        primary = _compact_observation(group[0])
        evidence_pack = primary.get("evidence_pack")
        if isinstance(evidence_pack, dict):
            primary["evidence_pack"] = compact_validation_evidence_pack(
                evidence_pack
            )
        occurrence_uids: List[str] = []
        entries: List[str] = []
        entry_paths: List[Any] = []
        validation_contexts: List[str] = []
        evidence_hashes: List[str] = []
        provenance_hashes: List[str] = []
        occurrences: List[Dict[str, Any]] = []

        for item in group:
            occurrence_uids.extend(
                str(value)
                for value in _list_values(item, "occurrence_uids", "occurrence_uid")
                if str(value)
            )
            entries.extend(
                str(value)
                for value in _list_values(
                    item,
                    "entries",
                    "entry_identity",
                    "entry_function",
                )
                if str(value)
            )
            entry_paths.extend(_list_values(item, "entry_paths", "call_paths"))
            validation_contexts.extend(
                str(value)
                for value in _list_values(
                    item,
                    "validation_contexts",
                    "context_signature",
                )
                if str(value)
            )
            evidence_hashes.extend(
                str(value)
                for value in _list_values(item, "evidence_hashes", "evidence_hash")
                if str(value)
            )
            provenance_hashes.extend(
                str(value)
                for value in _list_values(
                    item,
                    "provenance_hashes",
                    "provenance_hash",
                )
                if str(value)
            )
            raw_occurrences = item.get("occurrences")
            if isinstance(raw_occurrences, list):
                occurrences.extend(
                    deepcopy(value)
                    for value in raw_occurrences
                    if isinstance(value, dict)
                )

        def stable_unique(values: Iterable[Any]) -> List[Any]:
            unique: Dict[str, Any] = {}
            for value in values:
                fingerprint = _record_fingerprint(value) if isinstance(value, dict) else _stable_value(value)
                unique.setdefault(fingerprint, value)
            return [unique[name] for name in sorted(unique)]

        occurrence_uids = stable_unique(occurrence_uids)
        entries = stable_unique(entries)
        entry_paths = stable_unique(entry_paths)
        validation_contexts = stable_unique(validation_contexts)
        evidence_hashes = stable_unique(evidence_hashes)
        provenance_hashes = stable_unique(provenance_hashes)
        occurrences = stable_unique(occurrences)

        primary["occurrence_uids"] = occurrence_uids
        primary["occurrence_count"] = len(occurrence_uids) or max(1, len(group))
        primary["entries"] = entries
        primary["entry_count"] = len(entries)
        primary["entry_paths"] = entry_paths
        primary["validation_contexts"] = validation_contexts
        primary["evidence_hashes"] = evidence_hashes
        primary["provenance_hashes"] = provenance_hashes
        if occurrences:
            primary["occurrences"] = occurrences
        primary["grouped_observation_count"] = len(group)
        primary["alias_occurrence_uids"] = occurrence_uids[1:]
        result.append(primary)
    return result


def _stable_value(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def review_governance_summary(
    items: Iterable[Any],
    *,
    canonical_review: Optional[List[Dict[str, Any]]] = None,
    attached_count: int = 0,
) -> Dict[str, Any]:
    observations = issue_dicts(items)
    canonical = canonical_review if canonical_review is not None else coalesce_review_observations(observations)
    occurrence_ids: set[str] = set()
    fallback_occurrences = 0
    operational_keys: set[str] = set()
    security_projection_count = 0
    validation_not_completed_count = 0
    pending_validation_count = 0
    by_disposition: Dict[str, int] = {}
    by_reason: Dict[str, int] = {}
    for index, item in enumerate(observations):
        disposition = str(item.get("candidate_disposition") or "").lower()
        if disposition:
            by_disposition[disposition] = by_disposition.get(disposition, 0) + 1
        reason = str(item.get("reason") or item.get("deferred_reason") or "")
        if reason:
            by_reason[reason] = by_reason.get(reason, 0) + 1
            if reason == "validation_not_completed":
                validation_not_completed_count += 1
        status = str(item.get("status") or "").lower()
        if (
            str(item.get("record_role") or "") == "validation_obligation"
            and status in {"pending", "queued", "planned", "running"}
        ):
            pending_validation_count += 1
        is_operational = (
            disposition in OPERATIONAL_DISPOSITIONS
            or str(item.get("record_role") or "") == "operational_obligation"
        )
        is_security_review = (
            not is_operational
            and (
                disposition == "needs_review"
                or str(item.get("validation_status") or "").lower()
                in NEEDS_REVIEW_STATUSES
            )
        )
        if is_security_review:
            security_projection_count += 1
            values = _list_values(item, "occurrence_uids", "occurrence_uid")
            if values:
                occurrence_ids.update(
                    str(value) for value in values if str(value)
                )
            else:
                fallback_occurrences += 1
        if is_operational:
            operational_keys.add(
                str(
                    item.get("operational_uid")
                    or item.get("candidate_uid")
                    or f"{item.get('engine')}|{item.get('engine_status')}|{reason}|{index}"
                )
            )
    raw_occurrence_count = len(occurrence_ids) + fallback_occurrences
    displayed = len(canonical)
    return {
        "raw_occurrence_count": raw_occurrence_count,
        "raw_projection_count": security_projection_count,
        "unique_security_obligation_count": displayed,
        "operational_obligation_count": len(operational_keys),
        "displayed_review_count": displayed,
        "grouped_alias_count": max(
            0,
            security_projection_count - displayed,
        ),
        "attached_to_confirmed_count": int(attached_count),
        "validation_not_completed_count": validation_not_completed_count,
        "pending_validation_count": pending_validation_count,
        "by_disposition": dict(sorted(by_disposition.items())),
        "by_reason": dict(sorted(by_reason.items())),
    }


def group_by_severity(issues: Iterable[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }
    for issue in issues:
        level = str(issue.get("impact_level") or "medium").lower()
        if level not in groups:
            level = "medium"
        groups[level].append(issue)
    return groups


def _issue_location_parts(issue: Dict[str, Any]) -> Tuple[str, Optional[int]]:
    return parse_issue_location(str(issue.get("location") or issue.get("file") or ""))


def _issue_root_signature(issue: Dict[str, Any]) -> Tuple[str, str, str]:
    text = flatten_issue_text(issue)
    file_path, _line = _issue_location_parts(issue)
    category = canonical_category(issue, text)
    root = root_cause_token(issue, category, text)
    return file_path, str(issue.get("function") or issue.get("func_name") or "").lower(), root


def _same_root_cause(default_issue: Dict[str, Any], review_issue: Dict[str, Any]) -> bool:
    if not _same_category(default_issue, review_issue):
        return False

    default_uid = str(default_issue.get("candidate_uid") or "")
    review_uid = str(review_issue.get("candidate_uid") or "")
    if default_uid and review_uid and default_uid == review_uid:
        return True

    default_resource = issue_resource_signature(default_issue)
    review_resource = issue_resource_signature(review_issue)
    if (
        default_resource
        and review_resource
        and default_resource == review_resource
    ):
        return True

    def identity(issue: Dict[str, Any], key: str) -> str:
        value = issue.get(key)
        pack = issue.get("evidence_pack")
        if not value and isinstance(pack, dict):
            value = pack.get(key)
        return str(value or "").strip().lower()

    default_source = (
        identity(default_issue, "source_identity")
        or identity(default_issue, "source_location")
        or identity(default_issue, "source_loc")
    )
    review_source = (
        identity(review_issue, "source_identity")
        or identity(review_issue, "source_location")
        or identity(review_issue, "source_loc")
    )
    default_sink_identity = (
        identity(default_issue, "sink_identity")
        or identity(default_issue, "sink_location")
        or identity(default_issue, "sink_loc")
    )
    review_sink_identity = (
        identity(review_issue, "sink_identity")
        or identity(review_issue, "sink_location")
        or identity(review_issue, "sink_loc")
    )
    if (
        default_source
        and review_source
        and default_source == review_source
        and default_sink_identity
        and review_sink_identity
        and default_sink_identity == review_sink_identity
    ):
        return True

    default_path = issue_call_path_signature(default_issue)
    review_path = issue_call_path_signature(review_issue)
    default_sink = issue_sink_signature(default_issue)
    review_sink = issue_sink_signature(review_issue)
    return bool(
        default_path
        and review_path
        and default_path == review_path
        and default_sink
        and review_sink
        and default_sink == review_sink
        and default_source
        and review_source
        and default_source == review_source
    )


def _same_category(default_issue: Dict[str, Any], review_issue: Dict[str, Any]) -> bool:
    default_text = flatten_issue_text(default_issue)
    review_text = flatten_issue_text(review_issue)
    default_category = canonical_category(default_issue, default_text)
    review_category = canonical_category(review_issue, review_text)
    if default_category and default_category == review_category:
        return True

    default_root = root_cause_token(default_issue, default_category, default_text)
    review_root = root_cause_token(review_issue, review_category, review_text)
    if default_root and default_root == review_root:
        return report_cluster_category(default_category, default_root) == report_cluster_category(
            review_category,
            review_root,
        )
    return False


def _same_path_attribution(default_issue: Dict[str, Any], review_issue: Dict[str, Any]) -> bool:
    def value(issue: Dict[str, Any], key: str) -> str:
        direct = issue.get(key)
        if direct:
            return str(direct).lower()
        pack = issue.get("evidence_pack")
        if isinstance(pack, dict):
            packed = pack.get(key)
            if packed:
                return str(packed).lower()
        return ""

    default_entry = value(default_issue, "entry_function")
    review_entry = value(review_issue, "entry_function")
    default_sink = value(default_issue, "sink_function") or str(default_issue.get("function") or "").lower()
    review_sink = value(review_issue, "sink_function") or str(review_issue.get("function") or "").lower()
    if default_entry and default_entry == review_entry and default_sink and default_sink == review_sink:
        return True

    default_path = default_issue.get("call_path")
    review_path = review_issue.get("call_path")
    return bool(default_path and default_path == review_path)


def _compact_observation(issue: Dict[str, Any]) -> Dict[str, Any]:
    keep = (
        "id",
        "candidate_id",
        "candidate_source",
        "candidate_schema_version",
        "candidate_uid",
        "history_key",
        "evidence_hash",
        "context_signature",
        "run_issue_uid",
        "record_role",
        "finding_kind",
        "function",
        "location",
        "category",
        "subcategory",
        "description",
        "root_cause",
        "validation_status",
        "candidate_disposition",
        "engine_status",
        "verification_error",
        "deferred_reason",
        "validation_reasoning",
        "confidence",
        "impact_level",
        "dedup_key",
        "entry_function",
        "sink_function",
        "target_function",
        "analyzed_from",
        "reachable_from_entry",
        "internal_sink_lifted",
        "call_path",
        "call_paths",
        "evidence_pack",
        "evidence_refs",
        "file",
        "line",
        "start_line",
        "end_line",
        "source_loc",
        "sink_loc",
        "source_location",
        "sink_location",
        "normalized_category",
        "rule",
        "root_cause_key",
        "resource_signature",
        "resource_identity",
        "source_identity",
        "sink_identity",
        "validation_cluster_uid",
        "decision_evidence_hash",
        "provenance_hash",
        "provenance_hashes",
        "evidence_hashes",
        "occurrence_uid",
        "occurrence_uids",
        "occurrences",
        "occurrence_count",
        "entry_count",
        "entries",
        "entry_paths",
        "validation_contexts",
        "alias_occurrence_uids",
    )
    return {key: deepcopy(issue[key]) for key in keep if key in issue}


def _identity_value(issue: Dict[str, Any], key: str) -> str:
    value = issue.get(key)
    pack = issue.get("evidence_pack")
    if not value and isinstance(pack, dict):
        value = pack.get(key)
    return str(value or "").strip().lower()


def _root_match_keys(issue: Dict[str, Any]) -> List[Tuple[str, ...]]:
    """Return conservative lookup keys used by ``_same_root_cause``.

    Every key mirrors one of that function's positive structured-evidence
    branches.  The final predicate is still evaluated after lookup, so hash
    collisions or category-family differences cannot create an attachment.
    """

    keys: List[Tuple[str, ...]] = []
    candidate_uid = str(issue.get("candidate_uid") or "")
    if candidate_uid:
        keys.append(("candidate_uid", candidate_uid))

    resource = issue_resource_signature(issue)
    if resource:
        keys.append(("resource", resource))

    source = (
        _identity_value(issue, "source_identity")
        or _identity_value(issue, "source_location")
        or _identity_value(issue, "source_loc")
    )
    sink_identity = (
        _identity_value(issue, "sink_identity")
        or _identity_value(issue, "sink_location")
        or _identity_value(issue, "sink_loc")
    )
    if source and sink_identity:
        keys.append(("source_sink", source, sink_identity))

    path = issue_call_path_signature(issue)
    sink = issue_sink_signature(issue)
    if path and sink and source:
        keys.append(("path_sink_source", path, sink, source))
    return keys


def _record_fingerprint(record: Dict[str, Any]) -> str:
    encoded = json.dumps(
        record,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def attach_related_needs_review(
    default_issues: List[Dict[str, Any]],
    review_issues: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    """Attach review observations that only add evidence for an existing finding."""
    independent: List[Dict[str, Any]] = []
    attached_count = 0
    root_index: Dict[Tuple[str, ...], List[int]] = {}
    for index, issue in enumerate(default_issues):
        for key in _root_match_keys(issue):
            root_index.setdefault(key, []).append(index)
    attachment_cache: Dict[int, Dict[str, List[Dict[str, Any]]]] = {}

    for review_issue in review_issues:
        normalize_issue_fields(review_issue)
        review_issue["dedup_key"] = canonical_issue_key(review_issue)
        candidate_indices: List[int] = []
        seen_indices = set()
        for key in _root_match_keys(review_issue):
            for index in root_index.get(key, []):
                if index in seen_indices:
                    continue
                seen_indices.add(index)
                candidate_indices.append(index)
        match = next(
            (
                default_issues[index]
                for index in candidate_indices
                if _same_root_cause(default_issues[index], review_issue)
            ),
            None,
        )
        if match is None:
            independent.append(review_issue)
            continue

        attached = match.get("related_needs_review_observations")
        if not isinstance(attached, list):
            attached = []
            match["related_needs_review_observations"] = attached
        compact = _compact_observation(review_issue)
        buckets = attachment_cache.setdefault(id(match), {})
        if not buckets and attached:
            for existing in attached:
                if isinstance(existing, dict):
                    buckets.setdefault(_record_fingerprint(existing), []).append(existing)
        fingerprint = _record_fingerprint(compact)
        bucket = buckets.setdefault(fingerprint, [])
        if not any(existing == compact for existing in bucket):
            attached.append(compact)
            bucket.append(compact)
            attached_count += 1
        match["attached_needs_review_count"] = len(attached)

    return independent, attached_count


def build_report_views(
    issues: Iterable[Any],
    audit_observations: Iterable[Any],
    *,
    canonical_projection: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """Build default and needs-review-inclusive issue lists.

    A v3 canonical projection is already one row per immutable validation
    group.  Running legacy semantic de-duplication or attaching a review row
    to a confirmed finding at this point would change the ledger decision and
    break the public count invariant.  The legacy behaviour remains available
    for reports that predate lifecycle outcomes.
    """
    raw_issues = issue_dicts(issues)
    base_issues = raw_issues if canonical_projection else deduplicate_issues(raw_issues)
    default_issues = deepcopy(base_issues)
    review_base_issues = deepcopy(base_issues)
    raw_observations = issue_dicts(audit_observations)
    if canonical_projection:
        # Canonical outcomes have already been structurally clustered by
        # validation_cluster_uid.  Keep every security obligation visible,
        # including an unresolved group that is related to a confirmed one.
        review_issues = needs_review_observations(raw_observations)
        independent_review_issues = deepcopy(review_issues)
        attached_review_count = 0
        with_review = review_base_issues + independent_review_issues
    else:
        review_issues = coalesce_review_observations(raw_observations)
        independent_review_issues, attached_review_count = attach_related_needs_review(
            review_base_issues,
            review_issues,
        )
        with_review = deduplicate_issues(review_base_issues + independent_review_issues)
    review_count = len(review_issues)
    governance = review_governance_summary(
        raw_observations,
        canonical_review=review_issues,
        attached_count=attached_review_count,
    )
    return {
        DEFAULT_REPORT_VIEW: {
            "label": "Default",
            "description": "Verified/reportable issues only.",
            "issue_count": len(default_issues),
            "included_needs_review_count": 0,
            "issues": default_issues,
            "issues_by_severity": group_by_severity(default_issues),
        },
        WITH_NEEDS_REVIEW_REPORT_VIEW: {
            "label": "With needs_review",
            "description": "Default issues plus validator needs_review observations.",
            "issue_count": len(with_review),
            "included_needs_review_count": review_count,
            "independent_needs_review_count": len(independent_review_issues),
            "attached_needs_review_count": attached_review_count,
            "needs_review_governance": governance,
            "issues": with_review,
            "issues_by_severity": group_by_severity(with_review),
        },
    }


def findings_for_view(report: Dict[str, Any], view: str = DEFAULT_REPORT_VIEW) -> List[Dict[str, Any]]:
    """Read findings from a report view, falling back to legacy report shapes."""
    normalized_view = view if view in {DEFAULT_REPORT_VIEW, WITH_NEEDS_REVIEW_REPORT_VIEW} else DEFAULT_REPORT_VIEW
    report_views = report.get("report_views")
    if isinstance(report_views, dict):
        selected = report_views.get(normalized_view)
        if isinstance(selected, dict) and isinstance(selected.get("issues"), list):
            return [item for item in selected["issues"] if isinstance(item, dict)]

    issues = report.get("issues")
    if isinstance(issues, list):
        default_issues = [item for item in issues if isinstance(item, dict)]
        if (
            not default_issues
            and isinstance(report.get("findings"), list)
            and report.get("findings")
        ):
            default_issues = [
                item for item in report["findings"] if isinstance(item, dict)
            ]
    else:
        default_issues = []
        results = report.get("results")
        if isinstance(results, dict):
            for result in results.values():
                if isinstance(result, dict) and isinstance(result.get("issues"), list):
                    default_issues.extend(item for item in result["issues"] if isinstance(item, dict))
        if isinstance(report.get("function_results"), list):
            for result in report["function_results"]:
                if isinstance(result, dict) and isinstance(result.get("issues"), list):
                    default_issues.extend(item for item in result["issues"] if isinstance(item, dict))

    if normalized_view == DEFAULT_REPORT_VIEW:
        return default_issues

    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    observations = metadata.get("audit_observations") if isinstance(metadata, dict) else []
    return build_report_views(default_issues, observations)[WITH_NEEDS_REVIEW_REPORT_VIEW]["issues"]


def report_view_summary(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return lightweight counts for UI/API consumers."""
    views = report.get("report_views")
    if not isinstance(views, dict):
        views = build_report_views(
            report.get("issues", []),
            (report.get("metadata") or {}).get("audit_observations", [])
            if isinstance(report.get("metadata"), dict)
            else [],
        )
    summary: Dict[str, Dict[str, Any]] = {}
    for name in (DEFAULT_REPORT_VIEW, WITH_NEEDS_REVIEW_REPORT_VIEW):
        view = views.get(name) if isinstance(views, dict) else None
        if not isinstance(view, dict):
            continue
        issues = view.get("issues", [])
        issue_count = len(issues) if isinstance(issues, list) else int(view.get("issue_count") or 0)
        if "included_needs_review_count" in view:
            needs_review_count = int(view.get("included_needs_review_count") or 0)
        elif isinstance(issues, list):
            needs_review_count = sum(
                1
                for issue in issues
                if isinstance(issue, dict)
                and (
                    str(issue.get("validation_status") or "").lower()
                    in NEEDS_REVIEW_STATUSES
                    or str(issue.get("candidate_disposition") or "").lower()
                    in NEEDS_REVIEW_DISPOSITIONS
                )
            )
        else:
            needs_review_count = 0
        summary[name] = {
            "label": view.get("label", name),
            "description": view.get("description", ""),
            "issue_count": issue_count,
            "included_needs_review_count": needs_review_count,
            "independent_needs_review_count": int(view.get("independent_needs_review_count") or 0),
            "attached_needs_review_count": int(view.get("attached_needs_review_count") or 0),
        }
    return summary
