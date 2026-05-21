"""Helpers for exposing alternate report views."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..common.issue_identity import (
    canonical_category,
    canonical_issue_key,
    deduplicate_issues,
    flatten_issue_text,
    normalize_issue_fields,
    parse_issue_location,
    root_cause_token,
)

DEFAULT_REPORT_VIEW = "default"
WITH_NEEDS_REVIEW_REPORT_VIEW = "with_needs_review"
NEEDS_REVIEW_STATUSES = {"needs_review"}


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
        if str(issue.get("validation_status") or "").lower() in NEEDS_REVIEW_STATUSES
    ]


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
    default_key = canonical_issue_key(default_issue)
    review_key = canonical_issue_key(review_issue)
    if default_key == review_key:
        return True

    if not _same_category(default_issue, review_issue):
        return False

    if _same_path_attribution(default_issue, review_issue):
        return True

    default_file, default_func, default_root = _issue_root_signature(default_issue)
    review_file, review_func, review_root = _issue_root_signature(review_issue)
    if default_root and default_root == review_root and (default_file or default_func):
        if default_func and review_func:
            return default_func == review_func
        default_line = _issue_location_parts(default_issue)[1]
        review_line = _issue_location_parts(review_issue)[1]
        if (
            default_file
            and review_file
            and default_file == review_file
            and default_line is not None
            and review_line is not None
            and abs(default_line - review_line) <= 8
        ):
            return True

    return False


def _same_category(default_issue: Dict[str, Any], review_issue: Dict[str, Any]) -> bool:
    default_text = flatten_issue_text(default_issue)
    review_text = flatten_issue_text(review_issue)
    default_category = canonical_category(default_issue, default_text)
    review_category = canonical_category(review_issue, review_text)
    return bool(default_category and default_category == review_category)


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
        "finding_kind",
        "function",
        "location",
        "category",
        "subcategory",
        "description",
        "root_cause",
        "validation_status",
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
        "file",
        "line",
        "start_line",
        "end_line",
        "normalized_category",
    )
    return {key: deepcopy(issue[key]) for key in keep if key in issue}


def attach_related_needs_review(
    default_issues: List[Dict[str, Any]],
    review_issues: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], int]:
    """Attach review observations that only add evidence for an existing finding."""
    independent: List[Dict[str, Any]] = []
    attached_count = 0

    for review_issue in review_issues:
        normalize_issue_fields(review_issue)
        review_issue["dedup_key"] = canonical_issue_key(review_issue)
        match = next(
            (issue for issue in default_issues if _same_root_cause(issue, review_issue)),
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
        if compact not in attached:
            attached.append(compact)
            attached_count += 1
        match["attached_needs_review_count"] = len(attached)

    return independent, attached_count


def build_report_views(
    issues: Iterable[Any],
    audit_observations: Iterable[Any],
) -> Dict[str, Dict[str, Any]]:
    """Build default and needs-review-inclusive issue lists."""
    base_issues = deduplicate_issues(issue_dicts(issues))
    default_issues = deepcopy(base_issues)
    review_base_issues = deepcopy(base_issues)
    review_issues = needs_review_observations(audit_observations)
    independent_review_issues, attached_review_count = attach_related_needs_review(
        review_base_issues,
        review_issues,
    )
    with_review = deduplicate_issues(review_base_issues + independent_review_issues)
    review_count = len(review_issues)
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
                and str(issue.get("validation_status") or "").lower() in NEEDS_REVIEW_STATUSES
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
