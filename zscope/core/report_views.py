"""Helpers for exposing alternate report views."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List

from .issue_dedup import deduplicate_issues

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


def build_report_views(
    issues: Iterable[Any],
    audit_observations: Iterable[Any],
) -> Dict[str, Dict[str, Any]]:
    """Build default and needs-review-inclusive issue lists."""
    default_issues = deduplicate_issues(issue_dicts(issues))
    review_issues = needs_review_observations(audit_observations)
    with_review = deduplicate_issues(default_issues + review_issues)
    review_count = sum(
        1
        for issue in with_review
        if str(issue.get("validation_status") or "").lower() in NEEDS_REVIEW_STATUSES
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
        needs_review_count = (
            sum(
                1
                for issue in issues
                if isinstance(issue, dict)
                and str(issue.get("validation_status") or "").lower() in NEEDS_REVIEW_STATUSES
            )
            if isinstance(issues, list)
            else int(view.get("included_needs_review_count") or 0)
        )
        summary[name] = {
            "label": view.get("label", name),
            "description": view.get("description", ""),
            "issue_count": issue_count,
            "included_needs_review_count": needs_review_count,
        }
    return summary
