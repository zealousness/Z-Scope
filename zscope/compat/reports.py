"""Read-only presentation of reports that predate canonical Finding-root views."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Mapping

from ..reporting.views import build_report_views


def read_legacy_worker_reports(report: Mapping[str, Any]) -> list[Dict[str, Any]]:
    """Return detached historical worker-report metadata, when present."""

    metadata = report.get("metadata")
    if not isinstance(metadata, Mapping):
        return []
    values = metadata.get("subagent_reports")
    if not isinstance(values, list):
        return []
    return [deepcopy(item) for item in values if isinstance(item, dict)]


def read_legacy_report_view(
    report: Mapping[str, Any],
    *,
    view: str = "default",
) -> Dict[str, Any]:
    """Return a detached presentation view without mutating live scan state.

    This adapter deliberately accepts only a persisted report mapping.  It has
    no Candidate Ledger, proof, validator, promotion, Agent, or LLM hooks.
    """

    if view not in {"default", "with_needs_review"}:
        raise ValueError("view must be 'default' or 'with_needs_review'")
    stored_views = report.get("report_views")
    if isinstance(stored_views, Mapping) and isinstance(stored_views.get(view), Mapping):
        return deepcopy(dict(stored_views[view]))

    issues = report.get("issues")
    observations = report.get("audit_observations", report.get("observations"))
    views = build_report_views(
        (
            [deepcopy(item) for item in issues if isinstance(item, dict)]
            if isinstance(issues, list)
            else []
        ),
        (
            [deepcopy(item) for item in observations if isinstance(item, dict)]
            if isinstance(observations, list)
            else []
        ),
    )
    return deepcopy(dict(views[view]))
