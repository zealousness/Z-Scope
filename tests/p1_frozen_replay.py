from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict

from zscope.orchestration.specs import WorkflowStep
from zscope.orchestration.workflow_executor import WorkflowExecutor
from zscope.reporting.assembler import ReportAssembler
from zscope.reporting.views import build_report_views


def _terminal_projection(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: deepcopy(item[key])
        for key in (
            "candidate_uid",
            "validation_cluster_uid",
            "candidate_disposition",
            "reason",
            "validator_fact_resolution",
            "finding_root_uid",
            "finding_root_primary_candidate_uid",
            "finding_root_original_disposition",
            "finding_root_merge_contract",
            "finding_root_alias_count",
            "member_candidate_uids",
            "member_validation_cluster_uids",
        )
        if key in item
    }


def replay_frozen_state(payload: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = deepcopy(payload["candidate_lifecycle_snapshot"])
    state: Dict[str, Any] = {
        "candidate_lifecycle_snapshot": snapshot,
        "finding_root_projection_enabled": True,
    }
    outcomes = ReportAssembler._canonical_outcome_items(state) or []
    confirmed = [item for item in outcomes if item.get("candidate_disposition") == "confirmed"]
    review = [item for item in outcomes if item.get("candidate_disposition") == "needs_review"]
    views = build_report_views(confirmed, review, canonical_projection=True)

    workflow_payload = payload["workflow"]
    steps = [WorkflowStep(**raw) for raw in workflow_payload["steps"]]
    executed: list[str] = []

    def handler(_state: Dict[str, Any], step: WorkflowStep) -> bool:
        executed.append(step.id)
        return False

    progress: list[Dict[str, Any]] = []
    executor = WorkflowExecutor(
        workflow_name=workflow_payload["name"],
        scope="entry",
        handlers={step.id: handler for step in steps},
        progress=progress,
    )
    executor.validate(steps)
    executor.execute({}, steps)

    return {
        "schema_version": "zscope.p1-frozen-replay-output.v1",
        "candidate_uids": sorted(
            {
                str(item.get("candidate_uid") or "")
                for item in snapshot["records"]
                if item.get("candidate_uid")
            }
        ),
        "terminal_outcomes": [
            _terminal_projection(item)
            for item in sorted(
                outcomes,
                key=lambda value: (
                    str(value.get("candidate_disposition") or ""),
                    str(value.get("validation_cluster_uid") or ""),
                ),
            )
        ],
        "finding_root_projection": deepcopy(state.get("finding_root_projection_summary") or {}),
        "views": {
            name: {
                "issue_count": int(view.get("issue_count") or 0),
                "included_needs_review_count": int(view.get("included_needs_review_count") or 0),
                "candidate_uids": [
                    str(item.get("candidate_uid") or "") for item in view.get("issues", [])
                ],
            }
            for name, view in views.items()
        },
        "workflow": {
            "executed": executed,
            "progress": [
                {key: row[key] for key in ("index", "id", "scope", "handler", "status")}
                for row in progress
            ],
        },
    }
