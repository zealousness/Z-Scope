from __future__ import annotations

import pytest

from zscope.orchestration.specs import SpecRegistry, WorkflowStep
from zscope.orchestration.workflow_executor import WorkflowExecutor, validate_workflow_steps


def test_p1_workflow_stage_names_are_stable() -> None:
    registry = SpecRegistry()

    assert [step.id for step in registry.get_workflow("default").steps] == [
        "discover_entries",
        "collect_candidates",
        "validate_candidates",
        "persist_report",
    ]
    assert [step.id for step in registry.get_workflow("resume").steps] == [
        "discover_entries",
        "plan_resume",
        "run_pending_entries",
        "merge_reused_reports",
    ]
    assert [step.id for step in registry.get_workflow("maintain").steps] == [
        "discover_entries",
        "compare_entry_state",
        "reuse_unchanged_report",
        "reconcile_history",
        "run_changed_entry",
    ]


def test_handler_validation_includes_optional_steps() -> None:
    step = WorkflowStep(id="optional", required=False)

    with pytest.raises(ValueError, match="without registered handlers"):
        validate_workflow_steps(
            [step],
            {},
            workflow_name="test",
            scopes={"entry"},
        )


def test_stop_policy_records_each_later_step_as_skipped() -> None:
    steps = [
        WorkflowStep(id="compare_entry_state"),
        WorkflowStep(
            id="reuse_unchanged_report",
            stop_policy="stop_if_handler_returns_true",
        ),
        WorkflowStep(id="reconcile_history"),
        WorkflowStep(id="run_changed_entry"),
    ]
    progress = []
    handlers = {
        "compare_entry_state": lambda state, step: False,
        "reuse_unchanged_report": lambda state, step: True,
        "reconcile_history": lambda state, step: False,
        "run_changed_entry": lambda state, step: False,
    }
    executor = WorkflowExecutor(
        workflow_name="maintain",
        scope="entry",
        handlers=handlers,
        progress=progress,
    )

    executor.validate(steps)
    executor.execute({}, steps)

    assert [(item["id"], item["status"]) for item in progress] == [
        ("compare_entry_state", "completed"),
        ("reuse_unchanged_report", "completed"),
        ("reconcile_history", "skipped"),
        ("run_changed_entry", "skipped"),
    ]
    assert progress[-1]["skip_reason"] == "stopped_after:reuse_unchanged_report"
