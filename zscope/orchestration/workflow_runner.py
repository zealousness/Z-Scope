"""High-level analyzer workflow execution."""

from __future__ import annotations

import hashlib
import logging
from typing import Any, Callable, Dict, Optional, Sequence

from .workflow_executor import WorkflowExecutor
from .specs import WorkflowStep

logger = logging.getLogger(__name__)

StateFactory = Callable[[], Dict[str, Any]]
StepSelector = Callable[[], Sequence[WorkflowStep]]
ReportBuilder = Callable[[Dict[str, Any]], None]
ReportPersister = Callable[[Dict[str, Any]], Dict[str, Any]]
ReturnedReportFinalizer = Callable[[Dict[str, Any]], Dict[str, Any]]
CurrentStepSink = Callable[[Optional[str]], None]


class WorkflowRunner:
    """Run the selected workflow and handle final report handoff."""

    def __init__(
        self,
        *,
        workflow_name: str,
        state_factory: StateFactory,
        step_selector: StepSelector,
        executor: WorkflowExecutor,
        build_final_report: ReportBuilder,
        persist_final_report: ReportPersister,
        finalize_returned_report: ReturnedReportFinalizer,
        current_step_sink: Optional[CurrentStepSink] = None,
    ) -> None:
        self.workflow_name = workflow_name
        self.state_factory = state_factory
        self.step_selector = step_selector
        self.executor = executor
        self.build_final_report = build_final_report
        self.persist_final_report = persist_final_report
        self.finalize_returned_report = finalize_returned_report
        self.current_step_sink = current_step_sink

    def run(self) -> Dict[str, Any]:
        state = self.state_factory()
        if state.get("error"):
            error = str(state["error"])
            reason = str(state.get("reason") or "entry_initialization_failed")
            entry_function = str(state.get("entry_func") or "")
            digest = hashlib.sha256(
                f"{entry_function}\0{reason}".encode("utf-8")
            ).hexdigest()[:24]
            return {
                "schema_version": 2,
                "entry_function": entry_function,
                "overall_verdict": "error",
                "error": error,
                "error_reason": reason,
                "issues": [],
                "notes": [f"Analysis could not initialize: {error}"],
                "finding_status": "needs_review",
                "completeness": "failed",
                "scan_outcome": "incomplete",
                "candidate_terminal_states": [
                    {
                        "candidate_uid": f"ENGINE_{digest}",
                        "occurrence_uid": f"ENGINE_OCC_{digest}",
                        "candidate_disposition": "engine_failed",
                        "status": "engine_failed",
                        "engine": "entry_initialization",
                        "reason": reason,
                    }
                ],
                "metadata": {
                    "engine_capabilities": {
                        "entry_initialization": {
                            "status": "failed",
                            "reason": reason,
                        }
                    }
                },
                "run_manifest": {
                    "schema_version": "zscope.run-manifest.v1",
                    "entry_function": entry_function,
                    "finding_status": "needs_review",
                    "completeness": "failed",
                    "issue_count": 0,
                    "needs_review_count": 1,
                    "valid": False,
                    "engine_capabilities": {
                        "entry_initialization": {
                            "status": "failed",
                            "reason": reason,
                        }
                    },
                },
            }

        logger.info(
            "Starting workflow '%s' on entry function: %s",
            self.workflow_name,
            state["entry_func"],
        )

        steps = self.step_selector()
        self.executor.execute(state, steps)
        if self.current_step_sink:
            self.current_step_sink(self.executor.current_step)

        if state.get("final_report_dict"):
            return self.finalize_returned_report(state)

        if not state.get("final_report"):
            self.build_final_report(state)

        return self.persist_final_report(state)
