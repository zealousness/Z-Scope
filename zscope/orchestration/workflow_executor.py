"""Workflow step execution helpers."""

from __future__ import annotations

import datetime
import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from ..common.cancellation import CancellationToken
from .specs import WorkflowStep

logger = logging.getLogger(__name__)

WorkflowStepHandler = Callable[[Dict[str, Any], WorkflowStep], bool]

WORKFLOW_SCOPES = {"session", "batch", "entry"}


def handler_key(step: WorkflowStep) -> str:
    return step.handler or step.id


def workflow_steps_for_scope(
    steps: Sequence[WorkflowStep],
    scope: str,
) -> List[WorkflowStep]:
    return [step for step in steps if step.scope == scope]


def validate_workflow_steps(
    steps: Iterable[WorkflowStep],
    handlers: Dict[str, WorkflowStepHandler],
    *,
    workflow_name: str,
    scopes: Set[str],
) -> None:
    missing: List[str] = []
    invalid_scope: List[str] = []
    for step in steps:
        if step.scope not in WORKFLOW_SCOPES:
            invalid_scope.append(f"{step.id}:{step.scope}")
            continue
        if step.scope not in scopes:
            continue
        if handler_key(step) not in handlers:
            missing.append(f"{step.id}->{handler_key(step)}")

    if invalid_scope:
        valid = ", ".join(sorted(WORKFLOW_SCOPES))
        raise ValueError(
            f"Workflow '{workflow_name}' has invalid step scope(s): "
            f"{', '.join(invalid_scope)}. Valid scopes: {valid}"
        )
    if missing:
        known = ", ".join(sorted(handlers))
        raise ValueError(
            f"Workflow '{workflow_name}' has step(s) without registered handlers: "
            f"{', '.join(missing)}. Known handlers: {known}"
        )


class WorkflowExecutor:
    """Execute declarative workflow steps for one orchestration scope."""

    def __init__(
        self,
        *,
        workflow_name: str,
        scope: str,
        handlers: Dict[str, WorkflowStepHandler],
        progress: Optional[List[Dict[str, Any]]] = None,
        cancellation_token: Optional[CancellationToken] = None,
    ) -> None:
        if scope not in WORKFLOW_SCOPES:
            valid = ", ".join(sorted(WORKFLOW_SCOPES))
            raise ValueError(f"Invalid workflow scope '{scope}'. Valid scopes: {valid}")
        self.workflow_name = workflow_name
        self.scope = scope
        self.handlers = handlers
        self.progress = progress if progress is not None else []
        self.cancellation_token = cancellation_token
        self.current_step: Optional[str] = None

    def validate(self, steps: Iterable[WorkflowStep]) -> None:
        validate_workflow_steps(
            steps,
            self.handlers,
            workflow_name=self.workflow_name,
            scopes={self.scope},
        )

    def steps_for_scope(self, steps: Sequence[WorkflowStep]) -> List[WorkflowStep]:
        return workflow_steps_for_scope(steps, self.scope)

    def execute(self, state: Dict[str, Any], steps: Sequence[WorkflowStep]) -> None:
        scoped_steps = self.steps_for_scope(steps)
        for index, step in enumerate(scoped_steps):
            if self.cancellation_token is not None:
                self.cancellation_token.raise_if_cancelled()
            self._begin_step(step)
            try:
                should_stop = self._execute_step(state, step)
                if self.cancellation_token is not None:
                    self.cancellation_token.raise_if_cancelled()
                self._finish_step(step, "completed")
                if self._should_stop(step, should_stop):
                    reason = f"stopped_after:{step.id}"
                    for skipped in scoped_steps[index + 1 :]:
                        self._record_skipped(skipped, reason)
                    return
            except Exception as exc:
                self._finish_step(step, "failed", str(exc))
                raise

    def _execute_step(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        key = handler_key(step)
        handler = self.handlers.get(key)
        if not handler:
            known = ", ".join(sorted(self.handlers))
            raise ValueError(
                f"Unknown workflow step '{step.id}' in workflow '{self.workflow_name}' "
                f"for scope '{self.scope}' using handler '{key}'. Known handlers: {known}"
            )
        return handler(state, step)

    def _begin_step(self, step: WorkflowStep) -> None:
        self.current_step = step.id
        record = {
            "index": len(self.progress) + 1,
            "id": step.id,
            "scope": step.scope,
            "handler": handler_key(step),
            "agent": step.agent,
            "action": step.action,
            "status": "running",
            "started_at": datetime.datetime.now().isoformat(),
        }
        self.progress.append(record)
        logger.info(
            "[workflow:%s:%s] step %d start: %s%s",
            self.workflow_name,
            self.scope,
            record["index"],
            step.id,
            f" ({step.action})" if step.action else "",
        )

    def _finish_step(self, step: WorkflowStep, status: str, error: str = "") -> None:
        for record in reversed(self.progress):
            if (
                record["id"] == step.id
                and record.get("scope") == step.scope
                and record["status"] == "running"
            ):
                record["status"] = status
                record["finished_at"] = datetime.datetime.now().isoformat()
                if error:
                    record["error"] = error
                break
        logger.info("[workflow:%s] step %s %s", self.scope, step.id, status)
        self.current_step = None

    def _record_skipped(self, step: WorkflowStep, reason: str) -> None:
        timestamp = datetime.datetime.now().isoformat()
        self.progress.append(
            {
                "index": len(self.progress) + 1,
                "id": step.id,
                "scope": step.scope,
                "handler": handler_key(step),
                "agent": step.agent,
                "action": step.action,
                "status": "skipped",
                "skip_reason": reason,
                "started_at": timestamp,
                "finished_at": timestamp,
            }
        )
        logger.info("[workflow:%s] step %s skipped (%s)", self.scope, step.id, reason)

    @staticmethod
    def _should_stop(step: WorkflowStep, handler_requested_stop: bool) -> bool:
        if step.stop_policy == "stop_after_step":
            return True
        if step.stop_policy == "stop_if_handler_returns_true":
            return bool(handler_requested_stop)
        return bool(handler_requested_stop)
