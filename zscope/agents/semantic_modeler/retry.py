"""Fresh-session retries for terminal-loop-guarded semantic modeling."""

from copy import deepcopy
import logging
from typing import Any, Callable, Dict, List, Optional

from ...framework.base import AgentResponse
from .agent import SemanticModeler

logger = logging.getLogger(__name__)

DEFAULT_TERMINAL_GUARD_RETRIES = 2

_AGGREGATED_COUNTERS = (
    "context_tokens",
    "cumulative_prompt_tokens",
    "cumulative_completion_tokens",
    "cumulative_total_tokens",
    "iterations",
    "api_call_count",
    "tool_call_count",
    "terminal_tool_call_count",
    "terminal_invalid_call_count",
)


def _counter(metadata: Dict[str, Any], key: str) -> int:
    value = metadata.get(key)
    if value is None and key == "cumulative_total_tokens":
        value = metadata.get("context_tokens")
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def run_semantic_model_with_retries(
    agent_factory: Callable[[], SemanticModeler],
    context: Dict[str, Any],
    *,
    max_guard_retries: int = DEFAULT_TERMINAL_GUARD_RETRIES,
    log_context: str = "semantic",
    index_name: str = "",
) -> AgentResponse:
    """Run semantic modeling again in a fresh session after terminal loop guards."""
    max_attempts = 1 + max(0, int(max_guard_retries))
    attempts: List[Dict[str, Any]] = []
    totals = {key: 0 for key in _AGGREGATED_COUNTERS}
    final_response: Optional[AgentResponse] = None

    for attempt in range(1, max_attempts + 1):
        logger.info(
            "[semantic-retry] starting context=%s index_name=%s attempt=%d/%d",
            log_context,
            index_name or str(context.get("index_name") or ""),
            attempt,
            max_attempts,
        )
        response = agent_factory().run(deepcopy(context))
        metadata = dict(response.metadata or {})
        for key in _AGGREGATED_COUNTERS:
            totals[key] += _counter(metadata, key)

        attempt_record: Dict[str, Any] = {
            "attempt": attempt,
            "success": bool(response.success),
            "error": response.error,
            "reason": str(metadata.get("reason") or ""),
            "terminal_loop_guard_triggered": bool(metadata.get("terminal_loop_guard_triggered")),
            "terminal_loop_guard_reason": str(metadata.get("terminal_loop_guard_reason") or ""),
        }
        attempt_record.update({key: _counter(metadata, key) for key in _AGGREGATED_COUNTERS})
        attempts.append(attempt_record)
        final_response = response

        guarded = bool(metadata.get("terminal_loop_guard_triggered"))
        if response.success or not guarded or attempt >= max_attempts:
            break
        logger.warning(
            "[semantic-retry] restarting after terminal loop guard "
            "context=%s index_name=%s attempt=%d/%d reason=%s",
            log_context,
            index_name or str(context.get("index_name") or ""),
            attempt,
            max_attempts,
            metadata.get("terminal_loop_guard_reason") or "unknown",
        )

    if final_response is None:
        raise RuntimeError("semantic modeling retry runner made no attempts")

    merged_metadata = dict(final_response.metadata or {})
    merged_metadata.update(totals)
    merged_metadata["semantic_model_attempt_count"] = len(attempts)
    merged_metadata["semantic_model_retry_count"] = max(0, len(attempts) - 1)
    merged_metadata["semantic_model_attempts"] = attempts
    merged_metadata["terminal_loop_guard_triggered"] = bool(
        (final_response.metadata or {}).get("terminal_loop_guard_triggered")
    )
    if not merged_metadata["terminal_loop_guard_triggered"]:
        merged_metadata.pop("terminal_loop_guard_reason", None)
        merged_metadata.pop("repeated_terminal_tool_call", None)

    return AgentResponse(
        success=final_response.success,
        data=final_response.data,
        error=final_response.error,
        metadata=merged_metadata,
    )
