"""Fresh-session retries for terminal-loop-guarded semantic modeling."""

from copy import deepcopy
import logging
from typing import Any, Callable, Dict, List, Optional, cast

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

_PROVIDER_COUNTERS = (
    "provider_attempt_count",
    "provider_success_count",
    "provider_accounted_tokens",
    "provider_reported_tokens",
    "provider_conservative_tokens",
)


def _counter(metadata: Dict[str, Any], key: str) -> int:
    value = metadata.get(key)
    if value is None and key == "cumulative_total_tokens":
        value = metadata.get("context_tokens")
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _run_semantic_model_with_retries(
    agent_factory: Callable[[], SemanticModeler],
    context: Dict[str, Any],
    *,
    max_guard_retries: int = DEFAULT_TERMINAL_GUARD_RETRIES,
    log_context: str = "semantic",
    index_name: str = "",
    response_validator: Optional[Callable[[AgentResponse, Dict[str, Any]], List[str]]] = None,
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
        response = agent_factory().run(dict(deepcopy(context), semantic_model_attempt=attempt))
        contract_errors = (
            response_validator(response, context) if response.success and response_validator else []
        )
        if contract_errors:
            response.success = False
            response.error = "; ".join(contract_errors)
            response.metadata = dict(response.metadata or {}, reason="semantic_contract_invalid")
            # The next fresh session receives only this symbol's actionable
            # diagnostics, under the same total attempt ceiling as loop repairs.
            context = dict(context)
            context["user_config_context"] = str(context.get("user_config_context") or "") + (
                "\nContract validation failed: "
                + response.error
                + ". Correct the affected interface_contracts using the supplied source; "
                "keep prose in descriptions and use typed references in predicates."
                " If no caller-visible carrier exists, omit that interface contract and retain the behavior in effects/summary."
                " Member paths must include access operators (->field, .field), not bare field names."
                " Pool head_path/link_path must include ->. Express allocation success with return != null;"
                " do not confuse an updated pool head with its pre-call value."
            )
        metadata = dict(response.metadata or {})
        terminal_errors = list(metadata.get("terminal_validation_errors") or [])
        if not terminal_errors and metadata.get("terminal_loop_guard_triggered"):
            detail = (metadata.get("repeated_terminal_tool_call") or {}).get("error")
            if detail:
                terminal_errors = [str(detail)]
        if terminal_errors:
            context = dict(context)
            context["user_config_context"] = str(context.get("user_config_context") or "") + (
                "\nThe previous terminal payload failed schema validation: "
                + "; ".join(terminal_errors)
                + ". Repair these fields against the supplied schema and source in this attempt."
            )
        for key in _AGGREGATED_COUNTERS:
            totals[key] += _counter(metadata, key)

        attempt_record: Dict[str, Any] = {
            "attempt": attempt,
            "success": bool(response.success),
            "error": response.error,
            "reason": str(metadata.get("reason") or ""),
            "terminal_loop_guard_triggered": bool(metadata.get("terminal_loop_guard_triggered")),
            "terminal_loop_guard_reason": str(metadata.get("terminal_loop_guard_reason") or ""),
            "validation_errors": terminal_errors or contract_errors,
            "terminal_submissions": metadata.get("terminal_submissions", []),
        }
        attempt_record.update({key: _counter(metadata, key) for key in _AGGREGATED_COUNTERS})
        attempts.append(attempt_record)
        final_response = response

        guarded = bool(metadata.get("terminal_loop_guard_triggered"))
        if (
            response.success
            or not (guarded or contract_errors or terminal_errors)
            or attempt >= max_attempts
        ):
            break
        logger.warning(
            "[semantic-retry] restarting after invalid terminal output "
            "context=%s index_name=%s attempt=%d/%d reason=%s",
            log_context,
            index_name or str(context.get("index_name") or ""),
            attempt,
            max_attempts,
            "; ".join(contract_errors) or metadata.get("terminal_loop_guard_reason") or "unknown",
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


def run_semantic_model_with_retries(
    agent_factory: Callable[[], SemanticModeler],
    context: Dict[str, Any],
    *,
    max_guard_retries: int = DEFAULT_TERMINAL_GUARD_RETRIES,
    log_context: str = "semantic",
    index_name: str = "",
    response_validator: Optional[Callable[[AgentResponse, Dict[str, Any]], List[str]]] = None,
    snapshot_store: Any = None,
    input_version: Optional[Dict[str, Any]] = None,
) -> AgentResponse:
    """One versioned owner runs all physical attempts and atomically stages its result.

    SCC publication still belongs to the component scheduler; the staged result
    is immutable and never authorizes a rule before the workbook is published.
    """
    from pathlib import Path
    from ...orchestration.modeling_coordinator import scan_coordinator
    from ...semantics.contracts import digest, code_tokens, CONTRACT_COMPILER_VERSION

    def operation() -> AgentResponse:
        from ...framework.llm_usage import collect_task_usage_events, task_usage_counters

        response = None
        with collect_task_usage_events() as events:
            try:
                response = _run_semantic_model_with_retries(
                    agent_factory,
                    context,
                    max_guard_retries=max_guard_retries,
                    log_context=log_context,
                    index_name=index_name,
                    response_validator=response_validator,
                )
            finally:
                if response is None and events:
                    coordinator.record_completion(task_usage_counters(events))
        if events:
            response.metadata = dict(response.metadata or {}, **task_usage_counters(events))
        coordinator.record_completion(response.metadata or {})
        if snapshot_store is not None:
            (Path(snapshot_store.snapshot_dir) / ".modeling-tasks").mkdir(
                parents=True, exist_ok=True
            )
            snapshot_store._write_json_atomic(
                Path(snapshot_store.snapshot_dir) / ".modeling-tasks" / (key + ".json"),
                {
                    "task_key": key,
                    "success": response.success,
                    "snapshot": response.data,
                    "error": response.error,
                    "metadata": response.metadata,
                },
            )
        return response

    # Unit-level callers can omit a store. Product entrypoints always supply it.
    if snapshot_store is None:
        return _run_semantic_model_with_retries(
            agent_factory,
            context,
            max_guard_retries=max_guard_retries,
            log_context=log_context,
            index_name=index_name,
            response_validator=response_validator,
        )
    namespace = str(Path(snapshot_store.snapshot_dir).resolve())
    coordinator = scan_coordinator(namespace, snapshot_store)

    def structural(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: structural(v)
                for k, v in value.items()
                if k
                not in {
                    "start_line",
                    "end_line",
                    "reference_lines",
                    "callee_summary",
                    "semantic_model_attempt",
                    "run_id",
                }
            }
        if isinstance(value, list):
            return [structural(v) for v in value]
        return value

    semantic_input = structural(context)
    semantic_input["code"] = code_tokens(str(context.get("code") or ""))
    semantic_input.pop("index_name", None)  # frequently contains relocatable lines
    key = digest(
        {
            "namespace": namespace,
            "symbol": {
                "name": context.get("func_name"),
                "file": context.get("file_path"),
                "signature": context.get("signature"),
                "kind": context.get("is_macro", False),
            },
            "input": semantic_input,
            "compiler": CONTRACT_COMPILER_VERSION,
            "version": input_version,
        }
    )

    def shared(response: AgentResponse) -> AgentResponse:
        metadata = dict(response.metadata or {})
        owner_usage = {k: metadata.get(k, 0) for k in (*_AGGREGATED_COUNTERS, *_PROVIDER_COUNTERS)}
        metadata.update({k: 0 for k in (*_AGGREGATED_COUNTERS, *_PROVIDER_COUNTERS)})
        metadata.update(
            semantic_task_reused=True,
            owner_usage=owner_usage,
            semantic_model_attempt_count=0,
            semantic_model_retry_count=0,
        )
        response.metadata = metadata
        return response

    response = cast(AgentResponse, coordinator.run(key, operation, on_shared=shared))
    response.metadata = dict(
        response.metadata or {}, semantic_task_key=key, modeling_coordinator=coordinator.metrics()
    )
    return response
