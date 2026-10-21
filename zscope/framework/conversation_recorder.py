"""Full-trace LLM conversation recording for verbose runs (event schema v2).

Recording model:

- One append-only ``{session_id}.jsonl`` event stream per session keeps the
  complete iteration history: every successful exchange, every failed provider
  attempt, every tool call/result, runtime interventions (final instructions,
  length continuations, loop guards) and the session end summary.
- One bounded ``{session_id}.md`` tail snapshot per session for human reading.
  The markdown renders only the most recent exchanges plus aggregates; the
  JSONL remains the authoritative full trace.
- One ``manifest.json`` per run directory captures run-level metadata
  (versions, config hash, recorder settings) and one ``index.jsonl`` row per
  finished session summarises the outcome for offline analysis.

Environment knobs:

- ``Z_SCOPE_CONVERSATION_REASONING``: ``off`` (default) | ``tail:N`` | ``full``
  controls whether provider thinking payloads are persisted.
- ``Z_SCOPE_CONVERSATION_MAX_FIELD_BYTES``: oversized JSON fields (tool
  arguments/results) are truncated to a preview of this byte budget (default
  65536).
- ``Z_SCOPE_CONVERSATION_MD_TAIL_EXCHANGES``: how many recent exchanges the
  markdown snapshot renders (default 3).
- ``Z_SCOPE_CONVERSATION_MD_REWRITE_EVENT_INTERVAL``: rewrite the markdown
  snapshot after this many recorded events (default 8).
- ``Z_SCOPE_CONVERSATION_FLUSH_INTERVAL_SECONDS``: minimum seconds between
  markdown snapshot rewrites (default 0; the interval never delays the JSONL
  append, which is written synchronously for every event).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional

from .llm_usage import LLMUsageAttribution, escalation_rung_for_call_kind

logger = logging.getLogger(__name__)

CONVERSATION_EVENT_SCHEMA_VERSION = "zscope.conversation-event.v2"
CONVERSATION_RUN_MANIFEST_SCHEMA_VERSION = "zscope.conversation-run-manifest.v1"
CONVERSATION_INDEX_SCHEMA_VERSION = "zscope.conversation-session-index.v1"

_REASONING_KEYS = frozenset({"reasoning_content", "reasoning", "thinking"})
_LOCK_LOG_THRESHOLD_SECONDS = 0.05
_MD_WRITE_LOG_THRESHOLD_SECONDS = 0.50
_DEFAULT_MAX_FIELD_BYTES = 65536
_DEFAULT_MD_TAIL_EXCHANGES = 3
_DEFAULT_MD_REWRITE_EVENT_INTERVAL = 8
_DEFAULT_REASONING_TAIL_CHARS = 8192


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    try:
        value = int(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return max(minimum, value)


def _env_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    try:
        value = float(os.environ.get(name, "").strip() or default)
    except ValueError:
        return default
    return max(minimum, value)


@dataclass(frozen=True)
class _ReasoningPolicy:
    """Provider thinking payload persistence policy."""

    mode: str = "off"  # "off" | "tail" | "full"
    tail_chars: int = 0

    @property
    def enabled(self) -> bool:
        return self.mode != "off"


def _parse_reasoning_policy(raw: Optional[str] = None) -> _ReasoningPolicy:
    value = (
        str(raw if raw is not None else os.environ.get("Z_SCOPE_CONVERSATION_REASONING", ""))
        .strip()
        .lower()
    )
    if not value or value in {"0", "off", "false", "none", "no"}:
        return _ReasoningPolicy(mode="off")
    if value in {"1", "full", "true", "yes", "all"}:
        return _ReasoningPolicy(mode="full")
    match = re.fullmatch(r"tail(?::(\d+))?", value)
    if match:
        tail_chars = int(match.group(1)) if match.group(1) else _DEFAULT_REASONING_TAIL_CHARS
        return _ReasoningPolicy(mode="tail", tail_chars=max(0, tail_chars))
    logger.warning(
        "Invalid Z_SCOPE_CONVERSATION_REASONING=%r; expected off|tail:N|full. Falling back to off.",
        value,
    )
    return _ReasoningPolicy(mode="off")


@dataclass(frozen=True)
class ConversationSession:
    """Metadata for one agent conversation in one Python thread."""

    id: str
    thread_name: str
    agent_name: str
    thread_session_index: int
    agent_session_index: int
    label: str
    md_path: Path
    jsonl_path: Path
    # Escalation-ladder rung derived from the label's ``call_kind`` (plan
    # Phase 5: conversation session metadata rung sync).  Empty for
    # non-escalation calls.
    escalation_rung: str = ""


@dataclass
class _ConversationSessionState:
    session: ConversationSession
    started_at: str
    started_monotonic: float
    seq: int = 0
    recent_exchanges: List[Dict[str, Any]] = field(default_factory=list)
    tool_call_count: int = 0
    tool_result_count: int = 0
    tool_error_count: int = 0
    last_tool_result_summary: Optional[Dict[str, Any]] = None
    terminal_tool_call_count: int = 0
    terminal_tool_invalid_count: int = 0
    last_terminal_tool_summary: Optional[Dict[str, Any]] = None
    attempt_failure_count: int = 0
    last_attempt_failure: Optional[Dict[str, Any]] = None
    iteration_control_count: int = 0
    loop_guard_count: int = 0
    ended_at: Optional[str] = None
    iterations: Optional[int] = None
    context_tokens: Optional[int] = None
    cumulative_prompt_tokens: Optional[int] = None
    cumulative_completion_tokens: Optional[int] = None
    cumulative_total_tokens: Optional[int] = None
    wall_seconds: Optional[float] = None
    finish_reason: Optional[str] = None
    loop_guard_triggered: Optional[bool] = None
    terminal_tool_valid: Optional[bool] = None
    truncated: bool = False
    index_written: bool = False
    md_dirty: bool = False
    events_since_md_write: int = 0
    last_md_write_monotonic: float = 0.0


class ConversationRecorder:
    """Append-only JSONL trace plus bounded Markdown tail, split by LLM session."""

    def __init__(
        self,
        output_root: Path,
        metadata: Optional[Mapping[str, Any]] = None,
        flush_interval_seconds: Optional[float] = None,
    ):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.run_id = f"run_{timestamp}_{os.getpid()}"
        self.run_dir = Path(output_root) / self.run_id
        if self.run_dir.exists():
            # Two recorders created within the same second in one process
            # must not share a run directory (JSONL appends would interleave).
            self.run_id = f"{self.run_id}_{uuid.uuid4().hex[:8]}"
            self.run_dir = Path(output_root) / self.run_id
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._thread_session_counts: Dict[str, int] = {}
        self._agent_session_counts: Dict[tuple[str, str], int] = {}
        self._session_states: Dict[str, _ConversationSessionState] = {}
        self._manifest_path = self.run_dir / "manifest.json"
        self._index_path = self.run_dir / "index.jsonl"
        if flush_interval_seconds is None:
            flush_interval_seconds = _env_float("Z_SCOPE_CONVERSATION_FLUSH_INTERVAL_SECONDS", 0.0)
        self.flush_interval_seconds = max(0.0, float(flush_interval_seconds or 0.0))
        self.reasoning_policy = _parse_reasoning_policy()
        self.max_field_bytes = _env_int(
            "Z_SCOPE_CONVERSATION_MAX_FIELD_BYTES", _DEFAULT_MAX_FIELD_BYTES, minimum=256
        )
        self.md_tail_exchanges = _env_int(
            "Z_SCOPE_CONVERSATION_MD_TAIL_EXCHANGES", _DEFAULT_MD_TAIL_EXCHANGES, minimum=1
        )
        self.md_rewrite_event_interval = _env_int(
            "Z_SCOPE_CONVERSATION_MD_REWRITE_EVENT_INTERVAL",
            _DEFAULT_MD_REWRITE_EVENT_INTERVAL,
            minimum=1,
        )
        self._write_manifest(metadata or {})

    # ------------------------------------------------------------------
    # Run-level files
    # ------------------------------------------------------------------

    def _write_manifest(self, metadata: Mapping[str, Any]) -> None:
        manifest: Dict[str, Any] = {
            "schema_version": CONVERSATION_RUN_MANIFEST_SCHEMA_VERSION,
            "run_id": self.run_id,
            "started_at": self._now(),
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "recorder": {
                "event_schema_version": CONVERSATION_EVENT_SCHEMA_VERSION,
                "reasoning_policy": self.reasoning_policy.mode,
                "reasoning_tail_chars": (
                    self.reasoning_policy.tail_chars
                    if self.reasoning_policy.mode == "tail"
                    else None
                ),
                "max_field_bytes": self.max_field_bytes,
                "md_tail_exchanges": self.md_tail_exchanges,
                "md_rewrite_event_interval": self.md_rewrite_event_interval,
                "flush_interval_seconds": self.flush_interval_seconds,
            },
        }
        for key, value in dict(metadata).items():
            if value is not None:
                manifest[str(key)] = value
        try:
            with self._manifest_path.open("w", encoding="utf-8") as handle:
                json.dump(manifest, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
        except OSError:
            logger.warning("Failed to write conversation run manifest", exc_info=True)

    def _append_index_row(self, state: _ConversationSessionState) -> None:
        if state.index_written:
            return
        state.index_written = True
        session = state.session
        row = {
            "schema_version": CONVERSATION_INDEX_SCHEMA_VERSION,
            "run_id": self.run_id,
            "session_id": session.id,
            "agent": session.agent_name,
            "label": session.label,
            "thread_name": session.thread_name,
            "thread_session_index": session.thread_session_index,
            "agent_session_index": session.agent_session_index,
            "md_file": session.md_path.name,
            "jsonl_file": session.jsonl_path.name,
            "started_at": state.started_at,
            "ended_at": state.ended_at,
            "iterations": state.iterations,
            "context_tokens": state.context_tokens,
            "cumulative_prompt_tokens": state.cumulative_prompt_tokens,
            "cumulative_completion_tokens": state.cumulative_completion_tokens,
            "cumulative_total_tokens": state.cumulative_total_tokens,
            "wall_seconds": state.wall_seconds,
            "finish_reason": state.finish_reason,
            "truncated": state.truncated,
            "loop_guard_triggered": state.loop_guard_triggered,
            "terminal_tool_valid": state.terminal_tool_valid,
            "tool_call_count": state.tool_call_count,
            "tool_result_count": state.tool_result_count,
            "tool_error_count": state.tool_error_count,
            "attempt_failure_count": state.attempt_failure_count,
            "iteration_control_count": state.iteration_control_count,
            "loop_guard_count": state.loop_guard_count,
        }
        try:
            with self._index_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError:
            logger.warning("Failed to append conversation session index row", exc_info=True)

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def begin_session(
        self,
        agent_name: Optional[str] = None,
        label: Optional[str] = None,
        *,
        tools_schema_hash: Optional[str] = None,
        attribution: Optional[Mapping[str, Any]] = None,
    ) -> ConversationSession:
        thread_name = threading.current_thread().name or "main"
        safe_thread = self._safe_filename(thread_name)
        agent = agent_name or "unknown_agent"
        safe_agent = self._safe_filename(agent)

        with self._locked("begin_session"):
            thread_index = self._thread_session_counts.get(thread_name, 0) + 1
            self._thread_session_counts[thread_name] = thread_index
            agent_key = (thread_name, agent)
            agent_index = self._agent_session_counts.get(agent_key, 0) + 1
            self._agent_session_counts[agent_key] = agent_index
            session_id = f"{safe_thread}-{safe_agent}-{thread_index:04d}"
            md_path = self.run_dir / f"{session_id}.md"
            jsonl_path = self.run_dir / f"{session_id}.jsonl"
            session = ConversationSession(
                id=session_id,
                thread_name=thread_name,
                agent_name=agent,
                thread_session_index=thread_index,
                agent_session_index=agent_index,
                label=label or "",
                md_path=md_path,
                jsonl_path=jsonl_path,
                escalation_rung=escalation_rung_for_call_kind(
                    LLMUsageAttribution.from_trace(
                        trace_agent=agent, trace_label=label or ""
                    ).call_kind
                ),
            )
            state = _ConversationSessionState(
                session=session,
                started_at=self._now(),
                started_monotonic=time.monotonic(),
            )
            self._session_states[session.id] = state
            event: Dict[str, Any] = {
                "event": "session_start",
                "session": self._session_dict(session),
                "timestamp": state.started_at,
            }
            if tools_schema_hash:
                event["tools_schema_hash"] = str(tools_schema_hash)
            if attribution:
                event["attribution"] = dict(attribution)
            self._append_event(state, event)
        self._maybe_rewrite_markdown(state, force=True)
        return session

    def record_session_end(
        self,
        session: ConversationSession,
        iterations: int,
        context_tokens: int,
        truncated: bool = False,
        *,
        cumulative_prompt_tokens: Optional[int] = None,
        cumulative_completion_tokens: Optional[int] = None,
        cumulative_total_tokens: Optional[int] = None,
        wall_seconds: Optional[float] = None,
        finish_reason: Optional[str] = None,
        loop_guard_triggered: Optional[bool] = None,
        terminal_tool_valid: Optional[bool] = None,
    ) -> None:
        with self._locked("record_session_end", session):
            state = self._state_for(session)
            state.ended_at = self._now()
            state.iterations = iterations
            state.context_tokens = context_tokens
            state.truncated = bool(truncated)
            state.cumulative_prompt_tokens = cumulative_prompt_tokens
            state.cumulative_completion_tokens = cumulative_completion_tokens
            if cumulative_total_tokens is None and (
                cumulative_prompt_tokens is not None and cumulative_completion_tokens is not None
            ):
                cumulative_total_tokens = cumulative_prompt_tokens + cumulative_completion_tokens
            state.cumulative_total_tokens = cumulative_total_tokens
            state.wall_seconds = (
                wall_seconds
                if wall_seconds is not None
                else max(0.0, time.monotonic() - state.started_monotonic)
            )
            state.finish_reason = finish_reason
            if loop_guard_triggered is not None:
                state.loop_guard_triggered = loop_guard_triggered
            if terminal_tool_valid is not None:
                state.terminal_tool_valid = terminal_tool_valid
            self._append_event(
                state,
                {
                    "event": "session_end",
                    "timestamp": state.ended_at,
                    "iterations": iterations,
                    "context_tokens": context_tokens,
                    "truncated": state.truncated,
                    "cumulative_prompt_tokens": state.cumulative_prompt_tokens,
                    "cumulative_completion_tokens": state.cumulative_completion_tokens,
                    "cumulative_total_tokens": state.cumulative_total_tokens,
                    "wall_seconds": (
                        round(state.wall_seconds, 3) if state.wall_seconds is not None else None
                    ),
                    "finish_reason": finish_reason,
                    "loop_guard_triggered": state.loop_guard_triggered,
                    "terminal_tool_valid": state.terminal_tool_valid,
                },
            )
            self._append_index_row(state)
        self._maybe_rewrite_markdown(state, force=True)

    # ------------------------------------------------------------------
    # Provider exchanges and attempts
    # ------------------------------------------------------------------

    def record_exchange(
        self,
        session: ConversationSession,
        iteration: Optional[int],
        request_messages: List[Dict[str, Any]],
        response_message: Dict[str, Any],
        finish_reason: Optional[str],
        model: Optional[str],
        prompt_tokens: Optional[int],
        completion_tokens: Optional[int],
        *,
        duration_ms: Optional[int] = None,
        attempt_count: Optional[int] = None,
        base_url: Optional[str] = None,
        context_tokens: Optional[int] = None,
        usage_event_id: Optional[int] = None,
        attribution: Optional[Mapping[str, Any]] = None,
    ) -> None:
        with self._locked("record_exchange", session):
            state = self._state_for(session)
            event: Dict[str, Any] = {
                "event": "exchange",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
                "model": model,
                "finish_reason": finish_reason,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "request_messages": [
                    self._sanitize_message(message) for message in request_messages
                ],
                "response_message": self._sanitize_message(response_message),
            }
            optional_fields = {
                "duration_ms": duration_ms,
                "attempt_count": attempt_count,
                "base_url": base_url,
                "context_tokens": context_tokens,
                "usage_event_id": usage_event_id,
                "attribution": dict(attribution) if attribution else None,
            }
            for key, value in optional_fields.items():
                if value is not None:
                    event[key] = value
            self._append_event(state, event)
            state.recent_exchanges.append(event)
            del state.recent_exchanges[: -self.md_tail_exchanges]
        self._maybe_rewrite_markdown(state)

    def record_attempt_failure(
        self,
        session: ConversationSession,
        iteration: Optional[int],
        *,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        attempt: Optional[int] = None,
        outcome: str = "request_error",
        error: Optional[str] = None,
        delay_ms: Optional[int] = None,
    ) -> None:
        """Record one failed provider attempt (retry, timeout, HTTP error, fallback)."""

        with self._locked("record_attempt_failure", session):
            state = self._state_for(session)
            state.attempt_failure_count += 1
            summary = {
                "outcome": outcome,
                "model": model,
                "base_url": base_url,
                "attempt": attempt,
                "error": self._truncate(error, 500) if error else None,
            }
            state.last_attempt_failure = summary
            event: Dict[str, Any] = {
                "event": "attempt",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
                "outcome": outcome,
                "model": model,
                "base_url": base_url,
                "attempt": attempt,
                "error": self._truncate(error, 2000) if error else None,
            }
            if delay_ms is not None:
                event["delay_ms"] = max(0, int(delay_ms))
            self._append_event(state, event)
        self._maybe_rewrite_markdown(state)

    # ------------------------------------------------------------------
    # Tool calls
    # ------------------------------------------------------------------

    def record_tool_call(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        *,
        tool_call_id: Optional[str] = None,
    ) -> None:
        with self._locked("record_tool_call", session):
            state = self._state_for(session)
            state.tool_call_count += 1
            event: Dict[str, Any] = {
                "event": "tool_call",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
                "tool_name": tool_name,
                "args": self._fit_json_field(tool_args),
            }
            if tool_call_id:
                event["tool_call_id"] = tool_call_id
            self._append_event(state, event)
        self._maybe_rewrite_markdown(state)

    def record_tool_result(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        result: Dict[str, Any],
        error: Optional[str] = None,
        *,
        tool_call_id: Optional[str] = None,
        duration_ms: Optional[int] = None,
        blocked: Optional[bool] = None,
        cached_replay: Optional[bool] = None,
        repeat_count: Optional[int] = None,
        args_raw: Optional[str] = None,
        args_parse_error: Optional[str] = None,
    ) -> None:
        with self._locked("record_tool_result", session):
            state = self._state_for(session)
            state.tool_result_count += 1
            if error:
                state.tool_error_count += 1
            summary = self._tool_result_summary(
                session,
                iteration,
                tool_name,
                tool_args,
                result,
                error,
                duration_ms=duration_ms,
            )
            state.last_tool_result_summary = summary
            event: Dict[str, Any] = {
                "event": "tool_result",
                "session": self._session_dict(session),
                "timestamp": summary["timestamp"],
                "iteration": iteration,
                "tool_name": tool_name,
                "status": summary["status"],
                "error": summary["error"],
                "result_size_bytes": summary["result_size_bytes"],
                "result_keys": summary["result_keys"],
                "result": self._fit_json_field(result),
                "args": self._fit_json_field(tool_args),
            }
            optional_fields = {
                "tool_call_id": tool_call_id,
                "duration_ms": duration_ms,
                "blocked": blocked,
                "cached_replay": cached_replay,
                "repeat_count": repeat_count,
                "args_raw": self._fit_text(args_raw, self.max_field_bytes) if args_raw else None,
                "args_parse_error": (
                    self._truncate(args_parse_error, 500) if args_parse_error else None
                ),
            }
            for key, value in optional_fields.items():
                if value is not None:
                    event[key] = value
            self._append_event(state, event)
        self._maybe_rewrite_markdown(state)

    def record_terminal_tool(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        valid: bool,
        error: Optional[str] = None,
        *,
        tool_call_id: Optional[str] = None,
    ) -> None:
        """Record a final-tool submission without counting it as a normal tool result."""

        with self._locked("record_terminal_tool", session):
            state = self._state_for(session)
            state.terminal_tool_call_count += 1
            if not valid:
                state.terminal_tool_invalid_count += 1
            state.last_terminal_tool_summary = {
                "event": "terminal_tool_summary",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
                "tool_name": tool_name,
                "valid": bool(valid),
                "tool_call_id": tool_call_id,
                "tool_arg_keys": sorted(str(k) for k in tool_args.keys()),
                "error": self._truncate(error, 500) if error else None,
            }
            event: Dict[str, Any] = {
                "event": "terminal_tool",
                "session": self._session_dict(session),
                "timestamp": state.last_terminal_tool_summary["timestamp"],
                "iteration": iteration,
                "tool_name": tool_name,
                "valid": bool(valid),
                "args": self._fit_json_field(tool_args),
                "error": self._truncate(error, 2000) if error else None,
            }
            if tool_call_id:
                event["tool_call_id"] = tool_call_id
            self._append_event(state, event)
        self._maybe_rewrite_markdown(state)

    # ------------------------------------------------------------------
    # Runtime interventions
    # ------------------------------------------------------------------

    def record_iteration_control(
        self,
        session: ConversationSession,
        iteration: int,
        kind: str,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Record a runtime intervention injected into the conversation."""

        with self._locked("record_iteration_control", session):
            state = self._state_for(session)
            state.iteration_control_count += 1
            event: Dict[str, Any] = {
                "event": "iteration_control",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
                "kind": kind,
            }
            if detail:
                event["detail"] = self._fit_json_field(dict(detail))
            self._append_event(state, event)
        self._maybe_rewrite_markdown(state)

    def record_loop_guard(
        self,
        session: ConversationSession,
        iteration: int,
        *,
        tool: Optional[str] = None,
        repeat_count: Optional[int] = None,
        disabled_tools: Optional[List[str]] = None,
        reason: Optional[str] = None,
        scope: Optional[str] = None,
        recovered: Optional[bool] = None,
    ) -> None:
        """Record a loop-guard trigger (identical repeated calls / terminal failures)."""

        with self._locked("record_loop_guard", session):
            state = self._state_for(session)
            state.loop_guard_count += 1
            state.loop_guard_triggered = True
            event: Dict[str, Any] = {
                "event": "loop_guard",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
            }
            optional_fields = {
                "tool": tool,
                "repeat_count": repeat_count,
                "disabled_tools": list(disabled_tools) if disabled_tools else None,
                "reason": reason,
                "scope": scope,
                "recovered": recovered,
            }
            for key, value in optional_fields.items():
                if value is not None:
                    event[key] = value
            self._append_event(state, event)
        self._maybe_rewrite_markdown(state)

    # ------------------------------------------------------------------
    # Event persistence primitives
    # ------------------------------------------------------------------

    def _append_event(self, state: _ConversationSessionState, event: Dict[str, Any]) -> None:
        """Append one event line. Must be called while holding ``self._lock``."""

        state.seq += 1
        event["schema_version"] = CONVERSATION_EVENT_SCHEMA_VERSION
        event["seq"] = state.seq
        try:
            with state.session.jsonl_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        except OSError:
            logger.warning(
                "Failed to append conversation event session=%s event=%s",
                state.session.id,
                event.get("event"),
                exc_info=True,
            )
            return
        state.md_dirty = True
        state.events_since_md_write += 1

    def _maybe_rewrite_markdown(
        self, state: _ConversationSessionState, *, force: bool = False
    ) -> None:
        if not force:
            if not state.md_dirty:
                return
            elapsed = time.monotonic() - float(state.last_md_write_monotonic or 0.0)
            interval_due = (
                self.flush_interval_seconds > 0 and elapsed >= self.flush_interval_seconds
            )
            events_due = state.events_since_md_write >= self.md_rewrite_event_interval
            if not (interval_due or events_due):
                return
        started = time.monotonic()
        session = state.session
        self._write_text(session.md_path, self._format_session_snapshot(state))
        state.md_dirty = False
        state.events_since_md_write = 0
        state.last_md_write_monotonic = time.monotonic()
        duration = state.last_md_write_monotonic - started
        if duration >= _MD_WRITE_LOG_THRESHOLD_SECONDS:
            logger.info(
                "[recorder] markdown write session=%s path=%s duration=%.2fs",
                session.id,
                session.md_path,
                duration,
            )

    # ------------------------------------------------------------------
    # Sanitising / truncation helpers
    # ------------------------------------------------------------------

    def _sanitize_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Apply the reasoning persistence policy to one message copy."""

        source = dict(message or {})
        if not self.reasoning_policy.enabled:
            return {key: value for key, value in source.items() if key not in _REASONING_KEYS}
        sanitized: Dict[str, Any] = {}
        for key, value in source.items():
            if key in _REASONING_KEYS:
                if not isinstance(value, str) or not value:
                    if value is not None:
                        sanitized[key] = value
                    continue
                if self.reasoning_policy.mode == "full":
                    sanitized[key] = value
                    continue
                fitted = self._fit_text(value, self.reasoning_policy.tail_chars)
                sanitized[key] = fitted
                if fitted != value:
                    sanitized[f"{key}_truncated"] = True
            else:
                sanitized[key] = value
        return sanitized

    def _fit_json_field(self, value: Any) -> Any:
        """Return value as-is when it serialises within the byte budget, else a preview."""

        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            text = str(value)
        if len(text.encode("utf-8")) <= self.max_field_bytes:
            return value
        return {
            "__truncated__": True,
            "preview": self._fit_text(text, self.max_field_bytes),
            "original_chars": len(text),
        }

    @staticmethod
    def _fit_text(text: str, byte_limit: int) -> str:
        """Trim ``text`` so its UTF-8 encoding fits ``byte_limit`` bytes."""

        if byte_limit <= 0:
            return ""
        encoded = text.encode("utf-8")
        if len(encoded) <= byte_limit:
            return text
        chars = byte_limit
        while chars > 0:
            candidate = text[:chars]
            encoded = candidate.encode("utf-8")
            if len(encoded) <= byte_limit:
                return candidate
            # Scale the estimate down; UTF-8 multi-byte overhead shrinks fast.
            chars = max(1, int(chars * byte_limit / max(1, len(encoded))))
        return ""

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _safe_filename(value: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
        return safe[:80] or "thread"

    @staticmethod
    def _session_dict(session: ConversationSession) -> Dict[str, Any]:
        result = {
            "id": session.id,
            "thread_name": session.thread_name,
            "agent_name": session.agent_name,
            "thread_session_index": session.thread_session_index,
            "agent_session_index": session.agent_session_index,
            "label": session.label,
        }
        if session.escalation_rung:
            result["escalation_rung"] = session.escalation_rung
        return result

    @staticmethod
    def _format_session_header(state: _ConversationSessionState) -> str:
        session = state.session
        return (
            f"\n## Thread `{session.thread_name}` | Session {session.thread_session_index}\n\n"
            f"- Agent: `{session.agent_name}`\n"
            f"- Agent session in this thread: `{session.agent_session_index}`\n"
            f"- Label: {session.label or '(none)'}\n"
            f"- Started: {state.started_at}\n"
            f"- Event schema: `{CONVERSATION_EVENT_SCHEMA_VERSION}` (full JSONL trace beside this file)\n"
            f"- Reasoning policy: `{_parse_reasoning_policy().mode}`\n\n"
            f"> This snapshot contains proprietary source code and model outputs. Do not share externally.\n\n"
        )

    def _state_for(self, session: ConversationSession) -> _ConversationSessionState:
        try:
            return self._session_states[session.id]
        except KeyError as exc:
            raise ValueError(f"Unknown conversation session: {session.id}") from exc

    @contextmanager
    def _locked(
        self,
        context: str,
        session: Optional[ConversationSession] = None,
    ) -> Iterator[None]:
        started = time.monotonic()
        session_id = session.id if session else ""
        if self._lock.locked():
            logger.info(
                "[recorder-lock] waiting context=%s session=%s",
                context,
                session_id,
            )
        self._lock.acquire()
        waited = time.monotonic() - started
        if waited >= _LOCK_LOG_THRESHOLD_SECONDS:
            logger.info(
                "[recorder-lock] outcome context=%s session=%s waited=%.2fs",
                context,
                session_id,
                waited,
            )
        try:
            yield
        finally:
            self._lock.release()

    def _format_session_snapshot(self, state: _ConversationSessionState) -> str:
        parts = [self._format_session_header(state)]
        exchanges = state.recent_exchanges
        total = state.iterations
        if exchanges:
            shown = len(exchanges)
            omitted = None
            if total is not None and total > shown:
                omitted = total - shown
            parts.append(
                "### Recent Exchanges\n\n"
                f"- Rendering the last `{shown}` exchange(s) of this session; "
                "the complete history lives in the JSONL trace.\n"
            )
            if omitted is not None:
                parts.append(f"- `{omitted}` earlier iteration(s) omitted from this snapshot.\n")
            parts.append("\n")
            for exchange in exchanges:
                parts.extend(self._format_exchange_section(exchange, state))
        else:
            parts.append("### Recent Exchanges\n\n- `(none yet)`\n\n")

        if state.attempt_failure_count:
            parts.append("### Attempt Failures\n\n")
            parts.append(f"- Failed provider attempts observed: `{state.attempt_failure_count}`\n")
            if state.last_attempt_failure:
                summary = state.last_attempt_failure
                parts.append(
                    f"- Last failure: outcome `{summary.get('outcome')}`, "
                    f"model `{summary.get('model') or 'unknown'}`, "
                    f"attempt `{summary.get('attempt')}`\n"
                )
                if summary.get("error"):
                    parts.append(f"- Last error: `{summary['error']}`\n")
            parts.append("\n")

        if state.tool_call_count or state.tool_result_count:
            parts.append("### Tool Result Summary\n\n")
            parts.append(f"- Tool calls observed: `{state.tool_call_count}`\n")
            parts.append(f"- Tool results observed: `{state.tool_result_count}`\n")
            parts.append(f"- Tool errors observed: `{state.tool_error_count}`\n")
            if state.last_tool_result_summary:
                summary = state.last_tool_result_summary
                parts.append(f"- Last tool iteration: `{summary.get('iteration')}`\n")
                parts.append(f"- Last tool: `{summary.get('tool_name') or 'unknown'}`\n")
                parts.append(f"- Last status: `{summary.get('status')}`\n")
                if summary.get("duration_ms") is not None:
                    parts.append(f"- Last duration ms: `{summary.get('duration_ms')}`\n")
                arg_keys = ", ".join(summary.get("tool_arg_keys") or []) or "(none)"
                parts.append(f"- Last argument keys: `{arg_keys}`\n")
                result_keys = ", ".join(summary.get("result_keys") or []) or "(none)"
                parts.append(f"- Last result keys: `{result_keys}`\n")
                if summary.get("error"):
                    parts.append(f"- Last error: `{summary['error']}`\n")
            parts.append("\n")

        if state.terminal_tool_call_count:
            summary = state.last_terminal_tool_summary or {}
            parts.extend(
                [
                    "### Terminal Tool Summary\n\n",
                    f"- Terminal submissions observed: `{state.terminal_tool_call_count}`\n",
                    f"- Terminal invalid submissions: `{state.terminal_tool_invalid_count}`\n",
                    f"- Last terminal tool: `{summary.get('tool_name') or 'unknown'}`\n",
                    f"- Last terminal payload valid: `{str(bool(summary.get('valid'))).lower()}`\n",
                    f"- Last terminal argument keys: `{', '.join(summary.get('tool_arg_keys') or []) or '(none)'}`\n",
                ]
            )
            if summary.get("error"):
                parts.append(f"- Last terminal error: `{summary['error']}`\n")
            parts.append("\n")

        if state.loop_guard_count:
            parts.append("### Loop Guard\n\n")
            parts.append(f"- Loop guard events observed: `{state.loop_guard_count}`\n\n")

        if state.ended_at:
            parts.extend(
                [
                    "### Session End\n\n",
                    f"- Agent: `{state.session.agent_name}`\n",
                    f"- Iterations: `{state.iterations}`\n",
                    f"- Final context tokens: `{state.context_tokens}`\n",
                    f"- Cumulative prompt tokens: `{state.cumulative_prompt_tokens}`\n",
                    f"- Cumulative completion tokens: `{state.cumulative_completion_tokens}`\n",
                    f"- Cumulative total tokens: `{state.cumulative_total_tokens}`\n",
                    f"- Wall seconds: `{round(state.wall_seconds, 3) if state.wall_seconds is not None else None}`\n",
                    f"- Finish reason: `{state.finish_reason or 'unknown'}`\n",
                    f"- Truncated: `{str(state.truncated).lower()}`\n",
                    f"- Loop guard triggered: `{str(state.loop_guard_triggered).lower() if state.loop_guard_triggered is not None else 'unknown'}`\n",
                    f"- Ended: {state.ended_at}\n\n",
                ]
            )
        return "".join(parts)

    def _format_exchange_section(
        self, exchange: Dict[str, Any], state: _ConversationSessionState
    ) -> List[str]:
        iteration_label = self._iteration_label(exchange.get("iteration"))
        total_label = str(state.iterations) if state.iterations is not None else "pending"
        prompt_tokens = exchange.get("prompt_tokens") or 0
        completion_tokens = exchange.get("completion_tokens") or 0
        fields = [
            f"- Final retained iteration: `{iteration_label}` / total iterations `{total_label}`\n",
            f"- Model: `{exchange.get('model') or 'unknown'}`\n",
            f"- Finish reason: `{exchange.get('finish_reason') or 'unknown'}`\n",
            f"- Context tokens: prompt~{prompt_tokens}, "
            f"completion~{completion_tokens}, total~{prompt_tokens + completion_tokens}\n",
        ]
        if exchange.get("duration_ms") is not None:
            fields.append(f"- Duration ms: `{exchange.get('duration_ms')}`\n")
        if exchange.get("attempt_count") is not None:
            fields.append(f"- Attempts: `{exchange.get('attempt_count')}`\n")
        if exchange.get("base_url"):
            fields.append(f"- Base URL: `{exchange.get('base_url')}`\n")
        return [
            f"#### Exchange `{iteration_label}` ({state.session.agent_name})\n\n",
            *fields,
            "\n##### Z-SCOPE -> Model\n\n",
            self._format_messages(exchange.get("request_messages") or []),
            "\n##### Model -> Z-SCOPE\n\n",
            self._format_message(exchange.get("response_message") or {}),
            "\n",
        ]

    def _tool_result_summary(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        result: Dict[str, Any],
        error: Optional[str],
        *,
        duration_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        return {
            "event": "tool_result_summary",
            "session": self._session_dict(session),
            "timestamp": self._now(),
            "iteration": iteration,
            "tool_name": tool_name,
            "status": "error" if error else "ok",
            "tool_arg_keys": sorted(str(k) for k in tool_args.keys()),
            "result_keys": sorted(str(k) for k in result.keys()),
            "result_size_bytes": len(json.dumps(result, ensure_ascii=False, default=str)),
            "duration_ms": duration_ms,
            "error": self._truncate(error, 500) if error else None,
        }

    @staticmethod
    def _iteration_label(iteration: Optional[int]) -> str:
        return str(iteration) if iteration is not None else "direct"

    @staticmethod
    def _truncate(value: str, limit: int) -> str:
        return value if len(value) <= limit else value[: limit - 3] + "..."

    @staticmethod
    def _write_text(path: Path, text: str) -> None:
        with path.open("w", encoding="utf-8") as handle:
            handle.write(text)

    def _format_messages(self, messages: List[Dict[str, Any]]) -> str:
        return "\n".join(self._format_message(msg) for msg in messages) + "\n"

    def _format_message(self, msg: Dict[str, Any]) -> str:
        role = msg.get("role", "unknown")
        parts = [f"**{role}**\n\n"]
        content = msg.get("content")
        if content:
            label = "**Model content (output)**" if role == "assistant" else "**Content**"
            parts.append(label)
            parts.append("\n\n")
            parts.append(str(content))
            parts.append("\n\n")
        for reasoning_key in ("reasoning_content", "reasoning", "thinking"):
            reasoning = msg.get(reasoning_key)
            if reasoning:
                parts.append(f"**Reasoning ({reasoning_key})**\n\n")
                parts.append(str(reasoning))
                parts.append("\n\n")
        if msg.get("tool_calls"):
            parts.append("Tool calls:\n\n")
            parts.append(self._fenced_json(msg.get("tool_calls")))
            parts.append("\n")
        if msg.get("tool_call_id"):
            parts.append(f"Tool call id: `{msg.get('tool_call_id')}`\n\n")
        return "".join(parts).rstrip() + "\n"

    @staticmethod
    def _fenced_json(value: Any) -> str:
        return (
            "```json\n" + json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n```\n"
        )


_RECORDER: Optional[ConversationRecorder] = None


def enable_conversation_recording(
    output_root: Path,
    metadata: Optional[Mapping[str, Any]] = None,
) -> ConversationRecorder:
    """Enable process-wide LLM conversation recording."""

    global _RECORDER
    _RECORDER = ConversationRecorder(output_root, metadata=metadata)
    return _RECORDER


def get_conversation_recorder() -> Optional[ConversationRecorder]:
    """Return the active recorder, if verbose recording is enabled."""

    return _RECORDER


def disable_conversation_recording() -> None:
    """Disable process-wide LLM conversation recording."""

    global _RECORDER
    _RECORDER = None
