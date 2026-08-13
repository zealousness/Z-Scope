"""Human-readable LLM conversation recording for verbose runs."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


logger = logging.getLogger(__name__)
_RECORDER_LOCK_LOG_THRESHOLD_SECONDS = 0.05
_RECORDER_WRITE_LOG_THRESHOLD_SECONDS = 0.50


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


@dataclass
class _ConversationSessionState:
    session: ConversationSession
    started_at: str
    latest_exchange: Optional[Dict[str, Any]] = None
    tool_result_count: int = 0
    last_tool_result_summary: Optional[Dict[str, Any]] = None
    terminal_tool_call_count: int = 0
    last_terminal_tool_summary: Optional[Dict[str, Any]] = None
    ended_at: Optional[str] = None
    iterations: Optional[int] = None
    context_tokens: Optional[int] = None
    truncated: bool = False
    dirty: bool = False
    last_write_monotonic: float = 0.0


class ConversationRecorder:
    """Compact Markdown and JSONL recorder split by LLM session."""

    def __init__(self, output_root: Path, flush_interval_seconds: Optional[float] = None):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.run_dir = Path(output_root) / f"run_{timestamp}_{os.getpid()}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._thread_session_counts: Dict[str, int] = {}
        self._agent_session_counts: Dict[tuple[str, str], int] = {}
        self._session_states: Dict[str, _ConversationSessionState] = {}
        if flush_interval_seconds is None:
            try:
                flush_interval_seconds = float(
                    os.environ.get("Z_SCOPE_CONVERSATION_FLUSH_INTERVAL_SECONDS", "0") or 0
                )
            except ValueError:
                flush_interval_seconds = 0.0
        self.flush_interval_seconds = max(0.0, float(flush_interval_seconds or 0.0))

    def begin_session(
        self,
        agent_name: Optional[str] = None,
        label: Optional[str] = None,
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
            )
            self._session_states[session.id] = _ConversationSessionState(
                session=session,
                started_at=self._now(),
            )
            state = self._state_for(session)
        self._rewrite_session_files(state, force=True)
        return session

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
    ) -> None:
        with self._locked("record_exchange", session):
            state = self._state_for(session)
            state.latest_exchange = {
                "event": "exchange",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
                "model": model,
                "finish_reason": finish_reason,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "request_messages": [
                    self._without_reasoning_content(message) for message in request_messages
                ],
                "response_message": self._without_reasoning_content(response_message),
            }
            state.dirty = True
        self._rewrite_session_files(state)

    def record_tool_result(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        result: Dict[str, Any],
        error: Optional[str] = None,
    ) -> None:
        with self._locked("record_tool_result", session):
            state = self._state_for(session)
            state.tool_result_count += 1
            state.last_tool_result_summary = self._tool_result_summary(
                session,
                iteration,
                tool_name,
                tool_args,
                result,
                error,
            )
            state.dirty = True
        self._rewrite_session_files(state)

    def record_terminal_tool(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        valid: bool,
        error: Optional[str] = None,
    ) -> None:
        """Record a final-tool submission without counting it as a normal tool result."""
        with self._locked("record_terminal_tool", session):
            state = self._state_for(session)
            state.terminal_tool_call_count += 1
            state.last_terminal_tool_summary = {
                "event": "terminal_tool_summary",
                "session": self._session_dict(session),
                "timestamp": self._now(),
                "iteration": iteration,
                "tool_name": tool_name,
                "valid": bool(valid),
                "tool_arg_keys": sorted(str(k) for k in tool_args.keys()),
                "error": self._truncate(error, 500) if error else None,
            }
            state.dirty = True
        self._rewrite_session_files(state)

    def record_session_end(
        self,
        session: ConversationSession,
        iterations: int,
        context_tokens: int,
        truncated: bool = False,
    ) -> None:
        with self._locked("record_session_end", session):
            state = self._state_for(session)
            state.ended_at = self._now()
            state.iterations = iterations
            state.context_tokens = context_tokens
            state.truncated = truncated
            state.dirty = True
        self._rewrite_session_files(state, force=True)

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _safe_filename(value: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
        return safe[:80] or "thread"

    @staticmethod
    def _session_dict(session: ConversationSession) -> Dict[str, Any]:
        return {
            "id": session.id,
            "thread_name": session.thread_name,
            "agent_name": session.agent_name,
            "thread_session_index": session.thread_session_index,
            "agent_session_index": session.agent_session_index,
            "label": session.label,
        }

    @staticmethod
    def _format_session_header(state: _ConversationSessionState) -> str:
        session = state.session
        return (
            f"\n## Thread `{session.thread_name}` | Session {session.thread_session_index}\n\n"
            f"- Agent: `{session.agent_name}`\n"
            f"- Agent session in this thread: `{session.agent_session_index}`\n"
            f"- Label: {session.label or '(none)'}\n"
            f"- Started: {state.started_at}\n\n"
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
        if waited >= _RECORDER_LOCK_LOG_THRESHOLD_SECONDS:
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

    def _rewrite_session_files(
        self, state: _ConversationSessionState, *, force: bool = False
    ) -> None:
        if not force:
            if not state.dirty or self.flush_interval_seconds <= 0:
                return
            elapsed = time.monotonic() - float(state.last_write_monotonic or 0.0)
            if elapsed < self.flush_interval_seconds:
                return
        started = time.monotonic()
        session = state.session
        self._write_text(session.md_path, self._format_session_snapshot(state))
        self._write_jsonl(session.jsonl_path, self._jsonl_events(state))
        state.dirty = False
        state.last_write_monotonic = time.monotonic()
        duration = time.monotonic() - started
        if duration >= _RECORDER_WRITE_LOG_THRESHOLD_SECONDS:
            logger.info(
                "[recorder] write session=%s md=%s jsonl=%s duration=%.2fs",
                session.id,
                session.md_path,
                session.jsonl_path,
                duration,
            )

    def _format_session_snapshot(self, state: _ConversationSessionState) -> str:
        parts = [self._format_session_header(state)]
        exchange = state.latest_exchange
        if exchange:
            iteration_label = self._iteration_label(exchange.get("iteration"))
            total_label = str(state.iterations) if state.iterations is not None else "pending"
            prompt_tokens = exchange.get("prompt_tokens") or 0
            completion_tokens = exchange.get("completion_tokens") or 0
            parts.extend(
                [
                    f"### Retained Exchange ({state.session.agent_name})\n\n",
                    f"- Final retained iteration: `{iteration_label}` / total iterations `{total_label}`\n",
                    f"- Model: `{exchange.get('model') or 'unknown'}`\n",
                    f"- Finish reason: `{exchange.get('finish_reason') or 'unknown'}`\n",
                    f"- Context tokens: prompt~{prompt_tokens}, "
                    f"completion~{completion_tokens}, total~{prompt_tokens + completion_tokens}\n\n",
                    "#### Z-SCOPE -> Model\n\n",
                    self._format_messages(exchange.get("request_messages") or []),
                    "\n#### Model -> Z-SCOPE\n\n",
                    self._format_message(exchange.get("response_message") or {}),
                    "\n",
                ]
            )
        else:
            parts.append("### Retained Exchange\n\n- Final retained iteration: `(none yet)`\n\n")

        if state.tool_result_count:
            parts.append("#### Tool Result Summary\n\n")
            parts.append(f"- Tool results observed: `{state.tool_result_count}`\n")
            if state.last_tool_result_summary:
                summary = state.last_tool_result_summary
                parts.extend(
                    [
                        f"- Last tool iteration: `{summary.get('iteration')}`\n",
                        f"- Last tool: `{summary.get('tool_name') or 'unknown'}`\n",
                        f"- Last status: `{summary.get('status')}`\n",
                        f"- Last argument keys: `{', '.join(summary.get('tool_arg_keys') or []) or '(none)'}`\n",
                        f"- Last result keys: `{', '.join(summary.get('result_keys') or []) or '(none)'}`\n",
                    ]
                )
                if summary.get("error"):
                    parts.append(f"- Last error: `{summary.get('error')}`\n")
            parts.append("\n")

        if state.terminal_tool_call_count:
            summary = state.last_terminal_tool_summary or {}
            parts.extend(
                [
                    "#### Terminal Tool Summary\n\n",
                    f"- Terminal submissions observed: `{state.terminal_tool_call_count}`\n",
                    f"- Last terminal tool: `{summary.get('tool_name') or 'unknown'}`\n",
                    f"- Last terminal payload valid: `{str(bool(summary.get('valid'))).lower()}`\n",
                    f"- Last terminal argument keys: `{', '.join(summary.get('tool_arg_keys') or []) or '(none)'}`\n",
                ]
            )
            if summary.get("error"):
                parts.append(f"- Last terminal error: `{summary.get('error')}`\n")
            parts.append("\n")

        if state.ended_at:
            parts.extend(
                [
                    "### Session End\n\n",
                    f"- Agent: `{state.session.agent_name}`\n",
                    f"- Iterations: `{state.iterations}`\n",
                    f"- Final context tokens: `{state.context_tokens}`\n",
                    f"- Truncated: `{str(state.truncated).lower()}`\n",
                    f"- Ended: {state.ended_at}\n\n",
                ]
            )
        return "".join(parts)

    def _jsonl_events(self, state: _ConversationSessionState) -> List[Dict[str, Any]]:
        session = state.session
        events: List[Dict[str, Any]] = [
            {
                "event": "session_start",
                "session": self._session_dict(session),
                "timestamp": state.started_at,
            }
        ]
        if state.latest_exchange:
            exchange = dict(state.latest_exchange)
            exchange["retained_exchange"] = True
            exchange["total_iterations"] = state.iterations
            events.append(exchange)
        if state.tool_result_count:
            events.append(
                {
                    "event": "tool_result_summary",
                    "session": self._session_dict(session),
                    "timestamp": (state.last_tool_result_summary or {}).get(
                        "timestamp", self._now()
                    ),
                    "tool_result_count": state.tool_result_count,
                    "last_tool_result": state.last_tool_result_summary,
                }
            )
        if state.terminal_tool_call_count:
            events.append(
                {
                    "event": "terminal_tool_summary",
                    "session": self._session_dict(session),
                    "timestamp": (state.last_terminal_tool_summary or {}).get(
                        "timestamp", self._now()
                    ),
                    "terminal_tool_call_count": state.terminal_tool_call_count,
                    "last_terminal_tool": state.last_terminal_tool_summary,
                }
            )
        if state.ended_at:
            events.append(
                {
                    "event": "session_end",
                    "session": self._session_dict(session),
                    "timestamp": state.ended_at,
                    "iterations": state.iterations,
                    "context_tokens": state.context_tokens,
                    "truncated": state.truncated,
                }
            )
        return events

    def _tool_result_summary(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        result: Dict[str, Any],
        error: Optional[str],
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
        with path.open("w", encoding="utf-8") as f:
            f.write(text)

    @staticmethod
    def _write_jsonl(path: Path, events: List[Dict[str, Any]]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for event in events:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

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
        if msg.get("tool_calls"):
            parts.append("Tool calls:\n\n")
            parts.append(self._fenced_json(msg.get("tool_calls")))
            parts.append("\n")
        if msg.get("tool_call_id"):
            parts.append(f"Tool call id: `{msg.get('tool_call_id')}`\n\n")
        return "".join(parts).rstrip() + "\n"

    @staticmethod
    def _without_reasoning_content(message: Dict[str, Any]) -> Dict[str, Any]:
        """Drop provider thinking payloads before ordinary conversation persistence."""

        return {
            key: value
            for key, value in dict(message or {}).items()
            if key not in {"reasoning_content", "reasoning", "thinking"}
        }

    @staticmethod
    def _fenced_json(value: Any) -> str:
        return "```json\n" + json.dumps(value, ensure_ascii=False, indent=2) + "\n```\n"


_RECORDER: Optional[ConversationRecorder] = None


def enable_conversation_recording(output_root: Path) -> ConversationRecorder:
    """Enable process-wide LLM conversation recording."""

    global _RECORDER
    _RECORDER = ConversationRecorder(output_root)
    return _RECORDER


def get_conversation_recorder() -> Optional[ConversationRecorder]:
    """Return the active recorder, if verbose recording is enabled."""

    return _RECORDER


def disable_conversation_recording() -> None:
    """Disable process-wide LLM conversation recording."""

    global _RECORDER
    _RECORDER = None
