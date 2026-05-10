"""Human-readable LLM conversation recording for verbose runs."""

from __future__ import annotations

import json
import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


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


class ConversationRecorder:
    """Append-only Markdown and JSONL recorder split by Python thread."""

    def __init__(self, output_root: Path):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.run_dir = Path(output_root) / f"run_{timestamp}_{os.getpid()}"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._thread_session_counts: Dict[str, int] = {}
        self._agent_session_counts: Dict[tuple[str, str], int] = {}

    def begin_session(
        self,
        agent_name: Optional[str] = None,
        label: Optional[str] = None,
    ) -> ConversationSession:
        thread_name = threading.current_thread().name or "main"
        safe_thread = self._safe_filename(thread_name)
        agent = agent_name or "unknown_agent"
        safe_agent = self._safe_filename(agent)
        md_path = self.run_dir / f"{safe_thread}.md"
        jsonl_path = self.run_dir / f"{safe_thread}.jsonl"

        with self._lock:
            thread_index = self._thread_session_counts.get(thread_name, 0) + 1
            self._thread_session_counts[thread_name] = thread_index
            agent_key = (thread_name, agent)
            agent_index = self._agent_session_counts.get(agent_key, 0) + 1
            self._agent_session_counts[agent_key] = agent_index
            session_id = f"{safe_thread}-{safe_agent}-{thread_index:04d}"
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
            self._append_text(
                md_path,
                self._format_session_header(session),
            )
            self._append_jsonl(
                jsonl_path,
                {
                    "event": "session_start",
                    "session": self._session_dict(session),
                    "timestamp": self._now(),
                },
            )
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
        header = (
            f"\n### {session.agent_name} iteration "
            f"{iteration if iteration is not None else 'direct'}\n\n"
            f"- Model: `{model or 'unknown'}`\n"
            f"- Finish reason: `{finish_reason or 'unknown'}`\n"
            f"- Context tokens: prompt~{prompt_tokens or 0}, "
            f"completion~{completion_tokens or 0}, total~{(prompt_tokens or 0) + (completion_tokens or 0)}\n\n"
        )
        request_text = "#### Z-SCOPE -> Model\n\n" + self._format_messages(request_messages)
        response_text = "#### Model -> Z-SCOPE\n\n" + self._format_message(response_message)

        with self._lock:
            self._append_text(session.md_path, header + request_text + "\n" + response_text + "\n")
            self._append_jsonl(
                session.jsonl_path,
                {
                    "event": "exchange",
                    "session": self._session_dict(session),
                    "timestamp": self._now(),
                    "iteration": iteration,
                    "model": model,
                    "finish_reason": finish_reason,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "request_messages": request_messages,
                    "response_message": response_message,
                },
            )

    def record_tool_result(
        self,
        session: ConversationSession,
        iteration: int,
        tool_name: Optional[str],
        tool_args: Dict[str, Any],
        result: Dict[str, Any],
        error: Optional[str] = None,
    ) -> None:
        status = "error" if error else "ok"
        body = [
            f"\n#### Z-SCOPE Tool Result ({session.agent_name} iteration {iteration})\n\n",
            f"- Tool: `{tool_name or 'unknown'}`\n",
            f"- Status: `{status}`\n\n",
            "**Arguments**\n\n",
            self._fenced_json(tool_args),
            "\n**Result**\n\n",
            self._fenced_json({"error": error} if error else result),
            "\n",
        ]
        with self._lock:
            self._append_text(session.md_path, "".join(body))
            self._append_jsonl(
                session.jsonl_path,
                {
                    "event": "tool_result",
                    "session": self._session_dict(session),
                    "timestamp": self._now(),
                    "iteration": iteration,
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "result": result,
                    "error": error,
                },
            )

    def record_session_end(
        self,
        session: ConversationSession,
        iterations: int,
        context_tokens: int,
        truncated: bool = False,
    ) -> None:
        text = (
            f"\n### Session End\n\n"
            f"- Agent: `{session.agent_name}`\n"
            f"- Iterations: `{iterations}`\n"
            f"- Final context tokens: `{context_tokens}`\n"
            f"- Truncated: `{str(truncated).lower()}`\n\n"
        )
        with self._lock:
            self._append_text(session.md_path, text)
            self._append_jsonl(
                session.jsonl_path,
                {
                    "event": "session_end",
                    "session": self._session_dict(session),
                    "timestamp": self._now(),
                    "iterations": iterations,
                    "context_tokens": context_tokens,
                    "truncated": truncated,
                },
            )

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _safe_filename(value: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
        return safe[:80] or "thread"

    @staticmethod
    def _append_text(path: Path, text: str) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(text)

    @staticmethod
    def _append_jsonl(path: Path, data: Dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

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
    def _format_session_header(session: ConversationSession) -> str:
        return (
            f"\n## Thread `{session.thread_name}` | Session {session.thread_session_index}\n\n"
            f"- Agent: `{session.agent_name}`\n"
            f"- Agent session in this thread: `{session.agent_session_index}`\n"
            f"- Label: {session.label or '(none)'}\n"
            f"- Started: {ConversationRecorder._now()}\n\n"
        )

    def _format_messages(self, messages: List[Dict[str, Any]]) -> str:
        return "\n".join(self._format_message(msg) for msg in messages) + "\n"

    def _format_message(self, msg: Dict[str, Any]) -> str:
        role = msg.get("role", "unknown")
        parts = [f"**{role}**\n\n"]
        content = msg.get("content")
        if content:
            parts.append(str(content))
            parts.append("\n\n")
        if msg.get("reasoning_content"):
            parts.append("<details><summary>reasoning_content</summary>\n\n")
            parts.append(str(msg.get("reasoning_content")))
            parts.append("\n\n</details>\n\n")
        if msg.get("tool_calls"):
            parts.append("Tool calls:\n\n")
            parts.append(self._fenced_json(msg.get("tool_calls")))
            parts.append("\n")
        if msg.get("tool_call_id"):
            parts.append(f"Tool call id: `{msg.get('tool_call_id')}`\n\n")
        return "".join(parts).rstrip() + "\n"

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
