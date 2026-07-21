"""Runtime policy checks for LLM tools and MCP primitives."""

from __future__ import annotations

import fnmatch
import json
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Union

from ..framework.base import validate_function_arguments

Hook = Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]


SENSITIVE_ARG_PARTS = (
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "credential",
    "password",
    "secret",
    "session",
    "token",
)

SENSITIVE_PATH_KEY_PARTS = (
    "file",
    "filename",
    "path",
    "uri",
)

SENSITIVE_PATH_VALUE_PARTS = (
    ".env",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "password",
    "secret",
    "session",
    "token",
    "zscope.local.env",
)

SENSITIVE_TEXT_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"), r"\1[redacted]"),
    (re.compile(r"(?i)((?:api[_-]?key|apikey|token|session|password|secret)\s*[:=]\s*)[^\s,;]+"), r"\1[redacted]"),
)


def deny_sensitive_paths_hook(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """PreToolUse hook that denies obvious secret-bearing file/path inputs."""

    arguments = payload.get("arguments")
    if not isinstance(arguments, dict):
        return None
    blocked_key = _first_sensitive_path_key(arguments)
    if not blocked_key:
        return None
    return {"reason": f"sensitive path argument '{blocked_key}' is denied"}


def _first_sensitive_path_key(value: Any, *, parent_key: str = "") -> str:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            nested = _first_sensitive_path_key(item, parent_key=key_text)
            if nested:
                return nested
        return ""
    if isinstance(value, list):
        for item in value:
            nested = _first_sensitive_path_key(item, parent_key=parent_key)
            if nested:
                return nested
        return ""
    if not isinstance(value, str):
        return ""

    key_lower = parent_key.lower()
    if not any(part in key_lower for part in SENSITIVE_PATH_KEY_PARTS):
        return ""
    normalized = value.replace("\\", "/").lower()
    basename = normalized.rsplit("/", 1)[-1]
    if any(part in normalized or part in basename for part in SENSITIVE_PATH_VALUE_PARTS):
        return parent_key
    return ""


@dataclass
class ToolPolicyDecision:
    """Decision returned by policy checks."""

    action: str
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


@dataclass
class ToolAuditEvent:
    """Small, credential-safe audit event for a tool/resource decision."""

    timestamp: float
    kind: str
    name: str
    action: str
    reason: str
    actor: str = ""
    args_summary: Dict[str, Any] = field(default_factory=dict)
    result_summary: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "timestamp": self.timestamp,
            "kind": self.kind,
            "name": self.name,
            "action": self.action,
            "reason": self.reason,
            "actor": self.actor,
            "args_summary": self.args_summary,
        }
        if self.result_summary:
            data["result_summary"] = self.result_summary
        if self.duration_ms is not None:
            data["duration_ms"] = self.duration_ms
        return data


class ToolPolicy:
    """Allow/ask/deny policy plus optional strict schema validation.

    A ``None`` allowlist means unrestricted for that primitive kind. A concrete
    empty set means deny-by-default until entries are added.
    """

    SENSITIVE_ARG_PARTS = SENSITIVE_ARG_PARTS

    def __init__(
        self,
        *,
        allowed_tools: Optional[Iterable[str]] = None,
        ask_tools: Optional[Iterable[str]] = None,
        denied_tools: Optional[Iterable[str]] = None,
        allowed_resources: Optional[Iterable[str]] = None,
        ask_resources: Optional[Iterable[str]] = None,
        denied_resources: Optional[Iterable[str]] = None,
        allowed_prompts: Optional[Iterable[str]] = None,
        ask_prompts: Optional[Iterable[str]] = None,
        denied_prompts: Optional[Iterable[str]] = None,
        strict_schema: bool = False,
        pre_hooks: Optional[Sequence[Hook]] = None,
        post_hooks: Optional[Sequence[Hook]] = None,
        audit_log_path: Optional[Union[Path, str]] = None,
    ) -> None:
        self.allowed_tools = self._optional_set(allowed_tools)
        self.ask_tools = set(ask_tools or [])
        self.denied_tools = set(denied_tools or [])
        self.allowed_resources = self._optional_set(allowed_resources)
        self.ask_resources = set(ask_resources or [])
        self.denied_resources = set(denied_resources or [])
        self.allowed_prompts = self._optional_set(allowed_prompts)
        self.ask_prompts = set(ask_prompts or [])
        self.denied_prompts = set(denied_prompts or [])
        self.strict_schema = strict_schema
        self.pre_hooks = list(pre_hooks or [])
        self.post_hooks = list(post_hooks or [])
        self.audit_events: List[ToolAuditEvent] = []
        self.audit_log_path = Path(audit_log_path) if audit_log_path else None
        self._audit_lock = threading.Lock()

    @classmethod
    def allow_all(
        cls,
        *,
        strict_schema: bool = False,
        pre_hooks: Optional[Sequence[Hook]] = None,
        post_hooks: Optional[Sequence[Hook]] = None,
        audit_log_path: Optional[Union[Path, str]] = None,
    ) -> "ToolPolicy":
        return cls(
            strict_schema=strict_schema,
            pre_hooks=pre_hooks,
            post_hooks=post_hooks,
            audit_log_path=audit_log_path,
        )

    @staticmethod
    def _optional_set(values: Optional[Iterable[str]]) -> Optional[Set[str]]:
        if values is None:
            return None
        return {str(value) for value in values}

    def filter_tool_schemas(self, schemas: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return schemas visible to the model under the current policy."""
        filtered: List[Dict[str, Any]] = []
        for schema in schemas:
            name = self.schema_name(schema)
            if not name:
                continue
            decision = self._decision(
                name,
                allowed=self.allowed_tools,
                ask=self.ask_tools,
                denied=self.denied_tools,
            )
            if decision.action in {"allow", "ask"}:
                filtered.append(schema)
        return filtered

    def is_tool_visible(self, name: str) -> bool:
        """Return whether a tool should be exposed without recording an audit event."""
        return self._decision(
            name,
            allowed=self.allowed_tools,
            ask=self.ask_tools,
            denied=self.denied_tools,
        ).action in {"allow", "ask"}

    def filter_resources(self, resources: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            resource
            for resource in resources
            if self._decision(
                str(resource.get("uri") or ""),
                allowed=self.allowed_resources,
                ask=self.ask_resources,
                denied=self.denied_resources,
            ).action
            in {"allow", "ask"}
        ]

    def filter_prompts(self, prompts: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            prompt
            for prompt in prompts
            if self._decision(
                str(prompt.get("name") or ""),
                allowed=self.allowed_prompts,
                ask=self.ask_prompts,
                denied=self.denied_prompts,
            ).action
            in {"allow", "ask"}
        ]

    def enforce_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        schema: Optional[Dict[str, Any]] = None,
        actor: str = "",
    ) -> Optional[Dict[str, Any]]:
        return self._enforce(
            "tool",
            name,
            arguments,
            allowed=self.allowed_tools,
            ask=self.ask_tools,
            denied=self.denied_tools,
            schema=schema,
            actor=actor,
        )

    def enforce_resource(self, uri: str, *, actor: str = "") -> Optional[Dict[str, Any]]:
        return self._enforce(
            "resource",
            uri,
            {},
            allowed=self.allowed_resources,
            ask=self.ask_resources,
            denied=self.denied_resources,
            actor=actor,
        )

    def enforce_prompt(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        actor: str = "",
    ) -> Optional[Dict[str, Any]]:
        return self._enforce(
            "prompt",
            name,
            arguments,
            allowed=self.allowed_prompts,
            ask=self.ask_prompts,
            denied=self.denied_prompts,
            actor=actor,
        )

    def _enforce(
        self,
        kind: str,
        name: str,
        arguments: Dict[str, Any],
        *,
        allowed: Optional[Set[str]],
        ask: Set[str],
        denied: Set[str],
        schema: Optional[Dict[str, Any]] = None,
        actor: str = "",
    ) -> Optional[Dict[str, Any]]:
        decision = self._decision(name, allowed=allowed, ask=ask, denied=denied)
        hook_payload = {
            "kind": kind,
            "name": name,
            "arguments": arguments,
            "actor": actor,
            "decision": decision.action,
        }
        for hook in self.pre_hooks:
            hook_result = hook(dict(hook_payload))
            if hook_result:
                reason = str(hook_result.get("error") or hook_result.get("reason") or "blocked by pre-hook")
                self._audit(kind, name, "deny", reason, arguments, actor)
                return self._error(kind, name, "deny", reason)

        if decision.action == "deny":
            self._audit(kind, name, "deny", decision.reason, arguments, actor)
            return self._error(kind, name, "deny", decision.reason)
        if decision.action == "ask":
            reason = decision.reason or "approval required"
            self._audit(kind, name, "ask", reason, arguments, actor)
            return self._error(kind, name, "ask", reason)

        if kind == "tool" and self.strict_schema:
            schema_error = self.validate_arguments(schema, arguments)
            if schema_error:
                self._audit(kind, name, "schema_error", schema_error, arguments, actor)
                return self._error(kind, name, "schema_error", schema_error)

        self._audit(kind, name, "allow", decision.reason, arguments, actor)
        return None

    def run_post_hooks(
        self,
        kind: str,
        name: str,
        arguments: Dict[str, Any],
        *,
        result: Optional[Dict[str, Any]] = None,
        actor: str = "",
        duration_ms: Optional[float] = None,
    ) -> None:
        """Run PostToolUse-style hooks after the primitive has executed."""
        payload = {
            "kind": kind,
            "name": name,
            "arguments": arguments,
            "actor": actor,
            "result": result or {},
            "duration_ms": duration_ms,
        }
        for hook in self.post_hooks:
            hook(dict(payload))
        self._audit(
            kind,
            name,
            "post",
            "post hooks completed",
            arguments,
            actor,
            result=result,
            duration_ms=duration_ms,
        )

    def _decision(
        self,
        name: str,
        *,
        allowed: Optional[Set[str]],
        ask: Set[str],
        denied: Set[str],
    ) -> ToolPolicyDecision:
        if self._matches(denied, name):
            return ToolPolicyDecision("deny", f"{name!r} matches deny policy")
        if self._matches(ask, name):
            return ToolPolicyDecision("ask", f"{name!r} requires approval")
        if allowed is not None and not self._matches(allowed, name):
            return ToolPolicyDecision("deny", f"{name!r} is not in allowlist")
        return ToolPolicyDecision("allow", "allowed by policy")

    @classmethod
    def validate_arguments(
        cls,
        schema: Optional[Dict[str, Any]],
        arguments: Dict[str, Any],
    ) -> Optional[str]:
        return validate_function_arguments(schema, arguments, reject_unknown=True)

    @staticmethod
    def schema_name(schema: Dict[str, Any]) -> str:
        return str(schema.get("function", {}).get("name") or schema.get("name") or "")

    @staticmethod
    def _matches(patterns: Iterable[str], name: str) -> bool:
        return any(pattern == name or fnmatch.fnmatchcase(name, pattern) for pattern in patterns)

    def _audit(
        self,
        kind: str,
        name: str,
        action: str,
        reason: str,
        arguments: Dict[str, Any],
        actor: str,
        *,
        result: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        event = ToolAuditEvent(
            timestamp=time.time(),
            kind=kind,
            name=name,
            action=action,
            reason=reason,
            actor=actor,
            args_summary=self._summarize_args(arguments),
            result_summary=self._summarize_result(result or {}),
            duration_ms=duration_ms,
        )
        with self._audit_lock:
            self.audit_events.append(event)
            if self.audit_log_path:
                self._write_audit_event(event)

    def _write_audit_event(self, event: ToolAuditEvent) -> None:
        assert self.audit_log_path is not None
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True) + "\n")

    @classmethod
    def _summarize_args(cls, arguments: Dict[str, Any]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}
        for key, value in arguments.items():
            if cls._is_sensitive_key(key):
                summary[key] = "[redacted]"
            elif isinstance(value, str):
                summary[key] = cls._summarize_string(value)
            elif isinstance(value, (int, float, bool)) or value is None:
                summary[key] = value
            elif isinstance(value, list):
                summary[key] = f"list[{len(value)}]"
            elif isinstance(value, dict):
                summary[key] = f"object[{len(value)}]"
            else:
                summary[key] = type(value).__name__
        return summary

    @classmethod
    def _summarize_result(cls, result: Dict[str, Any]) -> Dict[str, Any]:
        if not result:
            return {}
        summary: Dict[str, Any] = {}
        for key in ("success", "error", "policy_decision", "policy_kind"):
            if key in result:
                value = result[key]
                summary[key] = cls._summarize_string(value) if isinstance(value, str) else value
        data = result.get("data")
        if isinstance(data, dict):
            for key, value in data.items():
                if cls._is_sensitive_key(key):
                    summary[f"data.{key}"] = "[redacted]"
                elif isinstance(value, list):
                    summary[f"data.{key}"] = f"list[{len(value)}]"
                elif isinstance(value, dict):
                    summary[f"data.{key}"] = f"object[{len(value)}]"
                elif isinstance(value, str):
                    summary[f"data.{key}"] = cls._summarize_string(value)
                elif isinstance(value, (int, float, bool)) or value is None:
                    summary[f"data.{key}"] = value
        return summary

    @classmethod
    def _is_sensitive_key(cls, key: Any) -> bool:
        lowered = str(key).lower()
        return any(part in lowered for part in cls.SENSITIVE_ARG_PARTS)

    @classmethod
    def _summarize_string(cls, value: str) -> str:
        redacted = value
        for pattern, replacement in SENSITIVE_TEXT_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted if len(redacted) <= 160 else redacted[:157] + "..."

    @staticmethod
    def _error(kind: str, name: str, decision: str, reason: str) -> Dict[str, Any]:
        return {
            "success": False,
            "error": f"{kind} use blocked by policy for {name!r}: {reason}",
            "policy_decision": decision,
            "policy_subject": name,
            "policy_kind": kind,
        }
