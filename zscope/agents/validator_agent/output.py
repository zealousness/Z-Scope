"""Read one complete public decision from the current assistant turn."""

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from ...common.validator_protocol import (
    decode_validator_json,
    normalize_validator_provider_payload_v3,
)


def is_incomplete(result: dict[str, Any]) -> bool:
    # Generic conversations report valid=False/name=None when no terminal was required.
    rejected = result.get("terminal_tool_valid") is False and result.get(
        "terminal_tool_name", "required"
    )
    return bool(rejected or result.get("truncated")) or result.get("finish_reason") in {
        "length",
        "context_window_exceeded",
        "content_filter",
        "error",
    }


def current_message(result: dict[str, Any]) -> dict[str, Any]:
    message = result.get("message")
    if isinstance(message, dict):
        return message if message.get("role", "assistant") == "assistant" else {}
    conversation = result.get("conversation")
    if conversation:
        last = conversation[-1]
        return last if isinstance(last, dict) and last.get("role") == "assistant" else {}
    return {"content": result.get("content", "")}


def _decode_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str):
        try:
            value = decode_validator_json(value)
        except (ValueError, RecursionError):
            return None
    return value if isinstance(value, dict) else None


def terminal_payload(result: dict[str, Any], tool_name: str) -> dict[str, Any] | None:
    """Reject mixed/duplicate tool calls, ambiguous text, and unfinished responses."""
    if is_incomplete(result):
        return None
    message = current_message(result)
    calls = message.get("tool_calls")
    if calls:
        if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], dict):
            return None
        if calls[0].get("type", "function") != "function":
            return None
        function = calls[0].get("function")
        if not isinstance(function, dict) or function.get("name") != tool_name:
            return None
        return _decode_object(function.get("arguments"))
    text = message.get("content")
    if not isinstance(text, str):
        return None
    text = text.strip()
    if text.startswith("```"):
        header, separator, body = text.partition("\n")
        if (
            header.strip().lower() not in {"```", "```json"}
            or not separator
            or not body.endswith("```")
        ):
            return None
        text = body[:-3]
    # Parse the entire object. Arrays, quoted JSON, and incomplete outer structures
    # cannot turn an embedded fragment into a decision; fenced objects remain supported.
    return _decode_object(text)


@dataclass(frozen=True)
class DecisionOutput:
    """Decode once; admission and audit observe the same public response."""

    raw: dict[str, Any] | None
    normalized: dict[str, Any] | None

    @classmethod
    def from_payload(cls, payload: Any) -> "DecisionOutput":
        raw = payload if isinstance(payload, dict) else None
        return cls(raw, normalize_validator_provider_payload_v3(raw))

    @classmethod
    def from_result(cls, result: dict[str, Any]) -> "DecisionOutput":
        return cls.from_payload(terminal_payload(result, "emit_validator_result_v3"))

    @property
    def payload(self) -> dict[str, Any] | None:
        return self.normalized if self.normalized is not None else self.raw

    def audit(self, parsed: bool, finish_reason: str = "") -> dict[str, Any]:
        audited = self.payload or {}
        if isinstance(audited.get("decision"), dict):
            audited = audited["decision"]
        request = audited.get("missing_fact_request")

        def sample(value: Any) -> str:
            return value[:512] if isinstance(value, str) else ""

        return {
            "parse_status": "parsed" if parsed else "malformed",
            "raw_verdict": sample(audited.get("verdict")),
            "raw_stop_reason": sample(audited.get("stop_reason")),
            "raw_missing_fact_kind": (
                sample(request.get("fact_kind")) if isinstance(request, dict) else ""
            ),
            "parsed": parsed,
            "protocol_error": "" if parsed else "validator_result_v3_schema_or_scope_mismatch",
            "finish_reason": sample(finish_reason),
            "raw_response": self._bounded(self.raw or {}),
            "provider_payload_normalized": self.normalized is not None,
            "normalized_response": self._bounded(self.normalized or {}),
        }

    @staticmethod
    def _bounded(payload: dict[str, Any]) -> dict[str, Any]:
        # Full conversations belong to the recorder; reports keep bounded diagnostics.
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8", errors="replace")
        if len(encoded) <= 65536:
            return payload
        return {
            "omitted": True,
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
