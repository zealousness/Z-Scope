"""Validate provider framing before exposing any tool call to an executor."""

from typing import Any
import json

import requests


class ProviderContextError(RuntimeError):
    """Sanitized provider context rejection, eligible for one narrower projection."""


class ChatProtocolError(requests.exceptions.ChunkedEncodingError):
    """A protocol violation, not an availability failure eligible for endless retries."""


class ChatChunkDecoder:
    """Decode SSE data fields without silently dropping damaged protocol frames."""

    def __init__(self) -> None:
        self.pending: list[str] = []
        self.done = False

    def feed(self, line: str) -> dict[str, Any] | None:
        line = line.strip()
        if not line:
            self.finish()
            return None
        if line.startswith((":", "event:", "id:", "retry:")):
            return None
        if line.startswith("data:"):
            line = line[5:].lstrip()
        elif not line.startswith("{") and not self.pending:
            return None
        if line == "[DONE]":
            self.finish()
            self.done = True
            return None
        self.pending.append(line)
        try:
            chunk = json.loads("\n".join(self.pending))
        except ValueError:
            return None  # Multi-line data is allowed; the event boundary is strict.
        self.pending.clear()
        if not isinstance(chunk, dict):
            raise ChatProtocolError("Invalid chat stream frame")
        if "error" in chunk:
            raise ChatProtocolError("Provider stream returned an error")
        return chunk

    def finish(self) -> None:
        if self.pending:
            raise ChatProtocolError("Malformed or truncated chat stream frame")


def validate_assistant_message(message: Any, finish_reason: Any) -> None:
    if not isinstance(message, dict) or not isinstance(finish_reason, str) or not finish_reason:
        raise ChatProtocolError("Incomplete chat completion envelope")
    calls = message.get("tool_calls")
    # A length-truncated turn is returned to its owner for bounded repair. It
    # must never reach tool execution, including when the arguments happen to parse.
    if calls is None or finish_reason == "length":
        return
    if finish_reason not in {"stop", "tool_calls"}:
        raise ChatProtocolError("Unfinished tool call turn")
    if not isinstance(calls, list):
        raise ChatProtocolError("Invalid tool call list")
    ids: set[str] = set()
    for call in calls:
        if not isinstance(call, dict):
            raise ChatProtocolError("Invalid tool call envelope")
        identifier = call.get("id")
        function = call.get("function")
        if (
            not isinstance(identifier, str)
            or not identifier.strip()
            or identifier in ids
            or call.get("type") != "function"
            or not isinstance(function, dict)
            or not isinstance(function.get("name"), str)
            or not function["name"].strip()
            or not isinstance(function.get("arguments"), str)
        ):
            raise ChatProtocolError("Invalid or duplicate tool call identity")
        ids.add(identifier)
