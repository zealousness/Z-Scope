"""Deterministic, lossless-metadata projections for bounded model requests.

The transcript is authoritative. Only explicitly identified bulk text in tool
results may be omitted from its model-facing projection. Unknown fields and all
record/list structure survive, so identities cannot become detached from facts.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from typing import Any, Callable, Mapping


# Configured fallback capacities, not automatic endpoint/model detection.
DEFAULT_CONTEXT_WINDOW = 192_000
DEFAULT_MAX_TOKENS = 8192


class ContextWindowExceeded(ValueError):
    """Required context cannot fit without losing contracts or evidence metadata."""

    def __init__(
        self,
        *,
        window: int,
        prompt_tokens: int,
        output_tokens: int,
        margin: int,
        input_limit: int | None = None,
        provider_rejected: bool = False,
    ):
        super().__init__(
            "context_window_exceeded: required context does not fit "
            f"(window={window}, estimated_prompt={prompt_tokens}, "
            f"output_reserve={output_tokens}, safety_margin={margin}, "
            f"input_limit={input_limit}, provider_rejected={provider_rejected}); "
            "contracts and evidence metadata were retained; narrow the evidence "
            "or configure the endpoint's actual context window"
        )


def validate_context_windows(window: int, overrides: Mapping[str, int]) -> dict[str, int]:
    if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
        raise ValueError("context_window must be a positive integer")
    if not isinstance(overrides, Mapping):
        raise ValueError("model_context_windows must be a mapping")
    for name, value in overrides.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("model_context_windows keys must be non-empty model names")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("model_context_windows values must be positive integers")
    return dict(overrides)


# Only text payloads are eligible. In particular, do not infer that arbitrary
# strings, long IDs, source paths, hashes, or list items can be truncated.
_BULK_TEXT_KEYS = frozenset({"code", "text", "content", "body", "raw", "implementation"})
_PROTECTED_KEYS = frozenset(
    {
        "coverage",
        "status",
        "success",
        "error",
        "warnings",
        "next_actions",
        "page",
        "provenance",
        "identity",
        "dependencies",
        "dependency",
        "build_context",
        "build_contexts",
        "evidence",
        "evidence_refs",
        "evidence_ref_catalog",
        "references",
        "missing",
        "missing_facts",
        "gaps",
        "limitations",
        "unknowns",
    }
)


def _protected(key: str) -> bool:
    return (
        key in _PROTECTED_KEYS
        or key.endswith(
            (
                "_id",
                "_ids",
                "_uid",
                "_uids",
                "_usr",
                "_usrs",
                "_ref",
                "_refs",
                "_hash",
                "_hashes",
                "_fingerprint",
                "_revision",
            )
        )
        or any(part in key for part in ("coverage", "evidence", "provenance", "missing", "gap"))
    )


def _omit_bulk(value: Any, key: str = "") -> tuple[Any, bool]:
    if _protected(key):
        return deepcopy(value), False
    if isinstance(value, str):
        if key in _BULK_TEXT_KEYS and len(value) > 256:
            return {
                "context_omitted": True,
                "original_chars": len(value),
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }, True
        return value, False
    if isinstance(value, dict):
        result = {}
        changed = False
        for child_key, child in value.items():
            result[child_key], omitted = _omit_bulk(child, str(child_key))
            changed |= omitted
        return result, changed
    if isinstance(value, list):
        items = []
        changed = False
        for child in value:
            item, omitted = _omit_bulk(child, key)
            items.append(item)
            changed |= omitted
        return items, changed
    return value, False


def compact_tool_result(content: str, tool_call_id: str) -> str:
    try:
        parsed = json.loads(content)
    except (ValueError, RecursionError):
        # Unstructured text may contain the only identity/gap record. Do not
        # guess how to extract it or authorize its disappearance.
        return content
    if isinstance(parsed, dict) and parsed.get("compacted_tool_result") is True:
        return content
    summary, changed = _omit_bulk(parsed)
    if not changed:
        return content
    result = {
        "compacted_tool_result": True,
        "original_chars": len(content),
        "summary": summary,
        "instruction": (
            "Bulk text marked context_omitted is absent from this projection, not "
            "from the source. Identities, evidence references and coverage metadata "
            "are unchanged. Omitted text is not evidence of absence or safety; "
            "retrieve a narrower source range/page before relying on its contents."
        ),
    }
    if len(tool_call_id) <= 256:
        result["tool_call_id"] = tool_call_id
    else:
        # The enclosing message still retains the complete protocol identity.
        result["tool_call_id_omitted"] = True
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))


def fit_context(
    messages: list[dict[str, Any]],
    *,
    window: int,
    output_tokens: int,
    estimate: Callable[[list[dict[str, Any]]], int],
    input_limit: int | None = None,
) -> list[dict[str, Any]]:
    """Fit oldest tool results first; never delete messages or alter call pairs.

    Even the latest result may need projection for a small window/large batch.
    Estimates guide projection, not rejection: an unknown tokenizer cannot
    prove overflow. Only a provider-rejected retry has an enforced input limit.
    The margin accounts for estimation and provider framing, not a scan budget.
    """
    margin = max(256, (window + 19) // 20)
    available = window - output_tokens - margin
    if available <= 0:
        raise ContextWindowExceeded(
            window=window,
            prompt_tokens=estimate(messages),
            output_tokens=output_tokens,
            margin=margin,
            input_limit=available,
        )
    if input_limit is not None:
        available = min(available, input_limit)
    projected = list(messages)
    tokens = estimate(projected)
    if tokens <= available:
        return projected
    for index, message in enumerate(projected):
        if message.get("role") != "tool" or not isinstance(message.get("content"), str):
            continue
        content = message["content"]
        compacted = compact_tool_result(content, str(message.get("tool_call_id") or ""))
        if len(compacted) >= len(content):
            continue
        projected[index] = {**message, "content": compacted}
        tokens = estimate(projected)
        if tokens <= available:
            return projected
    if input_limit is None:
        # Preserve all required evidence and let the actual provider decide.
        # In particular, exceeding a byte upper bound never proves overflow.
        return projected
    raise ContextWindowExceeded(
        window=window,
        prompt_tokens=tokens,
        output_tokens=output_tokens,
        margin=margin,
        input_limit=available,
        provider_rejected=True,
    )
