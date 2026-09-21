"""Token-first evidence projection; complete source stays outside the prompt."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from typing import Any

from ...framework.llm_client import LLMClient


def record_projection(result: dict[str, Any], section: str, original: Any, kept: Any) -> None:
    """Make upstream field/list compaction visible to the budget and validator."""
    if original == kept:
        return
    encoded = json.dumps(original, ensure_ascii=False, sort_keys=True, default=str)
    actual = json.dumps(kept, ensure_ascii=False, sort_keys=True, default=str)
    result["slice_truncated"] = True
    result["context_requires_retrieval"] = True
    sections = result.setdefault("slice_truncated_sections", [])
    if section not in sections:
        sections.append(section)
    result.setdefault("upstream_omissions", {})[section] = {
        "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "original_estimated_tokens": LLMClient.estimate_tokens(
            [{"role": "user", "content": encoded}]
        ),
        "actual_estimated_tokens": LLMClient.estimate_tokens([{"role": "user", "content": actual}]),
        "retrieval": "validation evidence pack or query_validation_facts",
    }


def fit_evidence(source: dict[str, Any], *, max_tokens: int) -> dict[str, Any]:
    result = deepcopy(source)

    def estimate() -> int:
        payload = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return LLMClient.estimate_tokens([{"role": "user", "content": payload}])

    original = estimate() + sum(
        max(0, row["original_estimated_tokens"] - row["actual_estimated_tokens"])
        for row in result.get("upstream_omissions", {}).values()
    )
    result["slice_original_estimated_tokens"] = max(
        original, int(result.get("slice_original_estimated_tokens") or 0)
    )
    result.setdefault("slice_truncated", False)
    result.setdefault("slice_truncated_sections", [])
    result["slice_estimated_tokens"] = original
    # Include metadata itself in the budget. Keep a small framing allowance.
    target = max_tokens - 32
    if estimate() <= target:
        result["slice_estimated_tokens"] = estimate()
        return result

    code = result.setdefault("code", {})
    # Auxiliary summaries must not evict a short, complete function.
    for owner, key in (
        (code, "snapshot_summary"),
        (result, "project_knowledge"),
        (result, "semantic_claims"),
    ):
        if estimate() <= target:
            break
        if owner.get(key):
            before = owner[key]
            owner[key] = [] if isinstance(before, list) else {}
            record_projection(result, key, before, owner[key])
    if estimate() <= target:
        result["slice_estimated_tokens"] = estimate()
        return result
    text = str(code.get("function_context") or "")
    lines = text.splitlines()
    refs = result.get("evidence", {})
    obligation = result.get("obligation", {})
    anchors = " ".join(str(refs.get(k) or "") for k in ("source", "sink"))
    identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", anchors))
    # Guards, ownership changes and state transitions matter even when far
    # from a reported sink. Their surrounding lines preserve local context.
    important = re.compile(
        r"\b(if|else|switch|case|while|for|return|throw|catch|delete|new|"
        r"free|realloc|fclose|closedir|close|unlock|assert)\b|\b\w*(?:lock)\s*\("
    )
    scores: dict[int, int] = {}
    for i, line in enumerate(lines):
        score = 1
        if i in (0, len(lines) - 1):
            score = 5
        if important.search(line):
            score = 8
        if identifiers.intersection(re.findall(r"\b[A-Za-z_]\w*\b", line)):
            score = 12
        for j in range(max(0, i - 2), min(len(lines), i + 3)):
            scores[j] = max(scores.get(j, 0), score - abs(i - j))
    selected = set(range(len(lines)))

    def render() -> None:
        chunks: list[str] = []
        omitted: list[list[int]] = []
        i = 0
        while i < len(lines):
            if i in selected:
                chunks.append(lines[i])
                i += 1
                continue
            start = i
            while i < len(lines) and i not in selected:
                i += 1
            omitted.append([start + 1, i])
            chunks.append(f"/* omitted function-relative lines {start + 1}-{i}; retrieve source */")
        code["function_context"] = "\n".join(chunks)
        code["omitted_line_intervals"] = omitted

    result["slice_truncated"] = True
    sections = result["slice_truncated_sections"]
    code["source_reference"] = {
        "function": obligation.get("function"),
        "location": obligation.get("location"),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "line_coordinates": "function-relative, one-based",
        "retrieval": "get_function_impl or query_validation_facts",
    }
    # Drop less relevant whole neighborhoods first, never a prefix-only cut.
    order = sorted(selected, key=lambda i: (scores.get(i, 0), i))
    while order and estimate() > target:
        count = max(1, len(order) // 4)
        for i in order[:count]:
            selected.discard(i)
        del order[:count]
        render()
    if len(selected) < len(lines):
        sections.append("code.function_context")
        decision = result.setdefault("decision_facts", {})
        missing = decision.setdefault("missing_fact_kinds", [])
        if "omitted_source_context" not in missing:
            missing.append("omitted_source_context")
        result["context_requires_retrieval"] = True

    # Large optional sections can crowd out even a small function. Preserve
    # their identity commitments elsewhere; never silently cut proof/contract.
    for owner, key in (
        (code, "callers"),
        (code, "callees"),
        (code, "snapshot_summary"),
        (result, "semantic_claims"),
        (result, "project_knowledge"),
    ):
        if estimate() <= target:
            break
        if owner.get(key):
            owner[key] = [] if isinstance(owner[key], list) else {}
            sections.append(key)
            result["context_requires_retrieval"] = True
    result["slice_truncated_sections"] = sorted(set(sections))
    result["slice_estimated_tokens"] = estimate()
    if estimate() > max_tokens:
        raise ValueError("Validator evidence commitments exceed the input token allowance")
    return result
