"""Deterministic Markdown-to-LLM compiler chunk planning."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Sequence, Tuple

from ..identity import stable_id
from .workset import _allowed_subject_ids


DEFAULT_CONTEXT_TOKENS = 32_768
MIN_TARGET_TOKENS = 256


@dataclass(frozen=True)
class CompilerChunk:
    chunk_id: str
    source_id: str
    ordinal: int
    total: int
    primary_ref_ids: Tuple[str, ...]
    start_line: int
    end_line: int
    estimated_tokens: int
    char_count: int
    split_depth: int = 0


class CompilerChunkError(ValueError):
    pass


class CompilerChunkBudgetExceeded(CompilerChunkError):
    pass


class CompilerContextOverflow(CompilerChunkError):
    pass


class CompilerChunkInvalid(CompilerChunkError):
    pass


class CompilerChunkTimeout(CompilerChunkError):
    pass


def _tokens(value: str) -> int:
    return max(1, int(math.ceil(len(str(value)) / 4.0)))


def _ref_id(section: Mapping[str, Any]) -> str:
    return stable_id("docref", str(section.get("source_id", "")), str(section.get("section_id", "")))


def _budget(
    *, context_tokens: int | None, completion_tokens: int | None, system_prompt: str, tool_schema: Mapping[str, Any] | None
) -> Tuple[int, int]:
    context = int(context_tokens or DEFAULT_CONTEXT_TOKENS)
    completion = max(256, int(completion_tokens or 0))
    framing = _tokens(system_prompt) + _tokens(json.dumps(tool_schema or {}, ensure_ascii=False, sort_keys=True)) + 512
    safety = int(math.ceil(context * 0.15))
    available = max(MIN_TARGET_TOKENS, context - completion - framing - safety)
    return max(MIN_TARGET_TOKENS, int(available * 0.70)), max(MIN_TARGET_TOKENS, int(available * 0.85))


def plan_compiler_chunks(
    workset: Mapping[str, Any],
    *,
    context_tokens: int | None = None,
    completion_tokens: int | None = None,
    system_prompt: str = "",
    tool_schema: Mapping[str, Any] | None = None,
) -> Tuple[CompilerChunk, ...]:
    """Plan contiguous, non-overlapping chunks over one document's sections."""
    sections = [item for item in workset.get("source_sections", ()) if isinstance(item, Mapping)]
    if not sections:
        return ()
    source_ids = {str(item.get("source_id", "")) for item in sections}
    if len(source_ids) != 1:
        raise ValueError("compiler chunk planning requires exactly one source")
    target, hard = _budget(
        context_tokens=context_tokens,
        completion_tokens=completion_tokens,
        system_prompt=system_prompt,
        tool_schema=tool_schema,
    )
    planned = []
    current = []
    used = 0
    for section in sections:
        cost = _tokens(str(section.get("excerpt", "")))
        if cost > hard:
            raise CompilerChunkBudgetExceeded(
                f"source section exceeds compiler hard input budget: {section.get('section_id', '')}"
            )
        if current and used + cost > target:
            planned.append(current)
            current, used = [], 0
        current.append(section)
        used += cost
    if current:
        planned.append(current)
    total = len(planned)
    result = []
    for ordinal, items in enumerate(planned):
        refs = tuple(_ref_id(item) for item in items)
        source_id = str(items[0].get("source_id", ""))
        start = min(int(item.get("start_line", 1)) for item in items)
        end = max(int(item.get("end_line", start)) for item in items)
        chars = sum(len(str(item.get("excerpt", ""))) for item in items)
        estimated = sum(_tokens(str(item.get("excerpt", ""))) for item in items)
        result.append(
            CompilerChunk(
                chunk_id=stable_id("docchunk", str(workset.get("workset_id", "")), source_id, str(ordinal), *refs),
                source_id=source_id,
                ordinal=ordinal,
                total=total,
                primary_ref_ids=refs,
                start_line=start,
                end_line=end,
                estimated_tokens=estimated,
                char_count=chars,
                split_depth=0,
            )
        )
    covered = [ref for chunk in result for ref in chunk.primary_ref_ids]
    if len(covered) != len(set(covered)):
        raise ValueError("compiler chunks overlap primary source refs")
    return tuple(result)


def build_chunk_workset(workset: Mapping[str, Any], chunk: CompilerChunk) -> Dict[str, Any]:
    """Narrow a document Workset to the refs and sections in one chunk."""
    refs = set(chunk.primary_ref_ids)
    child = dict(workset)
    child["workset_id"] = stable_id("workset", str(workset.get("workset_id", "")), chunk.chunk_id)
    child["source_sections"] = [
        item for item in workset.get("source_sections", ())
        if isinstance(item, Mapping) and _ref_id(item) in refs
    ]
    child["source_ref_catalog"] = [
        item for item in workset.get("source_ref_catalog", ())
        if isinstance(item, Mapping) and str(item.get("ref_id", "")) in refs
    ]
    child["allowed_source_refs"] = sorted(refs)
    child["allowed_subject_ids"] = list(
        _allowed_subject_ids(str(workset.get("project_id", "")), child["source_sections"])
    )
    return child


__all__ = [
    "CompilerChunk",
    "CompilerChunkError",
    "CompilerChunkBudgetExceeded",
    "CompilerContextOverflow",
    "CompilerChunkInvalid",
    "CompilerChunkTimeout",
    "plan_compiler_chunks",
    "build_chunk_workset",
    "DEFAULT_CONTEXT_TOKENS",
]
