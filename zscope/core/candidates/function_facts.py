"""Immutable per-instance facts shared by the C/C++ fast analyzers."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping

FUNCTION_FACT_SUMMARY_VERSION = "zscope.function-fact-summary.v1"


def function_source_fragment(
    body: Mapping[str, Any], *, source_cache: dict[Path, str]
) -> tuple[str, int, int]:
    """Read one exact function body from its native definition location.

    Native program facts establish the function identity and CFG.  This
    bounded parser supplies only the readable source used by deterministic
    rules and evidence rendering; it never authorizes semantic identity.
    """

    owner = body.get("owner")
    owner = owner if isinstance(owner, Mapping) else {}
    raw_file = str(owner.get("file") or "")
    start_line = int(owner.get("line") or 0)
    if not raw_file or start_line <= 0:
        return "", start_line, start_line
    path = Path(raw_file)
    try:
        text = source_cache.setdefault(path, path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return "", start_line, start_line
    callable_row = body.get("callable")
    callable_row = callable_row if isinstance(callable_row, Mapping) else {}
    location = callable_row.get("location")
    location = location if isinstance(location, Mapping) else {}
    try:
        name_offset = int(location.get("offset") or 0)
    except (TypeError, ValueError):
        name_offset = 0
    line_offset = 0
    if start_line > 1:
        cursor = 0
        for _ in range(start_line - 1):
            cursor = text.find("\n", cursor) + 1
            if cursor <= 0:
                break
        line_offset = max(0, cursor)
    search_from = max(line_offset, name_offset)
    opening = text.find("{", search_from)
    if opening < 0:
        end = text.find("\n", search_from)
        end = len(text) if end < 0 else end
        return text[line_offset:end], start_line, start_line

    depth = 0
    index = opening
    state = "code"
    escaped = False
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state in {"string", "char"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif char == "/" and next_char == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and next_char == "*":
            state = "block_comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                return (
                    text[line_offset:end],
                    start_line,
                    start_line + text.count("\n", line_offset, end),
                )
        index += 1
    return text[line_offset : min(len(text), opening + 6000)], start_line, start_line


def numbered_source_fragment(source: str, *, start_line: int) -> str:
    """Render an exact native source fragment with absolute source lines.

    The C/C++ local rule engines consume the same ``line | source`` contract
    as ``CodeIndex.get_function_impl``. Native program facts expose a raw
    source fragment, so passing that fragment through unchanged silently
    reset every candidate and CFG event to line one. Keep the raw bytes for
    the immutable fact digest and use this projection only at rule/Validator
    boundaries.
    """

    text = str(source or "")
    if not text:
        return ""
    first = max(1, int(start_line or 1))
    return "\n".join(
        f"{line_number} | {line}" for line_number, line in enumerate(text.splitlines(), start=first)
    )


@dataclass(frozen=True)
class FunctionFactSummary:
    """One native/local fact snapshot for an exact BuildContext + USR.

    Consumers receive copies of ``program_facts`` so rule engines cannot
    mutate the shared snapshot.  The digest is also the cache dependency used
    by fast function and link-group units.
    """

    analysis_unit_id: str
    build_context_id: str
    usr: str
    function: str
    file_path: str
    source_digest: str
    fact_digest: str
    program_facts: Mapping[str, Any]
    schema_version: str = FUNCTION_FACT_SUMMARY_VERSION

    @classmethod
    def create(
        cls,
        *,
        analysis_unit_id: str,
        build_context_id: str,
        usr: str,
        function: str,
        file_path: str,
        source: str,
        program_facts: Mapping[str, Any] | None,
    ) -> "FunctionFactSummary":
        facts = deepcopy(dict(program_facts or {}))
        stable = json.dumps(facts, ensure_ascii=False, sort_keys=True, default=str)
        return cls(
            analysis_unit_id=analysis_unit_id,
            build_context_id=build_context_id,
            usr=usr,
            function=function,
            file_path=file_path,
            source_digest=hashlib.sha256(source.encode("utf-8")).hexdigest(),
            fact_digest=hashlib.sha256(stable.encode("utf-8")).hexdigest(),
            program_facts=MappingProxyType(facts),
        )

    def facts_copy(self) -> Dict[str, Any]:
        return deepcopy(dict(self.program_facts))

    def manifest(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "analysis_unit_id": self.analysis_unit_id,
            "build_context_id": self.build_context_id,
            "usr": self.usr,
            "function": self.function,
            "file": self.file_path,
            "source_digest": self.source_digest,
            "fact_digest": self.fact_digest,
        }
