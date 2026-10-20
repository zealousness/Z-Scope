"""Semantic compiler input identity, separate from source-bound proof receipts."""

from __future__ import annotations

import re
from typing import Any

from .contracts import code_tokens

_POSITION = re.compile(r"^(c:[^@]+)@(\d+)@")
_COORDINATES = {"location", "end", "owner", "declaration", "line", "column", "offset"}
_USR_FIELDS = {"usr", "referenced_usr", "pointee_record_usr"}


def compiler_structure(value: Any) -> Any:
    """Remove coordinates while preserving distinct local declaration identities.

    Clang embeds byte offsets in local USRs. Rank those declaration offsets
    within each source file; retain the file, scope and symbol suffix, as well
    as all object equality relationships. Only the cache fingerprint changes:
    consumers and proof validation still receive the original compiler facts.
    Expanded expressions, CFG edges and target ABI remain part of the input.
    """
    # Build receipts bind exact bytes for evidence. LLM semantic reuse instead
    # binds the invocation/tool/ABI and normalized facts: a comment-only edit
    # must invalidate old proof receipts without forcing another model call.
    if isinstance(value, dict) and isinstance(value.get("build_context"), dict):
        value = {
            **{key: child for key, child in value.items() if key != "build_context_id"},
            "build_context": {
                key: child
                for key, child in value["build_context"].items()
                if key
                not in {
                    "dependencies",
                    "build_context_id",
                    "failure",
                    "compilation_database",
                    "search_directories",
                    "search_excludes",
                }
            },
        }
        if isinstance(value.get("function_identity"), dict):
            # The scoped function key is an evidence receipt. Preserve the USR
            # as semantic identity without making comment-only byte changes
            # invalidate an otherwise equivalent model input.
            value["function_identity"] = {
                key: child
                for key, child in value["function_identity"].items()
                if key not in {"key", "build_context_id"}
            }
    positions: dict[str, set[int]] = {}

    def collect(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key in _COORDINATES:
                    continue
                if key in _USR_FIELDS and isinstance(child, str):
                    if match := _POSITION.match(child):
                        positions.setdefault(match[1], set()).add(int(match[2]))
                else:
                    collect(child)
        elif isinstance(item, list):
            for child in item:
                collect(child)

    collect(value)
    ranks = {
        (file, offset): ordinal
        for file, offsets in positions.items()
        for ordinal, offset in enumerate(sorted(offsets))
    }

    def normalize(item: Any, field: str = "") -> Any:
        if isinstance(item, dict):
            return {
                key: normalize(child, key) for key, child in item.items() if key not in _COORDINATES
            }
        if isinstance(item, list):
            return [normalize(child) for child in item]
        if isinstance(item, str):
            if field in _USR_FIELDS and (match := _POSITION.match(item)):
                rank = ranks[(match[1], int(match[2]))]
                item = f"{match[1]}@decl{rank}@{item[match.end():]}"
            return code_tokens(item)
        return item

    return normalize(value)
