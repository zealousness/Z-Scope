"""Semantic compiler input identity, separate from source-bound proof receipts."""

from __future__ import annotations

import re
from typing import Any

from .contracts import code_tokens

_POSITION = re.compile(r"^(c:[^@]+)@(\d+)@")
_COORDINATES = {"location", "end", "owner", "declaration", "line", "column", "offset"}


def compiler_structure(value: Any) -> Any:
    """Remove coordinates while preserving distinct local declaration identities.

    Clang embeds byte offsets in local USRs. Rank those declaration offsets
    within each source file; retain the file, scope and symbol suffix, as well
    as all object equality relationships. Only the cache fingerprint changes:
    consumers and proof validation still receive the original compiler facts.
    Expanded expressions, CFG edges and target ABI remain part of the input.
    """
    positions: dict[str, set[int]] = {}

    def collect(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if key in _COORDINATES:
                    continue
                if key in {"usr", "referenced_usr"} and isinstance(child, str):
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
            if field in {"usr", "referenced_usr"} and (match := _POSITION.match(item)):
                rank = ranks[(match[1], int(match[2]))]
                item = f"{match[1]}@decl{rank}@{item[match.end():]}"
            return code_tokens(item)
        return item

    return normalize(value)
