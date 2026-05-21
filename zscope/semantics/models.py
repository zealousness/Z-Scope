"""Shared semantic models for candidate generators and defaults."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class LocalPatternSemantics:
    """Project-specific C aliases and API roles used by local-pattern rules."""

    type_aliases: Dict[str, str] = field(default_factory=dict)
    allocators: Dict[str, List[str]] = field(default_factory=dict)
    calloc_allocators: Dict[str, List[str]] = field(default_factory=dict)
    reallocators: Dict[str, List[str]] = field(default_factory=dict)
    deallocators: Dict[str, List[str]] = field(default_factory=dict)
    copy_sinks: Dict[str, List[str]] = field(default_factory=dict)
    lock_apis: Dict[str, List[str]] = field(default_factory=dict)
    unlock_apis: Dict[str, List[str]] = field(default_factory=dict)

    def add_api(self, category: str, name: str, source: str) -> None:
        target = {
            "allocator": self.allocators,
            "calloc": self.calloc_allocators,
            "reallocator": self.reallocators,
            "deallocator": self.deallocators,
            "copy": self.copy_sinks,
            "lock": self.lock_apis,
            "unlock": self.unlock_apis,
        }.get(category)
        if target is None:
            return
        clean = str(name or "").strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", clean):
            return
        sources = target.setdefault(clean, [])
        if source and source not in sources:
            sources.append(source)

    def merge(self, other: "LocalPatternSemantics") -> None:
        self.type_aliases.update(other.type_aliases)
        for attr in (
            "allocators",
            "calloc_allocators",
            "reallocators",
            "deallocators",
            "copy_sinks",
            "lock_apis",
            "unlock_apis",
        ):
            for name, sources in getattr(other, attr).items():
                for source in sources:
                    self.add_api(CATEGORY_BY_ATTR[attr], name, source)


CATEGORY_BY_ATTR = {
    "allocators": "allocator",
    "calloc_allocators": "calloc",
    "reallocators": "reallocator",
    "deallocators": "deallocator",
    "copy_sinks": "copy",
    "lock_apis": "lock",
    "unlock_apis": "unlock",
}


def classify_api_name(name: str) -> str:
    if name.isupper() and "_" in name:
        return ""
    lower = name.lower()
    tokens = [token for token in re.split(r"_+", lower) if token]
    if tokens:
        last = tokens[-1]
        previous = tokens[-2] if len(tokens) > 1 else ""
        if last == "unlock":
            return "unlock"
        if last == "lock" and previous not in {"under", "with", "while"}:
            return "lock"
        if lower.startswith("unlock") or lower.startswith("lock"):
            return "unlock" if lower.startswith("unlock") else "lock"
    if "realloc" in lower:
        return "reallocator"
    if "calloc" in lower:
        return "calloc"
    if "alloc" in lower or "malloc" in lower:
        return "allocator"
    if re.search(r"(?:^|_)(?:free|dealloc)(?:_|$)", lower) or lower.endswith(("free", "dealloc")):
        return "deallocator"
    if re.search(r"(?:mem)?(?:copy|cpy|move)", lower):
        return "copy"
    return ""


def attr_for_category(category: str) -> str:
    return {
        "allocator": "allocators",
        "calloc": "calloc_allocators",
        "reallocator": "reallocators",
        "deallocator": "deallocators",
        "copy": "copy_sinks",
        "lock": "lock_apis",
        "unlock": "unlock_apis",
    }[category]
