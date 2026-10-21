"""Shared semantic models for candidate generators and defaults."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set
from .contracts import ContractRegistry

DEFAULT_SEMANTICS_SOURCE = "builtin_defaults"

MERGE_ATTRS = (
    "allocators",
    "calloc_allocators",
    "reallocators",
    "deallocators",
    "copy_sinks",
    "lock_apis",
    "unlock_apis",
    "io_acquirers",
    "io_releasers",
    "send_sinks",
    "recv_sources",
    "format_sinks",
    "callback_registrars",
    "ownership_transfers",
)


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
    io_acquirers: Dict[str, List[str]] = field(default_factory=dict)
    io_releasers: Dict[str, List[str]] = field(default_factory=dict)
    send_sinks: Dict[str, List[str]] = field(default_factory=dict)
    recv_sources: Dict[str, List[str]] = field(default_factory=dict)
    format_sinks: Dict[str, List[str]] = field(default_factory=dict)
    callback_registrars: Dict[str, List[str]] = field(default_factory=dict)
    ownership_transfers: Dict[str, List[str]] = field(default_factory=dict)
    contracts: ContractRegistry = field(default_factory=ContractRegistry)

    def add_api(self, category: str, name: str, source: str) -> None:
        target = {
            "allocator": self.allocators,
            "calloc": self.calloc_allocators,
            "reallocator": self.reallocators,
            "deallocator": self.deallocators,
            "copy": self.copy_sinks,
            "lock": self.lock_apis,
            "unlock": self.unlock_apis,
            "io_acquire": self.io_acquirers,
            "io_release": self.io_releasers,
            "send_sink": self.send_sinks,
            "recv_source": self.recv_sources,
            "format_sink": self.format_sinks,
            "callback_register": self.callback_registrars,
            "ownership_transfer": self.ownership_transfers,
        }.get(category)
        if target is None:
            return
        clean = str(name or "").strip()
        if source == DEFAULT_SEMANTICS_SOURCE and clean in self.contracts.shadowed_symbols:
            return
        if not re.fullmatch(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*", clean):
            return
        # Publication enumerates declarations from every build. Scoped effect
        # lookup here would hide them outside a scan context and manufacture an
        # unscoped alias, later making the real call ambiguous (or overbroad).
        known = [
            c for c in self.contracts.contracts if c.symbol.name == clean and c.role == category
        ]
        if (
            category
            in {
                "allocator",
                "calloc",
                "reallocator",
                "deallocator",
                "lock",
                "unlock",
                "io_acquire",
                "io_release",
                "ownership_transfer",
            }
            and known
            and not any(c.effects_trusted for c in known)
        ):
            return
        sources = target.setdefault(clean, [])
        if source and source not in sources:
            sources.append(source)
        if not known:
            from .contracts import ApiContract

            contract = ApiContract.from_row(
                {"symbol_name": clean, "kind": category, "source": source}
            )
            if contract is not None:
                self.contracts.add(contract)

    def merge(self, other: "LocalPatternSemantics") -> None:
        self.type_aliases.update(other.type_aliases)
        self.contracts.shadowed_symbols.update(other.contracts.shadowed_symbols)
        self._prune_shadowed_defaults()
        for contract in other.contracts.contracts:
            self.contracts.add(contract)
        for pair in other.contracts.pairs:
            if pair not in self.contracts.pairs:
                self.contracts.pairs.append(pair)
        for attr in MERGE_ATTRS:
            for name, sources in getattr(other, attr).items():
                for source in sources:
                    self.add_api(CATEGORY_BY_ATTR[attr], name, source)

    def _prune_shadowed_defaults(self) -> None:
        """Keep raw role consumers consistent with the contract deny set."""
        for attr in MERGE_ATTRS:
            bucket = getattr(self, attr)
            for name in self.contracts.shadowed_symbols:
                if name in bucket and all(s == DEFAULT_SEMANTICS_SOURCE for s in bucket[name]):
                    bucket.pop(name)

    def names_from_nondefault_sources(self, attr: str) -> Set[str]:
        """Return names under ``attr`` that did not come from the builtin defaults.

        Checkers that must keep their hardcoded builtin API base sets unchanged
        use this to pick up only user-defined wrappers.
        """

        names = getattr(self, attr, {})
        if not isinstance(names, dict):
            return set()
        return {
            str(name)
            for name, sources in names.items()
            if any(str(source) != DEFAULT_SEMANTICS_SOURCE for source in sources or ())
        }

    def merge_overlay(self, overlay: dict) -> None:
        """Consume compiled structured rows; summary names carry no semantics."""
        from .contracts import ApiContract, ApiPair, SymbolIdentity

        self.contracts.shadowed_symbols.update(overlay.get("shadowed_symbols", []))
        self._prune_shadowed_defaults()
        for row in overlay.get("api_contracts", []):
            contract = ApiContract.from_row({"contract": row, "kind": row.get("role")})
            if contract:
                self.contracts.add(contract)
                self.add_api(contract.role, contract.symbol.name, contract.source)
        for row in [
            *overlay.get("resource_models", []),
            *overlay.get("lock_models", []),
            *overlay.get("macro_models", []),
        ]:
            if "api_contracts" in overlay:
                continue
            contract = ApiContract.from_row(row)
            if contract and not self.contracts.find(
                contract.symbol.name,
                contract.role,
                contract.symbol.file_path,
                contract.symbol.signature,
            ):
                self.contracts.add(contract)
                self.add_api(contract.role, contract.symbol.name, contract.source)
        for row in overlay.get("api_pairs", []):
            pair = ApiPair(
                SymbolIdentity.from_value(row.get("acquire")),
                SymbolIdentity.from_value(row.get("release")),
                row.get("conditions") or [],
                str(row.get("source") or ""),
                row.get("evidence") or [],
            )
            if pair not in self.contracts.pairs:
                self.contracts.pairs.append(pair)


CATEGORY_BY_ATTR = {
    "allocators": "allocator",
    "calloc_allocators": "calloc",
    "reallocators": "reallocator",
    "deallocators": "deallocator",
    "copy_sinks": "copy",
    "lock_apis": "lock",
    "unlock_apis": "unlock",
    "io_acquirers": "io_acquire",
    "io_releasers": "io_release",
    "send_sinks": "send_sink",
    "recv_sources": "recv_source",
    "format_sinks": "format_sink",
    "callback_registrars": "callback_register",
    "ownership_transfers": "ownership_transfer",
}

_CATEGORY_ATTRS = {
    "allocator": "allocators",
    "calloc": "calloc_allocators",
    "reallocator": "reallocators",
    "deallocator": "deallocators",
    "copy": "copy_sinks",
    "lock": "lock_apis",
    "unlock": "unlock_apis",
    "io_acquire": "io_acquirers",
    "io_release": "io_releasers",
    "send_sink": "send_sinks",
    "recv_source": "recv_sources",
    "format_sink": "format_sinks",
    "callback_register": "callback_registrars",
    "ownership_transfer": "ownership_transfers",
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
    if last_token_is(tokens, {"recv", "receive", "read", "input"}) or "recv" in lower:
        return "recv_source"
    if last_token_is(tokens, {"send", "write", "emit", "transmit"}) or "send" in lower:
        return "send_sink"
    if (
        last_token_is(tokens, {"open", "fopen", "socket", "accept", "connect", "mmap"})
        or "open" in lower
    ):
        return "io_acquire"
    if last_token_is(tokens, {"close", "fclose", "munmap", "disconnect"}) or "close" in lower:
        return "io_release"
    if "printf" in lower or last_token_is(tokens, {"log", "print", "syslog"}):
        return "format_sink"
    if (
        last_token_is(tokens, {"register", "subscribe", "hook", "install"})
        and "unregister" not in lower
    ):
        return "callback_register"
    return ""


def last_token_is(tokens: List[str], candidates: Set[str]) -> bool:
    return bool(tokens) and tokens[-1] in candidates


def attr_for_category(category: str) -> str:
    if category in _CATEGORY_ATTRS:
        return _CATEGORY_ATTRS[category]
    raise KeyError(category)
