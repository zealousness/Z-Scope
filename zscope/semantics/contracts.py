"""Caller-visible API contracts shared by modeling, workbooks and detectors.

Names are lookup keys, never evidence for a role. Pair edges are directed: a
shared release endpoint does not make two acquisition protocols interchangeable.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping
from .contract_conditions import evaluate, legacy_predicate
from ..reporting.shared_objects import dataclass_dict

CONTRACT_SCHEMA_VERSION = "zscope.api-contract.v4"
CONTRACT_COMPILER_VERSION = "zscope.contract-compiler.v15"
ROLES = frozenset(
    {
        "allocator",
        "calloc",
        "reallocator",
        "deallocator",
        "lock",
        "unlock",
        "copy",
        "io_acquire",
        "io_release",
        "send_sink",
        "recv_source",
        "format_sink",
        "callback_register",
        "ownership_transfer",
        "lock_init",
        "lock_destroy",
        "lock_state",
        "lock_wait",
        "condition_init",
        "condition_destroy",
        "condition_signal",
        "thread_create",
        "thread_release",
        "standard_operation",
    }
)
ACQUIRE_ROLES = frozenset({"allocator", "calloc", "reallocator", "lock", "io_acquire"})
RELEASE_ROLES = frozenset({"deallocator", "unlock", "io_release"})


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
        ).encode()
    ).hexdigest()


def expand_api_pattern(pattern: str, semantics: Any) -> str:
    """Extend legacy call-shaped regexes using explicitly configured roles.

    The builtin spelling selects the protocol slot in a detector. Project
    names come exclusively from the published semantics, never suffix guesses.
    """
    slots = {
        "malloc": "allocators",
        "calloc": "calloc_allocators",
        "realloc": "reallocators",
        "free": "deallocators",
        "recv": "recv_sources",
        "send": "send_sinks",
        "pthread_mutex_lock": "lock_apis",
        "pthread_mutex_unlock": "unlock_apis",
    }
    if r"\s*\(" not in pattern:
        return pattern

    def replace(match: re.Match[str]) -> str:
        name = match[0]
        names = set(getattr(semantics, slots[name], {})) | {name}
        names = {
            n
            for n in names
            if n not in semantics.contracts.shadowed_symbols
            or any(c.effects_trusted for c in semantics.contracts.find(n))
        }
        role = {"malloc": "allocator", "calloc": "calloc", "realloc": "reallocator"}.get(name)
        if role:
            names = return_acquisition_names(semantics, names, role)
        if not names:
            return "(?!)"
        return "(?:" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True)) + ")"

    return re.sub(r"(?<![A-Za-z_])(?:" + "|".join(slots) + r")(?![A-Za-z_])", replace, pattern)


def return_acquisition_names(semantics: Any, names: Iterable[str], role: str) -> set[str]:
    """Call-result patterns cannot model globals or output-parameter objects."""
    result = set()
    for name in names:
        contracts = [c for c in semantics.contracts.find(name) if c.role == role]
        if name in semantics.contracts.shadowed_symbols and not contracts:
            continue
        # Legacy explicit role collections use the historical return binding.
        if not contracts or any(
            c.effects_trusted and c.carrier.kind == "return" for c in contracts
        ):
            result.add(name)
    return result


_CODE_TOKEN_PATTERN = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/|[A-Za-z_$]\w*|\d+(?:\.\d+)?|>>=|<<=|->\*|::|->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|\S'


def code_tokens(code: str) -> list[str]:
    """Ignore whitespace/comments without modifying string literals or tokens."""
    code = re.sub(r"(?m)^\s*\d+\s*\| ?", "", code)
    code = re.sub(r"\\\r?\n", "", code)
    return [token for token in re.findall(_CODE_TOKEN_PATTERN, code) if not token.startswith(("//", "/*"))]


@dataclass(frozen=True, order=True)
class SymbolIdentity:
    name: str
    file_path: str = ""
    signature: str = ""
    symbol_type: str = "function"

    @property
    def key(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_value(cls, value: Any, **defaults: Any) -> "SymbolIdentity":
        if isinstance(value, str):
            value = {"name": value}
        data = dict(defaults)
        data.update(value if isinstance(value, dict) else {})
        return cls(
            str(data.get("name") or data.get("symbol_name") or data.get("func_name") or ""),
            str(data.get("file_path") or "").replace("\\", "/"),
            " ".join(code_tokens(str(data.get("signature") or ""))),
            str(data.get("symbol_type") or "function"),
        )


@dataclass(frozen=True)
class ObjectBinding:
    """A caller object: return, argument, output_argument, or global."""

    kind: str = "unknown"
    argument_index: int | None = None
    member_path: str = ""
    global_name: str = ""
    address_of: bool = False

    @classmethod
    def from_value(cls, value: Any, role: str = "") -> "ObjectBinding":
        if isinstance(value, str):
            value = {"kind": value}
        if not isinstance(value, dict):
            # Legacy explicitly configured roles have the documented C carrier.
            value = {
                "kind": (
                    "return"
                    if role in {"allocator", "calloc", "reallocator", "io_acquire"}
                    else "argument"
                ),
                "argument_index": 0,
            }
        kind = str(value.get("kind") or "unknown")
        kind = {
            "arg": "argument",
            "out_param": "output_argument",
            "out_argument": "output_argument",
            "return_value": "return",
            "global_object": "global",
        }.get(kind, kind)
        index = value.get("argument_index", value.get("index"))
        return cls(
            kind,
            int(index) if isinstance(index, int) and index >= 0 else None,
            str(value.get("member_path") or ""),
            str(value.get("global_name") or value.get("name") or ""),
            value.get("address_of", kind == "global" and role in {"lock", "unlock"}) is True,
        )

    def resolve(self, arguments: list[str], returned: str = "") -> str:
        if self.kind == "return":
            obj = returned
        elif self.kind == "global":
            obj = self.global_name
        elif self.kind in {"argument", "output_argument"} and self.argument_index is not None:
            if self.argument_index >= len(arguments):
                return ""
            obj = arguments[self.argument_index].strip()
        else:
            return ""
        tokens = code_tokens(obj)
        from .contract_compiler import _pointer_identity_value, unparen

        tokens = _pointer_identity_value(tokens)
        if tokens[:1] in (["&"], ["*"]):
            tokens = [tokens[0], *unparen(tokens[1:])]
        while tokens[:2] in (["&", "*"], ["*", "&"]):
            tokens = unparen(tokens[2:])
        if not tokens:
            return ""
        member = self.member_path
        if member.startswith("->") and tokens[:1] == ["&"]:
            tokens = unparen(tokens[1:])
            member = "." + member[2:]
        elif self.kind == "output_argument" and not member:
            tokens = unparen(tokens[1:]) if tokens[:1] == ["&"] else ["*", *tokens]
        if self.address_of:
            tokens = unparen(tokens[1:]) if tokens[:1] == ["*"] and not member else ["&", *tokens]
        return "".join(tokens) + member


def semantic_model_unit_uid(context: Mapping[str, Any]) -> str:
    """Run-scoped audit identity shared by model calls and published snapshots."""
    symbol = SymbolIdentity.from_value(
        {},
        name=context.get("func_name", ""),
        file_path=context.get("file_path", ""),
        signature=context.get("signature", ""),
        symbol_type="macro" if context.get("is_macro") else "function",
    )
    return "semantic:" + digest(symbol.key)[:24]


@dataclass(frozen=True)
class ApiPair:
    acquire: SymbolIdentity
    release: SymbolIdentity
    conditions: Any = field(default_factory=list)
    source: str = ""
    evidence: Any = field(default_factory=list)

    def structural(self) -> dict[str, Any]:
        return {
            "acquire": asdict(self.acquire),
            "release": asdict(self.release),
            "conditions": self.conditions,
        }

    def to_dict(self) -> dict[str, Any]:
        return dataclass_dict(self)


@dataclass(frozen=True)
class ApiContract:
    symbol: SymbolIdentity
    role: str
    carrier: ObjectBinding
    conditions: Any = field(default_factory=list)
    pairs: tuple[SymbolIdentity, ...] = ()
    resource_family: str = ""
    source: str = "user"
    confidence: float = 1.0
    evidence: Any = field(default_factory=list)
    status: str = "active"
    preconditions: Any = field(default_factory=lambda: {"op": "true"})
    effect_cases: Any = field(default_factory=list)
    delegates: Any = field(default_factory=list)
    verification: Any = field(default_factory=dict)
    pair_evidence: Any = field(default_factory=list)
    resource_domain: ObjectBinding | None = None
    protocol: Any = field(default_factory=dict)

    @property
    def effects_trusted(self) -> bool:
        """Whether implementation evidence or an explicit assumption supports effects.

        Confidence and schema validation cannot grant this permission. Model
        proposals remain queryable, but cannot discharge a caller obligation.
        """
        if not self.source.startswith("inferred"):
            return True
        return bool(
            self.verification.get("method") in {"source_composition", "source_protocol"}
            and self.verification.get("compiler_version") == CONTRACT_COMPILER_VERSION
            and self.verification.get("source_hash")
            and self.verification.get("effect_strength") == "must_under_guard"
        )

    def structural(self) -> dict[str, Any]:
        return {
            "symbol": asdict(self.symbol),
            "role": self.role,
            "carrier": asdict(self.carrier),
            "conditions": self.conditions,
            "pairs": sorted((asdict(p) for p in self.pairs), key=digest),
            "resource_family": self.resource_family,
            "status": self.status,
            "preconditions": self.preconditions,
            "effect_cases": self.effect_cases,
            "delegates": self.delegates,
            "resource_domain": asdict(self.resource_domain) if self.resource_domain else None,
            "protocol": self.protocol,
            "effect_authority": "must_under_guard" if self.effects_trusted else "unverified",
        }

    def to_dict(self) -> dict[str, Any]:
        # This is a JSON boundary. asdict preserves tuples, which would make
        # an otherwise JSON candidate fall back to a full evidence deepcopy.
        value = dataclass_dict(self)
        value["pairs"] = list(value["pairs"])
        return value

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "ApiContract | None":
        raw = row.get("contract") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (ValueError, TypeError):
                return None
        if not isinstance(raw, dict):
            return None
        role = str(row.get("kind") or raw.get("role") or "")
        role = {"resource_acquire": "allocator", "resource_release": "deallocator"}.get(role, role)
        status = str(row.get("status") or raw.get("status") or "active")
        if role not in ROLES or status not in {"active", "valid", "confirmed", ""}:
            return None
        symbol = SymbolIdentity.from_value(raw.get("symbol", {}), **dict(row))
        if not symbol.name:
            return None
        pairs = parse_pair_targets(row.get("pair") or raw.get("pairs") or [])
        try:
            value = row.get("confidence", raw.get("confidence", 1.0))
            confidence = float(value) if value not in (None, "") else 1.0
        except (ValueError, TypeError):
            confidence = 0.0
        return cls(
            symbol,
            role,
            ObjectBinding.from_value(raw.get("carrier"), role),
            raw.get("conditions") or [],
            tuple(pairs),
            str(raw.get("resource_family") or ""),
            str(row.get("source") or raw.get("source") or "user"),
            confidence,
            raw.get("evidence") or [],
            status or "active",
            raw.get("preconditions") or {"op": "true"},
            raw.get("effect_cases") or [],
            raw.get("delegates") or [],
            raw.get("verification") or {},
            raw.get("pair_evidence") or [],
            (
                ObjectBinding.from_value(raw["resource_domain"])
                if raw.get("resource_domain")
                else None
            ),
            raw.get("protocol") or {},
        )

    def applicability(
        self, arguments: list[str], returned: str = "", facts: Mapping[str, Any] | None = None
    ) -> str:
        if not self.effects_trusted:
            return "unknown"
        prerequisite = evaluate(self.preconditions, arguments, returned, facts)
        if prerequisite == "does_not_apply":
            return prerequisite
        cases = self.effect_cases or [
            {"when": legacy_predicate(self.conditions), "effect": "applies"}
        ]
        possible = False
        for case in cases:
            status = evaluate(case.get("when"), arguments, returned, facts)
            if status == "applies":
                if case.get("effect") == "no_effect":
                    return "does_not_apply"
                if case.get("effect") == "applies" and prerequisite == "applies":
                    return "applies"
            possible |= status != "does_not_apply" and case.get("effect") != "no_effect"
        return "unknown" if possible else "does_not_apply"


@dataclass(frozen=True)
class CallSemanticMatch:
    role: str
    object: str
    applicability: str
    symbol: SymbolIdentity
    contract_version: str
    conditions: Any = field(default_factory=list)
    source: str = ""
    verification: Any = field(default_factory=dict)
    resource_domain: str = ""
    resource_family: str = ""
    effects_trusted: bool = False
    unknown_reason: str = ""
    callsite_facts: Any = field(default_factory=dict)
    transitions: Any = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclass_dict(self)


def parse_pair_targets(value: Any) -> list[SymbolIdentity]:
    if isinstance(value, tuple):
        value = list(value)
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            value = [item.strip() for item in value.split(",") if item.strip()]
    if not isinstance(value, list):
        return []
    return list(
        dict.fromkeys(
            SymbolIdentity.from_value(item) for item in value if isinstance(item, (str, dict))
        )
    )


def contract_rows(snapshots: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = {"resource": [], "lock": []}
    for snapshot in snapshots:
        for raw in snapshot.get("interface_contracts", []) or []:
            if not isinstance(raw, dict):
                continue
            declared = SymbolIdentity.from_value(raw.get("symbol", {}))
            if declared.name and declared.name != snapshot.get("func_name"):
                continue
            symbol = SymbolIdentity.from_value(
                {},
                name=snapshot.get("func_name"),
                file_path=snapshot.get("file_path", ""),
                signature=snapshot.get("signature", ""),
                symbol_type="macro" if snapshot.get("is_macro") else "function",
            )
            raw = dict(raw, symbol=asdict(symbol))
            row = {
                "symbol_name": symbol.name,
                "file_path": symbol.file_path,
                "signature": symbol.signature,
                "symbol_type": symbol.symbol_type,
                "kind": raw.get("role", ""),
                "contract": raw,
                "pair": [asdict(p) for p in parse_pair_targets(raw.get("pairs") or [])],
                "source": "inferred:semantic_modeling",
                "confidence": raw.get("confidence", 0.0),
                "status": "active",
                "description": "",
                "notes": "",
            }
            if ApiContract.from_row(row) is not None:
                rows[
                    (
                        "lock"
                        if row["kind"]
                        in {
                            "lock",
                            "unlock",
                            "lock_init",
                            "lock_destroy",
                            "lock_state",
                            "lock_wait",
                            "condition_init",
                            "condition_destroy",
                            "condition_signal",
                        }
                        else "resource"
                    )
                ].append(row)
    return rows


@dataclass
class ContractRegistry:
    contracts: list[ApiContract] = field(default_factory=list)
    pairs: list[ApiPair] = field(default_factory=list)
    shadowed_symbols: set[str] = field(default_factory=set)

    @property
    def version(self) -> str:
        values = [
            {
                **c.structural(),
                "origin": (
                    "inferred"
                    if c.source.startswith("inferred")
                    else "builtin" if c.source == "builtin_defaults" else "manual"
                ),
            }
            for c in self.contracts
        ]
        contracts = {digest(c): c for c in values}
        pairs = {digest(p.structural()): p.structural() for p in self.pairs}
        return digest(
            {
                "schema": CONTRACT_SCHEMA_VERSION,
                "shadowed_symbols": sorted(self.shadowed_symbols),
                "contracts": [contracts[k] for k in sorted(contracts)],
                "pairs": [pairs[k] for k in sorted(pairs)],
            }
        )

    def add(self, contract: ApiContract) -> None:
        replaced = [
            c
            for c in self.contracts
            if (c.symbol, c.role, c.carrier, c.conditions)
            == (contract.symbol, contract.role, contract.carrier, contract.conditions)
        ]
        self.contracts = [
            c
            for c in self.contracts
            if (c.symbol, c.role, c.carrier, c.conditions)
            != (contract.symbol, contract.role, contract.carrier, contract.conditions)
        ]
        old_edges = [p for c in replaced for p in self._edges(c)]
        supported = [p for c in self.contracts for p in self._edges(c)]
        self.pairs = [p for p in self.pairs if p not in old_edges or p in supported]
        self.contracts.append(contract)
        for pair in self._edges(contract):
            if pair not in self.pairs:
                self.pairs.append(pair)

    @staticmethod
    def _edges(contract: ApiContract) -> Iterable[ApiPair]:
        for other in contract.pairs:
            # V2 edges express protocol compatibility. Each endpoint's effect
            # predicate is evaluated at the actual call, in its own namespace.
            conditions = [] if contract.effect_cases else contract.conditions
            if contract.role in ACQUIRE_ROLES:
                yield ApiPair(
                    contract.symbol,
                    other,
                    conditions,
                    contract.source,
                    contract.pair_evidence or contract.evidence,
                )
            elif contract.role in RELEASE_ROLES:
                yield ApiPair(
                    other,
                    contract.symbol,
                    conditions,
                    contract.source,
                    contract.pair_evidence or contract.evidence,
                )

    def find(
        self, name: str, role: str = "", file_path: str = "", signature: str = ""
    ) -> list[ApiContract]:
        scoped = [
            c for c in self.contracts if c.symbol.name == name and c.source != "builtin_defaults"
        ]
        return [
            c
            for c in self.contracts
            if c.symbol.name == name
            and not ((scoped or name in self.shadowed_symbols) and c.source == "builtin_defaults")
            and (not role or c.role == role)
            and (
                not file_path
                or not c.symbol.file_path
                or c.symbol.file_path == file_path.replace("\\", "/")
            )
            and (not signature or not c.symbol.signature or c.symbol.signature == signature)
        ]

    def releases(self, acquire: str) -> set[str]:
        return {p.release.name for p in self.pairs if p.acquire.name == acquire}

    def acquires(self, release: str) -> set[str]:
        return {p.acquire.name for p in self.pairs if p.release.name == release}

    def allows(self, acquire: str, release: str) -> bool:
        # A source-only detector cannot distinguish overloads or file-local
        # homonyms. Ambiguous identities must not discharge an obligation.
        for name in (acquire, release):
            declared = [c for c in self.find(name) if c.role in ACQUIRE_ROLES | RELEASE_ROLES]
            if declared and not any(c.effects_trusted for c in declared):
                return False
            scoped = {c.symbol for c in self.find(name) if c.symbol.file_path or c.symbol.signature}
            if len(scoped) > 1:
                return False
        for pair in self.pairs:
            if pair.source == "builtin_defaults" and ({acquire, release} & self.shadowed_symbols):
                continue
            if pair.acquire.name != acquire or pair.release.name != release or pair.conditions:
                continue
            if not pair.source.startswith("inferred"):
                return True
            # Model-proposed edges remain visible for investigation, but only
            # implementation-supported contracts can authorize their use.
            if any(
                contract.effects_trusted
                and any(edge.structural() == pair.structural() for edge in self._edges(contract))
                for contract in self.contracts
                if contract.symbol in {pair.acquire, pair.release}
            ):
                return True
        return False

    def match_call(
        self,
        name: str,
        role: str,
        arguments: list[str],
        returned: str = "",
        *,
        file_path: str = "",
        signature: str = "",
        facts: Mapping[str, Any] | None = None,
    ) -> list[CallSemanticMatch]:
        from .call_context import unknown_reason, current_call_values

        facts = {**current_call_values(self, name, arguments, returned), **dict(facts or {})}
        matches = self.find(name, role, file_path, signature)
        if len({c.symbol for c in matches if c.symbol.file_path or c.symbol.signature}) > 1:
            return []
        return [
            CallSemanticMatch(
                c.role,
                c.carrier.resolve(arguments, returned),
                c.applicability(arguments, returned, facts),
                c.symbol,
                self.version,
                c.effect_cases or c.conditions,
                c.source,
                c.verification,
                c.resource_domain.resolve(arguments) if c.resource_domain else "",
                c.resource_family,
                c.effects_trusted,
                (
                    unknown_reason(c)
                    if c.applicability(arguments, returned, facts) == "unknown"
                    else ""
                ),
                dict(facts or {}),
                self.resolved_transitions(name, arguments, returned, facts=facts),
            )
            for c in matches
        ]

    def resolved_transitions(
        self,
        name: str,
        arguments: list[str],
        returned: str = "",
        *,
        facts: Mapping[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        from .contract_conditions import evaluate
        from .call_context import current_call_values

        known = {**current_call_values(self, name, arguments, returned), **dict(facts or {})}
        result = []
        for contract in self.find(name):
            if contract.protocol.get("kind") != "standard_api_effects":
                continue
            for transition in contract.protocol.get("transitions", []):
                status = evaluate(transition["when"], arguments, returned, known)
                if not contract.effects_trusted and status != "does_not_apply":
                    status = "unknown"
                actions = []
                for action in transition.get("actions", []):
                    resolved = {"kind": action["kind"]}
                    for key in ("object", "old", "new"):
                        if key in action:
                            binding = ObjectBinding.from_value(action[key])
                            resolved[key] = binding.resolve(arguments, returned)
                    actions.append(resolved)
                result.append(
                    {
                        "when": transition["when"],
                        "applicability": status,
                        "actions": actions,
                        "source": contract.source,
                        "verification": contract.verification,
                        "contract_version": self.version,
                    }
                )
        return result

    def allocation_extent(self, name: str, arguments: list[str]) -> str:
        expressions = set()
        for contract in self.find(name):
            if not contract.effects_trusted:
                continue
            parts: list[str] = []
            for ref in contract.protocol.get("allocation_extent", []):
                if ref.get("kind") == "literal":
                    value = str(ref["value"])
                else:
                    value = ObjectBinding.from_value(ref).resolve(arguments)
                if not value:
                    parts = []
                    break
                parts.append(value)
            if parts:
                expressions.add(" * ".join(parts))
        return next(iter(expressions)) if len(expressions) == 1 else ""

    def reallocation_input(self, name: str, arguments: list[str]) -> str:
        objects = {
            action.get("object") or action.get("old")
            for transition in self.resolved_transitions(name, arguments)
            for action in transition["actions"]
            if action["kind"] in {"preserve", "replace"}
        }
        objects.discard("")
        return str(next(iter(objects))) if len(objects) == 1 else ""

    def reallocation_failure_preservation(self, name: str, arguments: list[str]) -> str:
        old = self.reallocation_input(name, arguments)
        transitions = self.resolved_transitions(
            name, arguments, "$failed", facts={"$failed": None, old: {"non_null_identity": old}}
        )
        statuses = [
            t["applicability"]
            for t in transitions
            if any(a["kind"] == "preserve" for a in t["actions"])
        ]
        if "applies" in statuses:
            return "applies"
        return "does_not_apply" if statuses and set(statuses) == {"does_not_apply"} else "unknown"

    def resolve_object(self, name: str, role: str, arguments: list[str], returned: str = "") -> str:
        objects = {
            c.object
            for c in self.match_call(name, role, arguments, returned)
            if c.applicability != "does_not_apply" and c.object
        }
        return next(iter(objects)) if len(objects) == 1 else ""

    def release_status(
        self,
        acquire: str,
        release: str,
        arguments: list[str],
        *,
        acquired_object: str,
        facts: Mapping[str, Any] | None = None,
        acquired_domain: str = "",
        acquired_family: str = "",
        object_resolver: Any = None,
    ) -> str:
        if not self.allows(acquire, release):
            return "unknown"
        known = dict(facts or {})
        # This query is made for an acquired object, so a null-tolerant release
        # can be evaluated without guessing the value of unrelated arguments.
        known.setdefault(re.sub(r"\s+", "", acquired_object), object())
        resolve = object_resolver or (lambda value: value)
        for argument in arguments:
            if resolve(argument) == acquired_object:
                known.setdefault(re.sub(r"\s+", "", argument), object())
        results = [
            m
            for role in RELEASE_ROLES
            for m in self.match_call(release, role, arguments, facts=known)
            if resolve(m.object) == acquired_object
            and (
                not m.resource_family or not acquired_family or m.resource_family == acquired_family
            )
        ]
        # A pool is part of the resource instance, not merely an API family.
        # Legacy consumers without an acquisition domain must remain unknown.
        domain_results = [
            m
            for m in results
            if not m.resource_domain
            and not acquired_domain
            or m.resource_domain
            and acquired_domain
            and resolve(m.resource_domain) == acquired_domain
        ]
        if results and not domain_results:
            return (
                "does_not_apply"
                if acquired_domain and all(m.resource_domain for m in results)
                else "unknown"
            )
        results = domain_results
        if any(m.applicability == "applies" for m in results):
            return "applies"
        if results and all(m.applicability == "does_not_apply" for m in results):
            return "does_not_apply"
        return "unknown"

    @staticmethod
    def call_arguments(name: str, text: str) -> list[str] | None:
        """Read actual arguments, including parenthesized macro arguments."""
        from .contract_compiler import closing, split_tokens

        tokens = code_tokens(text)
        for i, token in enumerate(tokens[:-1]):
            if token == name and tokens[i + 1] == "(":
                end = closing(tokens, i + 1)
                return ["".join(part) for part in split_tokens(tokens[i + 2 : end])]
        return None

    def effect_status(
        self, name: str, role: str, text: str, *, object_name: str = "", acquired: bool = False
    ) -> str:
        arguments = self.call_arguments(name, text)
        if arguments is None:
            return "unknown"
        facts = {re.sub(r"\s+", "", object_name): object()} if acquired and object_name else {}
        matches = self.match_call(name, role, arguments, facts=facts)
        matches = [m for m in matches if not object_name or m.object == object_name]
        if any(m.applicability == "applies" for m in matches):
            return "applies"
        if matches and all(m.applicability == "does_not_apply" for m in matches):
            return "does_not_apply"
        return "unknown"

    def release_in_text(
        self,
        acquire: str,
        release: str,
        text: str,
        object_name: str,
        *,
        acquired_domain: str = "",
        acquired_family: str = "",
        object_resolver: Any = None,
    ) -> str:
        arguments = self.call_arguments(release, text)
        if arguments is None:
            return "unknown"
        return self.release_status(
            acquire,
            release,
            arguments,
            acquired_object=object_name,
            acquired_domain=acquired_domain,
            acquired_family=acquired_family,
            object_resolver=object_resolver,
        )

    def acquisition_domain(self, name: str, text: str) -> tuple[str, str]:
        arguments = self.call_arguments(name, text)
        if arguments is None:
            return "", ""
        values = {
            (c.resource_domain.resolve(arguments) if c.resource_domain else "", c.resource_family)
            for c in self.find(name)
            if c.role in ACQUIRE_ROLES
        }
        return next(iter(values)) if len(values) == 1 else ("", "")

    def trace_calls(self, context: Mapping[str, Any]) -> list[dict[str, Any]]:
        """Auditable call-site resolutions against this frozen publication."""
        from .contract_compiler import read_source_facts

        source_facts = read_source_facts(context, self)
        events = []
        from .call_context import call_values

        for ordinal, call in enumerate(source_facts.calls):
            known = call_values(source_facts, call)
            for role in sorted({c.role for c in self.find(call.name)}):
                for match in self.match_call(
                    call.name, role, call.arguments, call.result, facts=known
                ):
                    events.append(
                        {
                            **match.to_dict(),
                            "call_ordinal": ordinal,
                            "caller": context.get("index_name") or context.get("func_name"),
                            "file_path": context.get("file_path"),
                            "arguments": call.arguments,
                            "returned": call.result,
                            "source_hash": digest(code_tokens(str(context.get("code") or ""))),
                            "guard": call.guard,
                            "source_facts_complete": source_facts.complete,
                        }
                    )
        return events


def outward_contract(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Only structured caller-visible behavior drives propagation, never prose."""
    contracts = []
    for raw in snapshot.get("interface_contracts", []) or []:
        if isinstance(raw, dict):
            contract = ApiContract.from_row(
                {
                    "contract": raw,
                    "kind": raw.get("role"),
                    "symbol_name": snapshot.get("func_name", ""),
                    "file_path": snapshot.get("file_path", ""),
                    "signature": snapshot.get("signature", ""),
                    "symbol_type": "macro" if snapshot.get("is_macro") else "function",
                }
            )
            if contract:
                contracts.append(contract.structural())

    def structure(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                k: structure(v)
                for k, v in value.items()
                if k
                not in {
                    "description",
                    "summary",
                    "meaning",
                    "caller_obligations",
                    "constraints",
                    "condition",
                    "guard",
                    "notes",
                    "evidence",
                    "line",
                    "lines",
                    "start_line",
                    "end_line",
                }
            }
        if isinstance(value, list):
            return [structure(v) for v in value]
        return value

    return {
        "interface_contracts": sorted(contracts, key=digest),
        "parameters": structure(snapshot.get("parameters", [])),
        "return_values": structure(snapshot.get("return_values", [])),
        "effects": structure(
            [
                effect
                for effect in snapshot.get("effects", [])
                if isinstance(effect, dict) and effect.get("caller_visible") is True
            ]
        ),
    }
