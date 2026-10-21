"""Conservative call-site values derived from parsed branch/assignment facts."""

from __future__ import annotations

import re
from typing import Any, Mapping


def branch_values(predicate: Mapping[str, Any], parameters: list[str]) -> dict[str, Any]:
    """Only conjunctive, explicit values authorize effects; alternatives intersect."""
    from .contract_conditions import predicate_errors

    if predicate_errors(dict(predicate)):
        return {}
    op = predicate.get("op")
    if op in {"all", "any"}:
        branches = [branch_values(item, parameters) for item in predicate.get("items", [])]
        if not branches:
            return {}
        result = dict(branches[0])
        for branch in branches[1:]:
            if op == "all":
                for key, value in branch.items():
                    if key in result and result[key] != value:
                        result.pop(key, None)
                    else:
                        result[key] = value
            else:
                result = {k: v for k, v in result.items() if branch.get(k, object()) == v}
        return result
    if op != "compare":
        return {}
    left, right = predicate.get("left", {}), predicate.get("right", {})
    if right.get("kind") != "literal":
        return {}
    kind = left.get("kind")
    if kind == "argument":
        index = left.get("index")
        name = parameters[index] if isinstance(index, int) and 0 <= index < len(parameters) else ""
    elif kind in {"global", "call_result"}:
        name = str(left.get("name") or "")
    else:
        return {}
    name = re.sub(r"\s+", "", name + str(left.get("member_path") or ""))
    if left.get("address_of"):
        from .contracts import ObjectBinding

        name = ObjectBinding.from_value(left).resolve(parameters)
    if not name:
        return {}
    value = right.get("value")
    if predicate.get("operator") == "==":
        return {name: value}
    if predicate.get("operator") == "!=" and value in (None, 0):
        return {name: {"non_null_identity": name}}
    return {}


def call_values(function_facts: Any, call: Any) -> dict[str, Any]:
    if not function_facts.complete:
        return {}
    values = branch_values(call.guard, function_facts.parameters)
    # Incoming aliases are tied to this call, not the final assignment map.
    for name, ref in call.aliases_at_call.items():
        identity = str(ref.get("name") or "") if isinstance(ref, dict) else ""
        if identity in values:
            values[name] = values[identity]
        else:
            values.pop(name, None)
    # Parameters with writes/address escapes cannot borrow an entry-value fact.
    for parameter in function_facts.parameters:
        if function_facts.assignment_counts.get(parameter):
            values.pop(parameter, None)
    return values


def unknown_reason(contract: Any) -> str:
    if not contract.effects_trusted:
        return "contract_unverified"

    def kinds(value: Any) -> set[str]:
        if isinstance(value, dict):
            return {str(value.get("kind") or "")} | set().union(*(kinds(v) for v in value.values()))
        if isinstance(value, list):
            return set().union(*(kinds(v) for v in value))
        return set()

    references = kinds(contract.effect_cases)
    if "call_result" in references:
        return "hidden_runtime_status"
    if not contract.resource_family and contract.role in {"allocator", "deallocator"}:
        return "underlying_protocol_unknown"
    return "callsite_facts_missing"


# Context belongs to the executing function, never to a mutable registry shared
# by parallel analyzers. Only values common to every indistinguishable call are
# exposed to consumers that do not provide a precise call ordinal.
from contextlib import contextmanager
from contextvars import ContextVar
from types import MappingProxyType

_ACTIVE_CALL_FACTS: ContextVar[Any] = ContextVar("semantic_call_facts", default=None)


def _freeze_nested(value: Any) -> Any:
    """Recursively copy one call-value payload, preserving its types.

    Dicts stay dicts, lists stay lists, tuples stay tuples — consumers
    compare and index these values with their original semantics — but
    every nested container is a fresh copy, so no nested list or dict is
    shared with the parent's live binding.  Scalars pass through
    unchanged; nothing is invented, widened, or re-derived.
    """

    if isinstance(value, dict):
        return {key: _freeze_nested(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_freeze_nested(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_freeze_nested(item) for item in value)
    return value


def freeze_call_facts(value: Any) -> Any:
    """Freeze one captured call-facts binding into an immutable snapshot.

    The registry reference is preserved verbatim — identity checks in
    :func:`current_callee_usr` compare object identity and must keep
    working — while every per-call entry and the callee-observation map
    are copied into write-protected containers.  Arguments stay lists and
    nested call values keep their original container types (a recursive
    copy, not a shallow wrap): a consumer passing a plain argument list
    still matches its frozen entry, valid native facts like target values
    survive the freeze unchanged, and a parent thread mutating its own
    live binding — at any nesting depth — can never rewrite what a worker
    already captured or what a provider task froze at submit time.
    ``None`` (no binding) passes through unchanged; the freeze never
    invents, widens, or re-derives an identity.
    """

    if value is None:
        return None
    registry, entries, observations = value
    frozen_entries = tuple(
        (symbol, list(arguments), result, MappingProxyType(_freeze_nested(values)))
        for symbol, arguments, result, values in entries
    )
    frozen_observations = MappingProxyType(dict(observations))
    return (registry, frozen_entries, frozen_observations)


def current_call_facts() -> Any:
    """The active per-entry call binding, exactly as verified at bind time.

    The value is the opaque ``(registry, entries, observations)`` tuple that
    :func:`bind_call_context` built from one entry's native receipts, or
    ``None`` when no entry context is bound.  Worker boundaries capture this
    value so they can rebind the same entry's map on another thread and,
    just as importantly, clear a previous entry's map when the identity
    switches — a captured value is never a license to keep another entry's
    observations alive.
    """

    return _ACTIVE_CALL_FACTS.get()


@contextmanager
def rebound_call_facts(value: Any):
    """Bind a captured call-facts value; always restore the previous one.

    Setting ``None`` deliberately clears any ambient binding (the legacy /
    unknown-identity case); the finally path restores whatever was active
    before, so pool threads reused across entries, variants, and exceptions
    never retain a stale callee map.
    """

    marker = _ACTIVE_CALL_FACTS.set(value)
    try:
        yield
    finally:
        _ACTIVE_CALL_FACTS.reset(marker)


# A callee name observed with conflicting or empty USRs inside one body.
# Distinct from "not observed at all": mixed observations are evidence
# AGAINST any single identity and must also block the entry-symbol fallback.
AMBIGUOUS_CALLEE = ""


def callee_usr_observations(context: Mapping[str, Any]) -> dict[str, str]:
    """Per-name callee identity state from this body's native call receipts.

    Returns ``name -> USR`` for unambiguously observed callees,
    ``name -> AMBIGUOUS_CALLEE`` for names whose events name more than one
    USR (mixed overloads or unresolved targets), and omits entirely
    unobserved names.  Incomplete or stale facts observe nothing.
    """

    facts = context.get("program_facts") or {}
    if not isinstance(facts, Mapping) or not facts.get("complete"):
        return {}
    if facts.get("reason"):
        # A stale receipt never resolves a callee identity, exactly like the
        # entry-symbol and context USR helpers.
        return {}
    observed: dict[str, set[str]] = {}
    for body in facts.get("functions", []) or []:
        if not isinstance(body, Mapping) or not body.get("complete"):
            continue
        for event in body.get("events", []) or []:
            if not isinstance(event, Mapping) or event.get("event_kind") != "call":
                continue
            callee = event.get("callee")
            callee = callee if isinstance(callee, Mapping) else {}
            name = str(callee.get("name") or "")
            if not name:
                continue
            observed.setdefault(name, set()).add(str(callee.get("usr") or ""))
    result: dict[str, str] = {}
    for name, usrs in observed.items():
        if len(usrs) == 1 and next(iter(usrs)):
            result[name] = next(iter(usrs))
        else:
            result[name] = AMBIGUOUS_CALLEE
    return result


def callee_usr_map(context: Mapping[str, Any]) -> dict[str, str]:
    """Per-body callee USRs from the native call receipts, conservatively.

    A callee name maps to a USR only when every native call event for that
    name inside this one complete function body names the same non-empty USR.
    Mixed overloads, unresolved/indirect targets, or incomplete facts leave
    the name unmapped (""); an unmapped name is name-level, never a wildcard.
    """

    return {
        name: usr
        for name, usr in callee_usr_observations(context).items()
        if usr != AMBIGUOUS_CALLEE
    }


@contextmanager
def bind_call_context(context: Mapping[str, Any], registry: Any):
    from .contract_compiler import read_source_facts
    from .build_scope import bind_build_scope

    source = read_source_facts(context, registry.for_context(context))
    target: dict[str, Any] = {}
    for body in (context.get("program_facts") or {}).get("functions", []):
        target.update(body.get("target_values") or {})
    entries = [
        (call.name, call.arguments, call.result, {**target, **call_values(source, call)})
        for call in source.calls
    ]
    observations = callee_usr_observations(context)
    marker = _ACTIVE_CALL_FACTS.set((registry, entries, observations))
    try:
        with bind_build_scope(context):
            yield
    finally:
        _ACTIVE_CALL_FACTS.reset(marker)


def current_call_values(
    registry: Any, name: str, arguments: list[str], returned: str
) -> dict[str, Any]:
    active = _ACTIVE_CALL_FACTS.get()
    if active is None or active[0] is not registry:
        return {}
    matches = [
        values
        for symbol, args, result, values in active[1]
        if symbol == name and args == arguments and (not returned or result == returned)
    ]
    if not matches:
        return {}
    return {
        key: value
        for key, value in matches[0].items()
        if all(key in other and other[key] == value for other in matches[1:])
    }


def current_callee_usr(registry: Any, name: str) -> str:
    """The bound body's unambiguous native USR for one callee name.

    The per-body call observations win.  An unambiguous receipt resolves the
    identity; a name this body observed with MIXED USRs is evidence against
    any single identity and resolves to "" — it must not fall back to the
    entry symbol, which would borrow the analyzed function's own USR for an
    unproven overload selection.  Only a name this body never observed may
    fall back to the analysis context's own entry symbol (that is the
    identity of the function being analyzed, not a guess about an unknown
    callee).  Anything else resolves to "".
    """

    active = _ACTIVE_CALL_FACTS.get()
    if active is not None and active[0] is registry and name in active[2]:
        return str(active[2][name] or "")
    from .build_scope import current_scope_symbol_usr

    return current_scope_symbol_usr(name)
