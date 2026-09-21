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

_ACTIVE_CALL_FACTS: ContextVar[Any] = ContextVar("semantic_call_facts", default=None)


@contextmanager
def bind_call_context(context: Mapping[str, Any], registry: Any):
    from .contract_compiler import read_source_facts

    source = read_source_facts(context, registry)
    target: dict[str, Any] = {}
    for body in (context.get("program_facts") or {}).get("functions", []):
        target.update(body.get("target_values") or {})
    entries = [
        (call.name, call.arguments, call.result, {**target, **call_values(source, call)})
        for call in source.calls
    ]
    marker = _ACTIVE_CALL_FACTS.set((registry, entries))
    try:
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
