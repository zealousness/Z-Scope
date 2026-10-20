"""Source-checked, non-atomic C reference-count effects, never implicit free.

This first subset uses one signed 32-bit member, explicit failure guards and
at most one zero-count callback. The callback's name does not establish its
effect: the object-path consumer must execute its current implementation.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import PurePath
import re
from typing import Any, Mapping

from .build_scope import context_build_id, source_scope_problem
from .contract_conditions import compare, negate
from .contracts import ApiContract, CONTRACT_COMPILER_VERSION, SymbolIdentity, code_tokens, digest


def verify_refcount_contract(
    raw: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, Any] | None:
    from .contract_compiler import closing, parameter_names

    proposal = raw.get("protocol")
    if not isinstance(proposal, dict) or proposal.get("kind") != "non_atomic_refcount":
        return None
    if source_scope_problem(context) or PurePath(str(context.get("file_path"))).suffix != ".c":
        return None
    facts = context.get("program_facts") or {}
    bodies = facts.get("functions") or []
    if not facts.get("complete") or not context_build_id(context) or len(bodies) != 1:
        return None
    body, name = bodies[0], str(context.get("func_name") or "")
    if (
        not body.get("complete")
        or body.get("fact_version") != "zscope.program-events.v5"
        or body.get("resource_protocol_facts_version") != "zscope.resource-protocol-facts.v1"
        or body.get("lifecycle_value_facts_version") != "zscope.lifecycle-value-facts.v1"
        or body.get("owner", {}).get("name") != name
        or not body.get("owner", {}).get("usr")
        or body.get("callable", {}).get("has_attributes") is not False
    ):
        return None
    contract = ApiContract.from_row({"contract": dict(raw), "symbol_name": name})
    if not contract or contract.role != "standard_operation":
        return None
    carrier = contract.carrier
    parameters = parameter_names(context)
    index = carrier.argument_index
    if (
        carrier.kind != "argument"
        or carrier.member_path
        or carrier.address_of
        or index is None
        or not 0 <= index < len(parameters)
    ):
        return None
    native_parameters = body.get("parameters") or []
    subject = [p for p in native_parameters if p.get("index") == index]
    if (
        len(subject) != 1
        or subject[0].get("pointee_record_kind") != "struct"
        or subject[0].get("volatile_or_atomic")
        or subject[0].get("has_attributes")
    ):
        return None
    operation = proposal.get("operation")
    path = str(proposal.get("count_path") or "")
    if operation not in {"init", "retain", "drop"} or not re.fullmatch(r"->[A-Za-z_]\w*", path):
        return None
    counter = parameters[index] + path
    events = body.get("events") or []
    if not events or any(
        not e.get("event_id")
        or e.get("contains_macro") is not False
        or e.get("event_kind") in {"implicit_release", "compound_assignment"}
        for e in events
    ):
        return None
    values = [v for e in events for key in ("defs", "uses") for v in e.get(key, [])]
    values += [v for edge in body.get("cfg_edges", []) for v in edge.get("condition_uses", [])]
    fields = [
        v
        for v in values
        if v.get("value_kind") == "field"
        and "".join(code_tokens(str(v.get("expression")))) == counter
    ]
    if (
        not fields
        or len({v.get("usr") for v in fields}) != 1
        or not fields[0].get("usr")
        or any(v.get("integer_bits") != 32 or v.get("integer_unsigned") for v in fields)
        or any(
            v.get("volatile_or_atomic") or v.get("overlapping_storage") or v.get("bit_field")
            for v in values
        )
    ):
        return None
    tokens = code_tokens(str(context.get("code") or ""))
    try:
        end = closing(tokens, tokens.index(name) + 1)
        implementation = "".join(tokens[end + 1 :]).replace("{return0;}", "return0;")
    except (ValueError, IndexError):
        return None
    calls = {
        ((e.get("location") or {}).get("offset"), e.get("expression")): e
        for e in events
        if e.get("event_kind") == "call"
    }
    terminal: dict[str, Any] = {}
    if operation == "init":
        expected = "{" + counter + "=1;}"
        returns, increment, assignment = set(), [], [counter + "=1"]
        if body.get("return_value_kind") != "void":
            return None
    else:
        if body.get("return_value_kind") != "integer" or body.get("return_integer_bits") != 32:
            return None
        guard = counter + "<=0"
        if operation == "retain":
            guard += "||" + counter + "==2147483647"
        change = counter + ("++" if operation == "retain" else "--")
        prefix = "{if(" + guard + ")return0;" + change + ";"
        middle = ""
        if operation == "drop" and calls:
            if len(calls) != 1:
                return None
            call = next(iter(calls.values()))
            arguments = ["".join(code_tokens(a)) for a in call.get("arguments", [])]
            if parameters[index] not in arguments or any(a not in parameters for a in arguments):
                return None
            middle = "if(" + counter + "==0){" + "".join(code_tokens(call["expression"])) + ";}"
            terminal = {
                "event_id": call["event_id"],
                "callee": call.get("callee", {}),
                "arguments": arguments,
                "effect": "requires_current_path_replay",
            }
        expected = prefix + middle + "return1;}"
        returns, increment, assignment = {"return0", "return1"}, [change], []
    if implementation != expected or (calls and not terminal):
        return None
    by_kind: dict[str, list[str]] = {}
    for event in events:
        by_kind.setdefault(str(event.get("event_kind")), []).append(
            "".join(code_tokens(str(event.get("expression") or "")))
        )
    if (
        by_kind.get("assignment", []) != assignment
        or by_kind.get("increment_decrement", []) != increment
        or set(by_kind.get("return", [])) != returns
    ):
        return None
    applied = {"op": "true"} if operation == "init" else compare({"kind": "return"}, "==", 1)
    return {
        "symbol": asdict(
            SymbolIdentity.from_value(
                {},
                name=name,
                file_path=context.get("file_path"),
                signature=context.get("signature"),
                build_context_id=context_build_id(context),
                # The verified native owner identity of the checked body;
                # consumers can pin this exact symbol and reject publications
                # whose USR was blanked or forged.
                usr=body["owner"]["usr"],
            )
        ),
        "role": "standard_operation",
        "carrier": asdict(carrier),
        "resource_domain": None,
        "resource_family": "refcount:"
        + digest([subject[0].get("pointee_record_usr"), fields[0]["usr"]]),
        "protocol": {
            "kind": "standard_api_effects",
            "family": "non_atomic_refcount",
            "operation": operation,
            "count_path": path,
            "count_field_usr": fields[0]["usr"],
            "integer_bits": 32,
            "atomic": False,
            "terminal_call": terminal,
            "terminal_effect": "unresolved",
            "thread_safety": "unproven",
            "transitions": [
                {
                    "when": applied,
                    "actions": [
                        {
                            "kind": "reference_count_" + operation,
                            "object": asdict(carrier),
                            "member_path": path,
                        }
                    ],
                }
            ],
        },
        "preconditions": {"op": "true"},
        "effect_cases": [{"when": applied, "effect": "applies"}]
        + ([] if operation == "init" else [{"when": negate(applied), "effect": "no_effect"}]),
        "conditions": [],
        "pairs": [],
        "source": "inferred:semantic_modeling",
        "evidence": [
            {"event_id": e["event_id"], "operation": e["event_kind"]}
            for e in events
            if e["event_kind"] in {"assignment", "increment_decrement", "call", "return"}
        ],
        "verification": {
            "method": "source_protocol",
            "checker": "non_atomic_refcount.v1",
            "compiler_version": CONTRACT_COMPILER_VERSION,
            "source_hash": digest(tokens),
            "effect_strength": "must_under_guard",
            "proof_authority": False,
        },
    }
