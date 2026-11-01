"""Source-checked bounded integer handle tables; no OS-close inference.

Slots have separate live and backing-object fields. Dup copies the backing
identity into a different free slot; closing consumes only that descriptor.
An error can occur before or after consumption, as established by the body.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from pathlib import PurePath
import re
from typing import Any, Mapping

from .build_scope import context_build_id, source_scope_problem
from .contract_conditions import compare, negate
from .contracts import ApiContract, CONTRACT_COMPILER_VERSION, SymbolIdentity, code_tokens, digest


def verify_handle_contract(
    raw: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, Any] | None:
    from .contract_compiler import closing, parameter_names

    proposal = raw.get("protocol")
    if not isinstance(proposal, dict) or proposal.get("kind") != "bounded_handle_table":
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
        or body.get("fact_version") != "zscope.program-events.v7"
        or body.get("resource_protocol_facts_version") != "zscope.resource-protocol-facts.v1"
        or body.get("lifecycle_value_facts_version") != "zscope.lifecycle-value-facts.v1"
        or body.get("owner", {}).get("name") != name
        or not body.get("owner", {}).get("usr")
        or body.get("callable", {}).get("has_attributes") is not False
        or body.get("return_value_kind") != "integer"
        or body.get("return_integer_bits") != 32
        or body.get("return_integer_unsigned")
    ):
        return None
    contract = ApiContract.from_row({"contract": dict(raw), "symbol_name": name})
    if not contract or contract.role != "standard_operation":
        return None
    domain, carrier = contract.resource_domain, contract.carrier
    parameters = parameter_names(context)
    operation = proposal.get("operation")
    if operation not in {"open", "close", "dup"}:
        return None
    count = {"open": 1, "close": 3, "dup": 2}[operation]
    if (
        len(parameters) != count
        or domain is None
        or domain.kind != "argument"
        or domain.argument_index != 0
        or domain.member_path
        or domain.address_of
        or carrier.kind != ("return" if operation == "open" else "argument")
        or carrier.argument_index != (None if operation == "open" else 1)
        or carrier.member_path
        or carrier.address_of
    ):
        return None
    native = body.get("parameters") or []
    if (
        len(native) != count
        or native[0].get("pointee_record_kind") != "struct"
        or not native[0].get("pointee_record_usr")
        or any(p.get("has_attributes") or p.get("volatile_or_atomic") for p in native)
        or any(p.get("integer_bits") != 32 or p.get("integer_unsigned") for p in native[1:])
    ):
        return None
    slots = proposal.get("handle_slots")
    if not isinstance(slots, list) or not 2 <= len(slots) <= 4:
        return None
    paths, numbers = [], []
    for slot in slots:
        if not isinstance(slot, dict):
            return None
        number = slot.get("value")
        if type(number) is not int or not 0 <= number < 2**31:
            return None
        numbers.append(number)
        for key in ("live_path", "object_path"):
            path = slot.get(key)
            if not isinstance(path, str) or not re.fullmatch(r"->[A-Za-z_]\w*", path):
                return None
            paths.append(path)
    if len(set(numbers)) != len(numbers) or len(set(paths)) != len(paths):
        return None
    sequence = proposal.get("sequence_path", "")
    if operation == "open":
        if (
            not isinstance(sequence, str)
            or not re.fullmatch(r"->[A-Za-z_]\w*", sequence)
            or sequence in paths
        ):
            return None
    elif sequence:
        return None
    failure = proposal.get("close_failure", "")
    if (operation == "close" and failure not in {"preserves", "consumes"}) or (
        operation != "close" and failure
    ):
        return None
    events = body.get("events") or []
    if not events or any(
        not e.get("event_id")
        or e.get("contains_macro") is not False
        or e.get("event_kind") not in {"assignment", "increment_decrement", "return", "statement"}
        for e in events
    ):
        return None
    values = [v for e in events for key in ("defs", "uses") for v in e.get(key, [])]
    values += [v for e in body.get("cfg_edges", []) for v in e.get("condition_uses", [])]
    if any(
        v.get("volatile_or_atomic") or v.get("overlapping_storage") or v.get("bit_field")
        for v in values
    ):
        return None
    table = parameters[0]
    field_usrs = {}
    for path in paths + ([sequence] if sequence else []):
        fields = [
            v
            for v in values
            if v.get("value_kind") == "field"
            and "".join(code_tokens(str(v.get("expression")))) == table + path
        ]
        if (
            not fields
            or len({v.get("usr") for v in fields}) != 1
            or not fields[0].get("usr")
            or any(v.get("integer_bits") != 32 or v.get("integer_unsigned") for v in fields)
        ):
            return None
        field_usrs[path] = fields[0]["usr"]
    tokens = code_tokens(str(context.get("code") or ""))
    try:
        end = closing(tokens, tokens.index(name) + 1)
        implementation = "".join(tokens[end + 1 :]).replace("{return-1;}", "return-1;")
    except (ValueError, IndexError):
        return None
    assignments, increments = [], []

    def store(target: str, value: str) -> str:
        expression = table + target + "=" + value
        assignments.append(expression)
        return expression + ";"

    expected = "{"
    if operation == "open":
        expected += "if(" + table + sequence + "==2147483647)return-1;"
        for slot in slots:
            increment = table + sequence + "++"
            increments.append(increment)
            expected += "if(!" + table + slot["live_path"] + "){" + increment + ";"
            expected += store(slot["object_path"], table + sequence)
            expected += store(slot["live_path"], "1") + "return" + str(slot["value"]) + ";}"
    elif operation == "close":
        handle, failed = parameters[1:]
        if failure == "preserves":
            expected += "if(" + failed + ")return-1;"
        for slot in slots:
            expected += (
                "if(" + handle + "==" + str(slot["value"]) + "&&" + table + slot["live_path"] + "){"
            )
            expected += store(slot["live_path"], "0") + store(slot["object_path"], "0")
            if failure == "consumes":
                expected += "if(" + failed + ")return-1;"
            expected += "return0;}"
    else:
        handle = parameters[1]
        for source in slots:
            expected += (
                "if("
                + handle
                + "=="
                + str(source["value"])
                + "&&"
                + table
                + source["live_path"]
                + "){"
            )
            for target in slots:
                if target is source:
                    continue
                expected += "if(!" + table + target["live_path"] + "){"
                expected += store(target["object_path"], table + source["object_path"])
                expected += store(target["live_path"], "1") + "return" + str(target["value"]) + ";}"
            expected += "return-1;}"
    expected += "return-1;}"
    if implementation != expected:
        return None

    def expressions(kind: str) -> Counter[str]:
        return Counter(
            "".join(code_tokens(str(e.get("expression"))))
            for e in events
            if e.get("event_kind") == kind
        )

    if expressions("assignment") != Counter(assignments) or expressions(
        "increment_decrement"
    ) != Counter(increments):
        return None
    identity = {
        "table_type_usr": native[0]["pointee_record_usr"],
        "slots": [
            {
                **s,
                "live_usr": field_usrs[s["live_path"]],
                "object_usr": field_usrs[s["object_path"]],
            }
            for s in slots
        ],
    }
    # Close's status alone never determines whether the descriptor was consumed.
    applied = {"op": "unknown"} if operation == "close" else compare({"kind": "return"}, ">=", 0)
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
        "resource_domain": asdict(domain),
        "resource_family": "handle_table:" + digest(identity),
        "protocol": {
            "kind": "standard_api_effects",
            "family": "bounded_handle_table",
            "operation": operation,
            "table_identity": identity,
            "sequence_path": sequence,
            "close_failure": failure,
            "failure_value": -1,
            "transitions": [
                {
                    "when": applied,
                    "actions": [
                        {
                            "kind": "handle_" + operation,
                            "object": asdict(carrier),
                            "requires_current_path_replay": True,
                        }
                    ],
                }
            ],
            "backing_object_destruction": "unproven",
            "thread_safety": "unproven",
        },
        "preconditions": {"op": "true"},
        "effect_cases": [
            {"when": applied, "effect": "applies"},
            {"when": negate(applied), "effect": "no_effect"},
        ],
        "conditions": [],
        "pairs": [],
        "source": "inferred:semantic_modeling",
        "evidence": [
            {"event_id": e["event_id"], "operation": e["event_kind"]}
            for e in events
            if e["event_kind"] != "statement"
        ],
        "verification": {
            "method": "source_protocol",
            "checker": "bounded_handle_table.v1",
            "compiler_version": CONTRACT_COMPILER_VERSION,
            "source_hash": digest(tokens),
            "effect_strength": "must_under_guard",
            "proof_authority": False,
        },
    }
