"""Bounded C pool effects checked against source and current native facts.

The slot has logical acquire/return obligations, never heap-free semantics.
Release guards refer to caller state before the call. Unknown membership or
availability cannot discharge an obligation, even for a compatible API pair.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import PurePath
import re
from typing import Any, Mapping

from .build_scope import context_build_id, source_scope_problem
from .contract_conditions import compare, conjunction, negate
from .contracts import (
    ApiContract,
    CONTRACT_COMPILER_VERSION,
    ObjectBinding,
    SymbolIdentity,
    code_tokens,
    digest,
)


def verify_single_slot_pool(
    raw: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, Any] | None:
    from .contract_compiler import closing, parameter_names, split_tokens

    proposal = raw.get("protocol")
    if not isinstance(proposal, dict) or proposal.get("kind") != "single_slot_pool":
        return None
    if (
        source_scope_problem(context)
        or PurePath(str(context.get("file_path") or "")).suffix != ".c"
    ):
        return None
    facts = context.get("program_facts") or {}
    bodies = facts.get("functions") or []
    if not facts.get("complete") or not context_build_id(context) or len(bodies) != 1:
        return None
    body, name = bodies[0], str(context.get("func_name") or "")
    if (
        body.get("fact_version") != "zscope.program-events.v5"
        or body.get("resource_protocol_facts_version") != "zscope.resource-protocol-facts.v1"
        or body.get("owner", {}).get("name") != name
        or not body.get("owner", {}).get("usr")
    ):
        return None
    events = body.get("events") or []
    if not events or any(
        not event.get("event_id")
        or event.get("event_kind") in {"call", "implicit_release", "compound_assignment"}
        or "contains_macro" not in event
        or (
            event.get("contains_macro")
            and not (
                event.get("null_pointer_constant") is True
                and "".join(code_tokens(str(event.get("expression") or "")))
                in {"NULL", "returnNULL"}
            )
        )
        for event in events
    ):
        return None
    contract = ApiContract.from_row({"contract": dict(raw), "symbol_name": name})
    if not contract or contract.role not in {"allocator", "deallocator"}:
        return None
    return_status = proposal.get("return_status", False)
    if not isinstance(return_status, bool) or (
        return_status
        and (
            contract.role != "deallocator"
            or body.get("return_value_kind") != "integer"
            or body.get("return_integer_bits") != 32
        )
    ):
        return None
    domain, carrier = contract.resource_domain, contract.carrier
    if not domain or domain.kind != "argument" or domain.member_path or domain.address_of:
        return None
    parameters = parameter_names(context)
    index = domain.argument_index
    if index is None or not 0 <= index < len(parameters):
        return None
    native_parameters = body.get("parameters") or []
    pool_parameters = [p for p in native_parameters if p.get("index") == index]
    if (
        len(pool_parameters) != 1
        or pool_parameters[0].get("pointee_record_kind") != "struct"
        or not pool_parameters[0].get("pointee_record_usr")
    ):
        return None
    paths = {
        key: str(proposal.get(key) or "")
        for key in ("slot_path", "live_path", "generation_path", "invalid_return_path")
    }
    if not all(re.fullmatch(r"->[A-Za-z_]\w*", paths[key]) for key in ("slot_path", "live_path")):
        return None
    if paths["slot_path"] == paths["live_path"]:
        return None
    for key in ("generation_path", "invalid_return_path"):
        path = paths[key]
        pattern = (
            r"->[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?" if key == "generation_path" else r"->[A-Za-z_]\w*"
        )
        if path and (
            not re.fullmatch(pattern, path) or path in {paths["slot_path"], paths["live_path"]}
        ):
            return None
    tokens = code_tokens(str(context.get("code") or ""))
    try:
        opening = tokens.index(name) + 1
        end = closing(tokens, opening)
        declarations = split_tokens(tokens[opening + 1 : end])
        declaration = declarations[index]
        if declaration.count("*") != 1 or declaration[-1] != parameters[index]:
            return None
        implementation = "".join(tokens[end + 1 :])
    except (ValueError, IndexError):
        return None
    pool = parameters[index]
    slot, live = pool + paths["slot_path"], pool + paths["live_path"]
    actions: list[dict[str, Any]]
    increments: list[str] = []
    if contract.role == "allocator":
        if carrier != ObjectBinding("return"):
            return None
        increment = pool + paths["generation_path"] + "++;" if paths["generation_path"] else ""
        pattern = (
            r"\{if\("
            + re.escape(live)
            + r"\)(?:\{return(?P<braced>NULL|0);\}|return(?P<plain>NULL|0);)"
            + re.escape(live + "=1;" + increment + "return&" + slot + ";}")
        )
        match = re.fullmatch(pattern, implementation)
        if not match:
            return None
        null = match["braced"] or match["plain"]
        expected_returns = {"return" + null, "return&" + slot}
        if not any(
            event.get("event_kind") == "return"
            and "".join(code_tokens(str(event.get("expression") or ""))) == "return" + null
            and event.get("null_pointer_constant") is True
            for event in events
        ):
            return None
        assignment = live + "=1"
        applied = compare({"kind": "return"}, "!=", None)
        actions = [
            {
                "kind": "acquire_pool_slot",
                "object": asdict(carrier),
                "new": asdict(
                    ObjectBinding("argument", index, paths["slot_path"], address_of=True)
                ),
            }
        ]
        if increment:
            increments.append(increment[:-1])
            actions.append(
                {
                    "kind": "advance_generation",
                    "object": asdict(ObjectBinding("argument", index, paths["generation_path"])),
                }
            )
    else:
        node_index = carrier.argument_index
        if (
            carrier.kind != "argument"
            or carrier.member_path
            or carrier.address_of
            or node_index is None
            or not 0 <= node_index < len(parameters)
            or node_index == index
        ):
            return None
        if declarations[node_index].count("*") != 1:
            return None
        node = parameters[node_index]
        invalid = (
            pool + paths["invalid_return_path"] + "++;" if paths["invalid_return_path"] else ""
        )
        guard = node + "!=&" + slot + "||!" + live
        failure_return = "return0" if return_status else "return"
        expected = "{if(" + guard + "){" + invalid + failure_return + ";}" + live + "=0;"
        expected += "return1;}" if return_status else "}"
        if implementation != expected:
            return None
        expected_returns = {"return0", "return1"} if return_status else {"return"}
        assignment = live + "=0"
        if invalid:
            increments.append(invalid[:-1])
        membership = {
            "op": "compare",
            "left": {"kind": "argument", "index": node_index},
            "operator": "==",
            "right": {
                "kind": "argument",
                "index": index,
                "member_path": paths["slot_path"],
                "address_of": True,
            },
        }
        applied = conjunction(
            [
                membership,
                compare(
                    {"kind": "argument", "index": index, "member_path": paths["live_path"]}, "!=", 0
                ),
            ]
        )
        actions = [{"kind": "release_pool_slot", "object": asdict(carrier)}]
    by_kind: dict[str, list[str]] = {}
    for event in events:
        by_kind.setdefault(str(event.get("event_kind")), []).append(
            "".join(code_tokens(str(event.get("expression") or "")))
        )
    if (
        by_kind.get("assignment") != [assignment]
        or sorted(by_kind.get("increment_decrement", [])) != sorted(increments)
        or set(by_kind.get("return", [])) != expected_returns
    ):
        return None
    identity = {
        "pool_type_usr": pool_parameters[0]["pointee_record_usr"],
        "slot_path": paths["slot_path"],
        "live_path": paths["live_path"],
    }
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
        "role": contract.role,
        "carrier": asdict(carrier),
        "resource_domain": asdict(domain),
        "resource_family": "pool:" + digest(identity),
        "protocol": {
            "kind": "standard_api_effects",
            "family": "single_slot_pool",
            "pool_identity": identity,
            "pool_type": " ".join(declaration[:-1]),
            "storage": "embedded_slot",
            "generation_uniqueness": "unproven",
            **({"return_status": {"success": 1, "failure": 0}} if return_status else {}),
            "transitions": [{"when": applied, "actions": actions}],
        },
        "preconditions": {"op": "true"},
        "effect_cases": [
            {"when": applied, "effect": "applies"},
            {"when": negate(applied), "effect": "no_effect"},
        ],
        "conditions": [],
        "pairs": [],
        "proposed_pairs": [asdict(pair) for pair in contract.pairs],
        "source": "inferred:semantic_modeling",
        "evidence": [
            {"event_id": event["event_id"], "operation": event["event_kind"]}
            for event in events
            if event["event_kind"] in {"assignment", "increment_decrement", "return"}
        ],
        "verification": {
            "method": "source_protocol",
            "compiler_version": CONTRACT_COMPILER_VERSION,
            "source_hash": digest(tokens),
            "effect_strength": "must_under_guard",
            "proof_authority": False,
        },
    }
