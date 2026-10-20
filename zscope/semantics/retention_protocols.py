"""Verify bounded retained-reference effects without inventing ownership rules.

A stored pointer proves retention, not who must eventually release its resource.
Discovery supplies the proposed carrier and slot; current native facts and the
complete implementation must independently agree before effects are published.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import PurePath
import re
from typing import Any, Mapping

from .build_scope import context_build_id, source_scope_problem
from .contract_conditions import compare
from .contracts import (
    ApiContract,
    CONTRACT_COMPILER_VERSION,
    ObjectBinding,
    SymbolIdentity,
    code_tokens,
    digest,
)


def verify_retention_contract(
    raw: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, Any] | None:
    from .contract_compiler import closing, parameter_names, split_tokens

    protocol = raw.get("protocol")
    if not isinstance(protocol, dict) or protocol.get("kind") != "single_slot_retention":
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
    body = bodies[0]
    name = str(context.get("func_name") or "")
    if (
        body.get("fact_version") != "zscope.program-events.v5"
        or body.get("resource_protocol_facts_version") != "zscope.resource-protocol-facts.v1"
        or body.get("owner", {}).get("name") != name
        or not body.get("owner", {}).get("usr")
    ):
        return None
    events = body.get("events") or []
    if not events or any(
        event.get("contains_macro") is not False or event.get("event_kind") == "call"
        for event in events
    ):
        return None
    contract = ApiContract.from_row({"contract": dict(raw), "symbol_name": name})
    if not contract or contract.role not in {"reference_retention", "ownership_transfer"}:
        return None
    carrier, domain = contract.carrier, contract.resource_domain
    if not domain or any(
        binding.kind != "argument" or binding.member_path or binding.address_of
        for binding in (carrier, domain)
    ):
        return None
    parameters = parameter_names(context)
    if any(
        binding.argument_index is None or not 0 <= binding.argument_index < len(parameters)
        for binding in (carrier, domain)
    ):
        return None
    if carrier.argument_index == domain.argument_index:
        return None
    slot_path = str(protocol.get("slot_path") or "")
    if not re.fullmatch(r"->[A-Za-z_]\w*", slot_path):
        return None
    tokens = code_tokens(str(context.get("code") or ""))
    try:
        opening = tokens.index(name) + 1
        end = closing(tokens, opening)
        declarations = split_tokens(tokens[opening + 1 : end])
        for binding in (carrier, domain):
            assert binding.argument_index is not None
            if declarations[binding.argument_index].count("*") != 1:
                return None
        implementation = "".join(tokens[end + 1 :])
        assert domain.argument_index is not None and carrier.argument_index is not None
        slot = parameters[domain.argument_index] + slot_path
        node = parameters[carrier.argument_index]
    except (ValueError, IndexError):
        return None
    # One conditional early return followed by a single pointer store and a
    # distinct success result. Unsupported control flow remains a proposal.
    pattern = (
        r"\{if\((?P<guard>[^(){};]+)\)(?:\{return(?P<braced>-?\d+);\}|return(?P<plain>-?\d+);)"
        + re.escape(slot + "=" + node + ";")
        + r"return(?P<success>-?\d+);\}"
    )
    match = re.fullmatch(pattern, implementation)
    if not match:
        return None
    guard = match["guard"]
    allowed_guards = {slot}
    for parameter in parameters:
        if parameter not in {parameters[domain.argument_index], node}:
            allowed_guards.update({parameter + "||" + slot, slot + "||" + parameter})
    failure, success = int(match["braced"] or match["plain"]), int(match["success"])
    if guard not in allowed_guards or failure == success:
        return None
    stores = [event for event in events if event.get("event_kind") == "assignment"]
    if (
        len(stores) != 1
        or not stores[0].get("event_id")
        or "".join(code_tokens(str(stores[0].get("expression") or ""))) != slot + "=" + node
    ):
        return None
    returns = {
        "".join(code_tokens(str(event.get("expression") or "")))
        for event in events
        if event.get("event_kind") == "return"
    }
    if returns != {"return" + str(failure), "return" + str(success)}:
        return None
    applied = compare({"kind": "return"}, "==", success)
    unchanged = compare({"kind": "return"}, "==", failure)
    slot_binding = ObjectBinding("argument", domain.argument_index, member_path=slot_path)
    return {
        "symbol": asdict(
            SymbolIdentity.from_value(
                {},
                name=name,
                file_path=context.get("file_path"),
                signature=context.get("signature"),
                build_context_id=context_build_id(context),
                # The verified native owner identity of the checked body;
                # consumers pin this exact symbol and reject publications
                # whose USR was blanked or forged.
                usr=body["owner"]["usr"],
            )
        ),
        "role": "reference_retention",
        "carrier": asdict(carrier),
        "resource_domain": asdict(domain),
        "resource_family": "retained_reference",
        "protocol": {
            "kind": "standard_api_effects",
            "family": "single_slot_retention",
            "release_responsibility": "unresolved",
            "transitions": [
                {
                    "when": applied,
                    "actions": [
                        {
                            "kind": "retain_reference",
                            "object": asdict(carrier),
                            "new": asdict(slot_binding),
                        }
                    ],
                },
                {
                    "when": unchanged,
                    "actions": [
                        {
                            "kind": "retention_unchanged",
                            "object": asdict(carrier),
                            "new": asdict(slot_binding),
                        }
                    ],
                },
            ],
        },
        "preconditions": {"op": "true"},
        "effect_cases": [
            {"when": applied, "effect": "applies"},
            {"when": unchanged, "effect": "no_effect"},
        ],
        "conditions": [],
        "pairs": [],
        "source": "inferred:semantic_modeling",
        "evidence": [{"event_id": stores[0].get("event_id"), "operation": "retain_reference"}],
        "verification": {
            "method": "source_protocol",
            "compiler_version": CONTRACT_COMPILER_VERSION,
            "source_hash": digest(tokens),
            "effect_strength": "must_under_guard",
            "proof_authority": False,
        },
    }


def verify_resource_protocol(
    raw: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, Any] | None:
    from .pool_protocols import verify_pool_contract
    from .single_slot_pool import verify_single_slot_pool
    from .refcount_protocols import verify_refcount_contract
    from .handle_protocols import verify_handle_contract

    verified = (
        verify_pool_contract(raw, context)
        or verify_retention_contract(raw, context)
        or verify_single_slot_pool(raw, context)
        or verify_refcount_contract(raw, context)
        or verify_handle_contract(raw, context)
    )
    if verified is not None:
        symbol = verified.get("symbol")
        if isinstance(symbol, dict) and not symbol.get("usr"):
            # The publication funnel stamps the checked body's verified
            # native owner receipt onto checkers that do not embed it
            # themselves; consumers can then pin the exact symbol.  The
            # receipt comes only from the current complete facts — never
            # from the user row or the contract's own claim — and a missing
            # or ambiguous receipt leaves the record name-level.
            from .build_scope import context_symbol_usr

            owner_usr = context_symbol_usr(context)
            if owner_usr:
                verified = {**verified, "symbol": {**symbol, "usr": owner_usr}}
    return verified
