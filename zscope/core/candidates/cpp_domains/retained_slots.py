"""Bounded, native-backed observations of retained pointer slot teardown.

This is an intraprocedural summary, not ownership or lifetime proof. In
particular a call of a pool-return API need not satisfy its membership/live
guard, and an entry slot value has no established allocation generation.
"""

from __future__ import annotations

from pathlib import PurePath
import re
from typing import Any, Mapping

from ....semantics.build_scope import bind_build_scope, context_build_id, source_scope_problem
from ....semantics.contracts import ContractRegistry, code_tokens, digest


def _compact(value: Any) -> str:
    return "".join(code_tokens(str(value or "")))


def retained_slot_teardown(
    context: Mapping[str, Any], registry: ContractRegistry
) -> dict[str, Any] | None:
    """Recognize one guarded return of a struct parameter's pointer slot.

    Supported bodies contain only a slot read (optionally copied to a local),
    one non-null guard, one verified single-slot-pool return call, and optional
    slot clearing. Full-body matching rejects loops, extra calls, conditional
    resets and reassignment. An unrecognized body is unknown, never safe.
    """
    from ....semantics.contract_compiler import closing

    facts = context.get("program_facts") or {}
    bodies = facts.get("functions") or []
    build = context_build_id(context)
    name = str(context.get("func_name") or "")
    if (
        source_scope_problem(context)
        or PurePath(str(context.get("file_path") or "")).suffix != ".c"
        or not build
        or not facts.get("complete")
        or len(bodies) != 1
    ):
        return None
    body = bodies[0]
    if (
        not body.get("complete")
        or body.get("fact_version") != "zscope.program-events.v7"
        or body.get("resource_protocol_facts_version") != "zscope.resource-protocol-facts.v1"
        or body.get("owner", {}).get("name") != name
        or not body.get("owner", {}).get("usr")
    ):
        return None
    events = body.get("events") or []
    if (
        not events
        or any(not event.get("event_id") for event in events)
        or len({event["event_id"] for event in events}) != len(events)
    ):
        return None
    calls = [event for event in events if event.get("event_kind") == "call"]
    if len(calls) != 1:
        return None
    call = calls[0]
    callee = call.get("callee") or {}
    callee_file = str((callee.get("declaration") or {}).get("file") or "")
    if not callee.get("usr") or callee_file != str(context.get("file_path") or "").replace(
        "\\", "/"
    ):
        return None
    with bind_build_scope(context):
        # The callee's native USR is verified above; only a publication pinned
        # to that exact identity may grant the release effect.
        contracts = registry.find_for_call(
            str(callee.get("name") or ""), file_path=callee_file, usr=str(callee.get("usr") or "")
        )
    # Resolve identity before role. A trusted row among competing effects is
    # insufficient; no unscoped/manual assumption is promoted to native fact.
    if len(contracts) != 1:
        return None
    contract = contracts[0]
    if (
        contract.role != "deallocator"
        or contract.status != "active"
        or not contract.effects_trusted
        or contract.verification.get("method") != "source_protocol"
        or contract.protocol.get("family") != "single_slot_pool"
        or contract.symbol.build_context_id != build
        or contract.symbol.file_path != callee_file
        or contract.carrier.kind != "argument"
        or contract.carrier.member_path
        or contract.carrier.address_of
        or contract.resource_domain is None
    ):
        return None
    args = [_compact(value) for value in call.get("arguments") or []]
    carrier_index = contract.carrier.argument_index
    if carrier_index is None or not 0 <= carrier_index < len(args):
        return None
    obj = args[carrier_index]
    domain = contract.resource_domain.resolve(args)
    parameters = {p.get("name"): p for p in body.get("parameters") or []}
    pool = parameters.get(domain, {})
    if (
        pool.get("pointee_record_kind") != "struct"
        or not pool.get("usr")
        or not pool.get("pointee_record_usr")
        or pool.get("pointee_record_usr")
        != contract.protocol.get("pool_identity", {}).get("pool_type_usr")
    ):
        return None
    initializers = [e for e in events if e.get("event_kind") == "declaration_initializer"]
    slot = obj
    prefix = ""
    read_event = call
    if re.fullmatch(r"[A-Za-z_]\w*", obj):
        if len(initializers) != 1:
            return None
        read_event = initializers[0]
        slot = _compact(read_event.get("assignment_value"))
        if _compact(read_event.get("assignment_target")) != obj:
            return None
        prefix = _compact(read_event.get("expression"))
        if not re.fullmatch(
            r"(?:struct)?[A-Za-z_]\w*\*" + re.escape(obj + "=" + slot + ";"), prefix
        ):
            return None
        # Native USRs, not local spelling, connect the copy to the call.
        definitions = read_event.get("defs") or []
        arguments = call.get("argument_objects") or []
        if (
            len(definitions) != 1
            or not definitions[0].get("usr")
            or len(arguments) <= carrier_index
            or arguments[carrier_index].get("usr") != definitions[0]["usr"]
        ):
            return None
    elif initializers:
        return None
    match = re.fullmatch(r"(?P<receiver>[A-Za-z_]\w*)->(?P<field>[A-Za-z_]\w*)", slot)
    if not match:
        return None
    receiver = parameters.get(match["receiver"], {})
    if (
        receiver.get("pointee_record_kind") != "struct"
        or not receiver.get("usr")
        or not receiver.get("pointee_record_usr")
        or receiver.get("usr") == pool.get("usr")
    ):
        return None
    fields = [
        value
        for value in read_event.get("uses") or []
        if value.get("value_kind") == "field" and _compact(value.get("expression")) == slot
    ]
    if len(fields) != 1 or not fields[0].get("usr"):
        return None
    call_text = str(callee["name"]) + "(" + ",".join(args) + ")"
    if _compact(call.get("expression")) != call_text:
        return None
    stores = [event for event in events if event.get("event_kind") == "assignment"]
    if len(stores) > 1:
        return None
    clear = ""
    if stores:
        store = stores[0]
        # assignment_value is the compiler-expanded RHS, so a user #define
        # NULL ((void*)8) cannot masquerade as a detach. The LHS is checked
        # independently; nested field macros cannot redirect the cleared slot.
        if (
            _compact(store.get("assignment_target")) != slot
            or _compact(store.get("assignment_value")) not in {"0", "((void*)0)"}
            or _compact(store.get("expression")) not in {slot + "=NULL", slot + "=0"}
            or len(store.get("defs") or []) != 1
            or store["defs"][0].get("usr") != fields[0]["usr"]
        ):
            return None
        clear = _compact(store["expression"]) + ";"
    for event in events:
        kind = event.get("event_kind")
        if kind not in {"call", "assignment", "declaration_initializer", "statement"}:
            return None
        if event.get("contains_macro") is not False and event not in stores:
            return None
        if kind == "statement" and _compact(event.get("expression")) != obj:
            return None
    tokens = code_tokens(str(context.get("code") or ""))
    try:
        opening = tokens.index(name) + 1
        end = closing(tokens, opening)
        implementation = "".join(tokens[end + 1 :])
    except (ValueError, IndexError):
        return None
    guarded = "if(" + obj + ")"
    shapes = {
        "{" + prefix + guarded + call_text + ";" + clear + "}": "after_release",
        "{" + prefix + guarded + "{" + call_text + ";" + clear + "}}": "after_release",
    }
    if prefix and clear:
        shapes.update(
            {
                "{" + prefix + clear + guarded + call_text + ";}": "before_release",
                "{" + prefix + clear + guarded + "{" + call_text + ";}}": "before_release",
            }
        )
    if implementation not in shapes:
        return None
    edges = body.get("cfg_edges") or []
    guard_edges = [edge for edge in edges if edge.get("condition")]
    if (
        len(guard_edges) != 2
        or any(_compact(edge.get("condition")) != obj for edge in guard_edges)
        or not any(
            e.get("branch") == "true" and e.get("to") == call.get("block") for e in guard_edges
        )
        or not any(e.get("branch") == "false" for e in guard_edges)
    ):
        return None
    return {
        "schema": "zscope.retained-slot-teardown.v1",
        "build_context_id": build,
        "function_usr": body["owner"]["usr"],
        "source_hash": digest(tokens),
        "receiver_usr": receiver["usr"],
        "receiver_type_usr": receiver["pointee_record_usr"],
        "slot_field_usr": fields[0]["usr"],
        "slot": slot,
        "object": obj,
        "object_origin": "entry_slot_value",
        "allocation_site": "unknown",
        "generation": "unknown",
        "resource_domain": domain,
        "resource_domain_usr": pool["usr"],
        "resource_family": contract.resource_family,
        "release_contract": contract.to_dict(),
        "release_applicability": "unknown",
        "release_event": dict(call),
        "local_guard_edges": guard_edges,
        "read_event_id": read_event["event_id"],
        "detach_event_id": stores[0]["event_id"] if stores else "",
        "detach_order": shapes[implementation] if clear else "absent",
        "slot_at_exit": "null" if clear else "entry_value",
        "proof_authority": False,
        "scope": "local_slot_only",
    }
