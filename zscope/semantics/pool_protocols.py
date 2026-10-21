"""Implementation checks for LLM-proposed pool primitives.

Discovery belongs to the modeler. This verifier recognizes a deliberately
bounded intrusive free-list protocol; unsupported implementations retain their
proposal and diagnostics and require an explicit project contract. No function
or field spelling is a semantic seed.
"""

from __future__ import annotations

from dataclasses import asdict
import re
from typing import Any, Mapping

from .contract_conditions import compare
from .contracts import ApiContract, CONTRACT_COMPILER_VERSION, SymbolIdentity, code_tokens, digest


def verify_pool_contract(
    raw: Mapping[str, Any], context: Mapping[str, Any]
) -> dict[str, Any] | None:
    from .contract_compiler import closing, parameter_names, split_tokens
    from .build_scope import context_build_id, source_scope_problem

    if source_scope_problem(context):
        return None

    protocol = raw.get("protocol")
    if not isinstance(protocol, dict) or protocol.get("kind") != "intrusive_freelist":
        return None
    contract = ApiContract.from_row(
        {"contract": dict(raw), "symbol_name": context.get("func_name")}
    )
    if not contract or contract.role not in {"allocator", "deallocator", "ownership_transfer"}:
        return None
    domain = contract.resource_domain
    if not domain or domain.kind != "argument" or domain.address_of or domain.member_path:
        return None
    parameters = parameter_names(context)
    if domain.argument_index is None or domain.argument_index >= len(parameters):
        return None
    head, link = str(protocol.get("head_path", "")), str(protocol.get("link_path", ""))
    if not all(re.fullmatch(r"->[A-Za-z_]\w*", path) for path in (head, link)):
        return None
    tokens = code_tokens(str(context.get("code") or ""))
    name = str(context.get("func_name") or "")
    try:
        opening = tokens.index(name) + 1
        end = closing(tokens, opening)
        declarations = split_tokens(tokens[opening + 1 : end])
        declaration = declarations[domain.argument_index]
        # The pool's declared type is part of the protocol, separate from the
        # actual pool object supplied at each call. Never unite unrelated types.
        pool_type = " ".join(declaration[:-1])
        if declaration[-1] != parameters[domain.argument_index] or "*" not in declaration:
            return None
        body = "".join(tokens[end + 1 :])
    except (ValueError, IndexError):
        return None
    if not body.startswith("{") or not body.endswith("}"):
        return None
    body = body[1:-1]
    pool = parameters[domain.argument_index]
    slot = pool + head
    carrier = contract.carrier
    # The proposed protocol selects this verifier; the complete implementation
    # and carrier establish whether this is a pop or a return-to-pool push.
    role = "allocator" if carrier.kind == "return" else "deallocator"
    if role == "allocator":
        if carrier.kind != "return" or carrier.member_path or carrier.address_of:
            return None
        # Bind the local result from the actual assignment, not proposal prose.
        match = re.match(
            r"(?:struct)?[A-Za-z_]\w*\*+(?P<node>[A-Za-z_]\w*)=" + re.escape(slot) + ";", body
        )
        if not match:
            return None
        node = match["node"]
        if node in parameters:
            return None
        tail = body[match.end() :]
        update = slot + "=" + node + link + ";"
        ret = "return" + node + ";"
        positive = (node, node + "!=NULL", node + "!=0", node + "!=nullptr")
        negative = ("!" + node, node + "==NULL", node + "==0", node + "==nullptr")
        legal = {"if(" + cond + "){" + update + "}" + ret for cond in positive}
        legal |= {"if(" + cond + ")" + update + ret for cond in positive}
        legal |= {
            "if(" + cond + ")return" + null + ";" + update + ret
            for cond in negative
            for null in ("NULL", "0", "nullptr")
        }
        legal |= {
            "if(" + cond + "){return" + null + ";}" + update + ret
            for cond in negative
            for null in ("NULL", "0", "nullptr")
        }
        if tail not in legal:
            return None
        cases = [
            {"when": compare({"kind": "return"}, "!=", None), "effect": "applies"},
            {"when": compare({"kind": "return"}, "==", None), "effect": "no_effect"},
        ]
    else:
        if carrier.kind != "argument" or carrier.member_path or carrier.address_of:
            return None
        if carrier.argument_index is None or carrier.argument_index >= len(parameters):
            return None
        node = parameters[carrier.argument_index]
        if node == pool:
            return None
        update = node + link + "=" + slot + ";" + slot + "=" + node + ";"
        unguarded = {update, update + "return;"}
        guarded = {
            "if(" + cond + "){" + update + "}" for cond in (node, node + "!=NULL", node + "!=0")
        }
        if body not in unguarded | guarded:
            return None
        cases = [
            {
                "when": compare({"kind": "argument", "index": carrier.argument_index}, "!=", None),
                "effect": "applies",
            }
        ]
    protocol = {
        "kind": "intrusive_freelist",
        "pool_type": pool_type,
        "head_path": head,
        "link_path": link,
    }
    return {
        "symbol": asdict(
            SymbolIdentity.from_value(
                {},
                name=name,
                file_path=context.get("file_path"),
                signature=context.get("signature"),
                symbol_type="function",
                build_context_id=context_build_id(context),
            )
        ),
        "role": role,
        "carrier": asdict(carrier),
        "resource_domain": asdict(domain),
        "resource_family": "pool:" + digest(protocol),
        "protocol": protocol,
        "preconditions": {"op": "true"},
        "effect_cases": cases,
        "conditions": [],
        # Proposed names only drive counterpart discovery. Pair publication
        # separately requires matching verified protocols (or a manual edge).
        "pairs": [],
        "proposed_pairs": [asdict(p) for p in contract.pairs],
        "source": "inferred:semantic_modeling",
        "confidence": 1.0,
        "evidence": [
            {
                "source_index": context.get("index_name"),
                "operation": "freelist_pop" if role == "allocator" else "freelist_push",
            }
        ],
        "verification": {
            "method": "source_protocol",
            "compiler_version": CONTRACT_COMPILER_VERSION,
            "source_hash": digest(tokens),
            "effect_strength": "must_under_guard",
            "proof_authority": False,
        },
    }


def pool_pair_compatible(acquire: ApiContract, release: ApiContract) -> bool:
    """Compatibility of logical return obligations, never heap destruction."""
    same_protocol = (
        acquire.protocol.get("kind") == "intrusive_freelist"
        and acquire.protocol == release.protocol
    ) or (
        acquire.protocol.get("kind") == release.protocol.get("kind") == "standard_api_effects"
        and acquire.protocol.get("family") == release.protocol.get("family") == "single_slot_pool"
        and bool(acquire.protocol.get("pool_identity"))
        and acquire.protocol.get("pool_identity") == release.protocol.get("pool_identity")
    )
    return bool(
        acquire.symbol.build_context_id == release.symbol.build_context_id
        and acquire.effects_trusted
        and release.effects_trusted
        and acquire.source.startswith("inferred")
        and release.source.startswith("inferred")
        and not acquire.verification.get("assumptions")
        and not release.verification.get("assumptions")
        and acquire.role == "allocator"
        and release.role == "deallocator"
        and same_protocol
        and acquire.resource_family == release.resource_family
        and acquire.resource_domain
        and release.resource_domain
    )
