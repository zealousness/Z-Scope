"""Current-build, deterministic wrapper closure independent of project YAML.

Only compiler-backed effects rooted in this build's authorized builtin APIs
enter the closure. Missing bodies and unsupported composition are diagnostics,
not requests to trust a name or declarations that the function has no effects.
"""

from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping

from .contracts import ApiContract, ApiPair, ContractRegistry, SymbolIdentity, code_tokens, digest
from .native_wrappers import NativeWrapper, Unsupported, infer_native_wrapper

AUTOMATIC_VERSION = "zscope.automatic-native-semantics.v1"
AUTOMATIC_SOURCE = "inferred:automatic_native"


def align_project_identities(
    automatic_rows: list[dict[str, Any]], project_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Use one native display identity for an already admitted exact symbol.

    YAML selectors use project-relative paths; native definitions use absolute
    paths. Those are not overloads when both have the same nonempty USR and
    exact BuildContext. This operates only on factory-admitted contracts and
    does not loosen general Registry resolution or unknown-build matching.
    """
    symbols: dict[tuple[str, str], dict[str, Any]] = {}
    for row in automatic_rows:
        symbol = row["symbol"]
        key = (str(symbol.get("build_context_id") or ""), str(symbol.get("usr") or ""))
        if all(key):
            if key in symbols and symbols[key] != symbol:
                raise ValueError("automatic_native_symbol_ambiguous")
            symbols[key] = symbol
    result = deepcopy(project_rows)
    for row in result:
        for symbol in [row["symbol"], *row.get("pairs", [])]:
            if not isinstance(symbol, dict):
                continue
            key = (str(symbol.get("build_context_id") or ""), str(symbol.get("usr") or ""))
            native = symbols.get(key)
            if native and native.get("name") == symbol.get("name"):
                symbol.update(native)
    return result


def configuration_requirements(
    project_rows: list[dict[str, Any]], automatic_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    """Exact effect equivalence only; object coverage is not guard equivalence."""

    def boundary(c: ApiContract) -> tuple[Any, ...]:
        return c.symbol, c.role, c.carrier

    def proposition(c: ApiContract) -> dict[str, Any]:
        value = c.structural()
        # Delegation/evidence identifies a proof, not the effect proposition.
        value.pop("delegates", None)
        value.pop("status", None)
        value["effect_cases"] = sorted(value["effect_cases"], key=digest)
        return value

    automatic = [c for r in automatic_rows if (c := ApiContract.from_row({"contract": r}))]
    rows = []
    for raw in align_project_identities(automatic_rows, project_rows):
        contract = ApiContract.from_row({"contract": raw})
        if contract is None:
            continue
        matches = [c for c in automatic if boundary(c) == boundary(contract)]
        equivalent = any(proposition(c) == proposition(contract) for c in matches)
        differences = (
            sorted(
                {
                    key
                    for c in matches
                    for key, value in proposition(contract).items()
                    if value != proposition(c).get(key)
                }
            )
            if not equivalent
            else []
        )
        rows.append(
            {
                "project_semantics_id": str(
                    contract.verification.get("project_semantics_id") or ""
                ),
                "name": contract.symbol.name,
                "usr": contract.symbol.usr,
                "build_context_id": contract.symbol.build_context_id,
                "role": contract.role,
                "carrier": raw.get("carrier"),
                "status": (
                    "automatically_equivalent"
                    if equivalent
                    else ("boundary_derived_contract_differs" if matches else "automatic_gap")
                ),
                "removal_proven": equivalent,
                "differing_fields": differences,
            }
        )
    return {
        "schema": "zscope.configuration-requirements.v1",
        "rows": rows,
        "minimum_proven": False,
        "scope": "exact_current_contract_equivalence",
        "note": "A derivation gap does not prove a declaration is necessary; native bodies may be analyzed directly. Candidate and consumer ablation is required.",
    }


def _forwarder(context: Mapping[str, Any], registry: ContractRegistry) -> list[dict[str, Any]]:
    """One native direct call with immutable parameter operands and early returns.

    No arbitrary source-only composition is admitted here. Macro expansion,
    local stores, pointer arithmetic, loops, result transformations and opaque
    calls need a richer proof and remain gaps.
    """
    from .contract_compiler import _derive_source_contracts, read_source_facts, split_tokens

    wrapper = NativeWrapper(context, registry)
    wrapper.prepare()
    body = wrapper.body
    events = body["events"]
    calls = {
        (e.get("location", {}).get("offset"), e.get("expression")): e
        for e in events
        if e.get("event_kind") == "call"
    }
    if len(calls) != 1:
        return []
    event = next(iter(calls.values()))
    callee = event.get("callee") or {}
    if not callee.get("usr") or any(
        e.get("contains_macro") and not e.get("null_pointer_constant") for e in events
    ):
        raise Unsupported("forwarder_macro_or_indirect_call")
    if any(e.get("event_kind") not in {"call", "return", "statement"} for e in events):
        raise Unsupported("forwarder_mutation_or_local_state")
    source = str(context.get("code") or "")
    tokens = code_tokens(source[source.find("{") :])
    if set(tokens) & {
        "for",
        "while",
        "do",
        "switch",
        "goto",
        "?",
        "=",
        "++",
        "--",
        "[",
        "->",
        ".",
        "asm",
    }:
        raise Unsupported("forwarder_control_or_object_mapping")
    arguments = ["".join(code_tokens(str(a))) for a in event.get("arguments", [])]
    if any(a not in wrapper.parameters and a not in {"0", "NULL", "nullptr"} for a in arguments):
        raise Unsupported("forwarder_argument_not_parameter")
    # Some static consumers still use complete standard operand positions,
    # not just the contract's primary object. Until all of those positions
    # are explicitly represented, reordered/dropped/defaulted operands are a
    # consumer capability gap, even if the primary carrier can be mapped.
    if arguments != wrapper.parameters:
        raise Unsupported("forwarder_operand_layout_unclosed")

    def signature(value: str) -> tuple[str, list[str]]:
        tokens = code_tokens(value)
        if "(" not in tokens or tokens[-1:] != [")"]:
            raise Unsupported("forwarder_native_signature_missing")
        at = tokens.index("(")
        return "".join(tokens[:at]), ["".join(t) for t in split_tokens(tokens[at + 1 : -1])]

    own_return, own_params = signature(
        str((body.get("callable") or {}).get("canonical_signature") or "")
    )
    target_return, target_params = signature(str(callee.get("canonical_signature") or ""))
    for position, argument in enumerate(arguments):
        if argument not in wrapper.parameters:
            continue
        if position >= len(target_params) or target_params[position] == "...":
            continue
        own_position = wrapper.parameters.index(argument)
        if own_position >= len(own_params):
            raise Unsupported("forwarder_native_signature_incomplete")
        own = own_params[own_position]
        target = target_params[position]
        if own != target and not ("*" in own and "*" in target):
            raise Unsupported("forwarder_argument_conversion_unclosed")
    bases = wrapper.registry.find_for_call(str(callee.get("name") or ""), usr=str(callee["usr"]))
    if not bases or any(not c.effects_trusted for c in bases):
        raise Unsupported("forwarder_callee_unresolved")
    if (
        any(c.source == "builtin_defaults" for c in bases)
        and callee.get("has_definition")
        and not callee.get("is_system_header")
    ):
        raise Unsupported("project_shadows_standard")
    facts = read_source_facts(context, registry.for_context(context))
    if not facts.complete or len(facts.calls) != 1 or facts.unknown_calls or facts.assignments:
        raise Unsupported("forwarder_source_mapping_unclosed")
    call = facts.calls[0]
    if (
        call.result == "$return"
        and own_return != target_return
        and not ("*" in own_return and "*" in target_return)
    ):
        raise Unsupported("forwarder_return_conversion_unclosed")
    if call.name != callee.get("name") or call.arguments != list(event.get("arguments", [])):
        # Formatting differences are harmless; actual operands must be equal.
        if (
            call.name != callee.get("name")
            or ["".join(code_tokens(a)) for a in call.arguments] != arguments
        ):
            raise Unsupported("forwarder_source_native_call_conflict")
    # Returning an expression that contains a call is not returning its value.
    from .contract_compiler import unparen

    for returned in events:
        if returned.get("event_kind") != "return":
            continue
        expression = code_tokens(str(returned.get("expression") or ""))
        if callee.get("name") in expression and unparen(expression[1:]) != code_tokens(
            str(event.get("expression"))
        ):
            raise Unsupported("forwarder_result_transformed")

    def unobservable(value: Any) -> bool:
        if isinstance(value, dict):
            return (
                value.get("op") == "unknown"
                or value.get("kind") in {"unknown", "call_result"}
                or any(unobservable(v) for v in value.values())
            )
        return isinstance(value, list) and any(unobservable(v) for v in value)

    result = []
    for raw in _derive_source_contracts(context, registry):
        if raw.get("role") in {"allocator", "calloc", "reallocator", "deallocator"}:
            # Resource failures never fall back to source-token authority.
            continue
        parsed = ApiContract.from_row({"contract": raw})
        if not parsed or not parsed.effects_trusted:
            continue
        # A hidden status cannot authorize lock/unlock/close success. Unknown
        # predicates stay investigation gaps rather than automatic effects.
        if unobservable(raw.get("effect_cases")):
            continue
        raw["verification"].update(
            checker="native_transparent_forwarder.v1", native_input_hash=digest(body)
        )
        raw["evidence"].append(
            {
                "function_usr": body["owner"]["usr"],
                "build_context_id": wrapper.build,
                "native_input_hash": digest(body),
            }
        )
        result.append(raw)
    return result


def derive_automatic_contracts(
    contexts: Mapping[str, Mapping[str, Any]], registry: ContractRegistry
) -> dict[str, Any]:
    """Compute a dependency worklist once per exact build; no model calls."""
    from .contract_review import proof_key

    registry = deepcopy(registry)
    # Project declarations are deliberately not seeds. This measures what can
    # be omitted from configuration, not what a configured assumption implies.
    registry.contracts = [c for c in registry.contracts if c.source == "builtin_defaults"]
    registry.pairs = [p for p in registry.pairs if p.source == "builtin_defaults"]
    dependents: dict[str, set[str]] = defaultdict(set)
    for usr, context in contexts.items():
        for body in (context.get("program_facts") or {}).get("functions", []):
            for event in body.get("events", []):
                if event.get("event_kind") == "call":
                    dependents[str((event.get("callee") or {}).get("usr") or "")].add(usr)
    queue = deque(sorted(contexts))
    queued = set(queue)
    contracts: dict[str, dict[str, Any]] = {}
    units: dict[str, dict[str, Any]] = {}
    attempts = 0
    while queue:
        usr = queue.popleft()
        queued.remove(usr)
        context = contexts[usr]
        attempts += 1
        native = infer_native_wrapper(context, registry)
        rows = [
            r
            for r in native["contracts"]
            if r["verification"]["checker"] == "native_wrapper_value_flow.v2"
        ]
        reasons = list(native["reasons"])
        try:
            rows.extend(_forwarder(context, registry))
        except Unsupported as exc:
            reasons.append(str(exc))
        added = False
        known = {proof_key(c) for c in registry.contracts if c.effects_trusted}
        accepted = []
        for raw in rows:
            raw = deepcopy(raw)
            raw["source"] = AUTOMATIC_SOURCE
            verification = raw["verification"]
            dependencies = set(verification.get("proof_dependencies", []))
            symbol = raw["symbol"]
            if (
                symbol.get("usr") != usr
                or symbol.get("build_context_id") != registry.build_context_id
                or not dependencies
                or not dependencies <= known
                or not verification.get("native_input_hash")
            ):
                reasons.append("automatic_dependency_or_identity_unclosed")
                continue
            verification.update(
                automatic_version=AUTOMATIC_VERSION,
                identity_verified=True,
                authority="native_current",
            )
            parsed = ApiContract.from_row({"contract": raw})
            if not parsed or not parsed.effects_trusted:
                continue
            key = proof_key(parsed)
            accepted.append(key)
            if key in contracts:
                continue
            contracts[key] = raw
            registry.add(parsed)
            known.add(key)
            added = True
        units[usr] = {
            "usr": usr,
            "name": str(context.get("func_name") or ""),
            "build_context_id": registry.build_context_id,
            "contract_keys": sorted(set(accepted)),
            "status": "derived" if accepted else "not_derived",
            "reasons": sorted(set(reasons)) if not accepted else [],
        }
        if added:
            for caller in sorted(dependents[usr] - queued):
                queue.append(caller)
                queued.add(caller)
    return {
        "schema": AUTOMATIC_VERSION,
        "contracts": [contracts[k] for k in sorted(contracts)],
        "units": [units[k] for k in sorted(units)],
        "derivation_attempts": attempts,
        "llm_calls": 0,
        "scope": "same_exact_build_native_bodies",
        "complete_coverage_proven": False,
    }


def derive_build_payload(scoped_index: Any, payload: Mapping[str, Any]) -> dict[str, Any]:
    """Called only by the snapshot factory after current-build admission."""
    from ..core.candidates.function_facts import function_source_fragment
    from ..retrieval.build_context import program_facts_result

    build = scoped_index.scope.build_context_id
    registry = ContractRegistry(build_context_id=build)
    registry.shadowed_symbols = set(payload["shadowed_symbols"])
    for raw in payload["contracts"]:
        contract = ApiContract.from_row({"contract": raw})
        if contract and contract.symbol.name not in registry.shadowed_symbols:
            registry.add(contract)
    for raw in payload["pairs"]:
        acquire, release = SymbolIdentity.from_value(raw["acquire"]), SymbolIdentity.from_value(
            raw["release"]
        )
        if not ({acquire.name, release.name} & registry.shadowed_symbols):
            registry.pairs.append(ApiPair(acquire, release, source="builtin_defaults"))
    bodies: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for body in scoped_index._context_rows(("program_function",)):
        usr = str((body.get("owner") or {}).get("usr") or "")
        if usr:
            bodies[usr].append(body)
    contexts = {}
    gaps = []
    sources: dict[Path, str] = {}
    for usr, rows in bodies.items():
        if len(rows) != 1 or not rows[0].get("complete"):
            gaps.append({"usr": usr, "reason": "automatic_native_body_ambiguous_or_incomplete"})
            continue
        body = rows[0]
        owner = body.get("owner") or {}
        code, _, _ = function_source_fragment(body, source_cache=sources)
        if not code:
            gaps.append({"usr": usr, "reason": "automatic_current_source_unavailable"})
            continue
        facts = program_facts_result([body])
        facts.update(
            build_context_id=build, function_identity={"usr": usr, "build_context_id": build}
        )
        contexts[usr] = {
            "func_name": owner.get("name"),
            "file_path": owner.get("file"),
            "code": code,
            "signature": (body.get("callable") or {}).get("canonical_signature", ""),
            "program_facts": facts,
        }
    result = derive_automatic_contracts(contexts, registry)
    result["inventory_gaps"] = gaps or (
        [] if bodies else [{"reason": "automatic_native_inventory_unavailable"}]
    )
    return result
