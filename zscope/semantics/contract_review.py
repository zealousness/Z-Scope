"""Reduce manual review to unsupported proof roots, never guessed wrappers."""

from __future__ import annotations

from dataclasses import asdict
from itertools import combinations
from typing import Any, Iterable, Mapping

from .contracts import ApiContract, ContractRegistry, digest


def proof_key(contract: ApiContract) -> str:
    specification = contract.structural()
    # Confirmation changes authority/status, never the proposition being
    # confirmed. Different pools, conditions or protocols are different roots.
    specification.pop("effect_authority", None)
    specification.pop("status", None)
    return digest(specification)


def review_roots(
    snapshots: Iterable[Mapping[str, Any]], registry: ContractRegistry
) -> dict[str, Any]:
    nodes: dict[str, ApiContract] = {}
    alternatives: dict[str, list[set[str]]] = {}
    for snapshot in snapshots:
        for raw in snapshot.get("interface_contracts", []):
            contract = ApiContract.from_row({"contract": raw})
            if contract:
                key = proof_key(contract)
                nodes[key] = contract
                verification = contract.verification
                if verification.get("mapping_verified") and verification.get("proof_dependencies"):
                    alternatives.setdefault(key, []).append(set(verification["proof_dependencies"]))
    known = {proof_key(c) for c in registry.contracts if c.effects_trusted}
    known.update(k for k, c in nodes.items() if c.effects_trusted)

    def closure(seeds: set[str]) -> set[str]:
        result = set(seeds)
        while True:
            added = {
                key for key, paths in alternatives.items() if any(path <= result for path in paths)
            } - result
            if not added:
                return result
            result.update(added)

    known = closure(known)
    roots = set(nodes) - known - set(alternatives)
    pending = set(nodes) - known
    coverable = closure(known | roots) - known
    # Separate independent proof components before minimizing confirmations.
    # Hyperedges retain conjunctions: confirming one of two required roots
    # cannot be advertised as unlocking their dependent wrapper.
    adjacency: dict[str, set[str]] = {k: set() for k in pending}
    for key, paths in alternatives.items():
        for path in paths:
            for dependency in path - known:
                adjacency.setdefault(key, set()).add(dependency)
                adjacency.setdefault(dependency, set()).add(key)
    components: list[set[str]] = []
    remaining = set(pending)
    while remaining:
        component, stack = set(), [min(remaining)]
        while stack:
            key = stack.pop()
            if key not in component:
                component.add(key)
                stack.extend(adjacency.get(key, set()) - component)
        remaining -= component
        components.append(component)
    selected: list[str] = []
    minimization: list[dict[str, Any]] = []
    for component in components:
        candidates = sorted(roots & component)
        target = coverable & component
        if not candidates:
            continue
        chosen: set[str] = set()
        while not target <= closure(known | chosen):
            pick = max(
                (k for k in candidates if k not in chosen),
                key=lambda k: (len(closure(known | chosen | {k}) & target), k),
            )
            chosen.add(pick)
        for key in sorted(chosen, reverse=True):
            if target <= closure(known | (chosen - {key})):
                chosen.remove(key)
        attempts, exact = 0, True
        for size in range(len(chosen)):
            found = None
            for subset in combinations(candidates, size):
                attempts += 1
                if attempts > 50000:
                    exact = False
                    break
                if target <= closure(known | set(subset)):
                    found = set(subset)
                    break
            if not exact:
                break
            if found is not None:
                chosen = found
                break
        selected.extend(sorted(chosen))
        minimization.append(
            {
                "roots": candidates,
                "selected": sorted(chosen),
                "coverable_propositions": len(target),
                "search_states": attempts,
                "minimum_proven": exact,
            }
        )
    covered = closure(known | set(selected))
    graph_minimum = all(c["minimum_proven"] for c in minimization) and pending <= covered
    minimum = graph_minimum and all(
        c.verification.get("proof_dependencies_complete") for k, c in nodes.items() if k in pending
    )
    rows = []
    for key in selected:
        contract = nodes[key]
        affected = closure(known | {key}) - known - {key}
        rows.append(
            {
                "review_id": key,
                "symbol_name": contract.symbol.name,
                "file_path": contract.symbol.file_path,
                "signature": contract.symbol.signature,
                "kind": contract.role,
                "symbol_type": contract.symbol.symbol_type,
                "contract": contract.to_dict(),
                "pair": [asdict(p) for p in contract.pairs],
                "status": "pending",
                "source": "inferred:contract_review",
                "source_evidence": contract.evidence,
                "affected_interfaces": sorted(
                    {nodes[k].symbol.name for k in affected if k in nodes}
                ),
                "pending_conditions": contract.effect_cases or contract.conditions,
                "minimum_proven": minimum,
                "graph_minimum_proven": graph_minimum,
                "minimum_scope": "provided_verified_proof_graph",
                "notes": "Confirm the interface specification only; runtime success remains conditional.",
            }
        )
    return {
        "rows": rows,
        "verified": sorted(known),
        "proof_dependencies": {k: [sorted(p) for p in paths] for k, paths in alternatives.items()},
        "unresolved_cycles": sorted(pending - covered),
        "unresolved_dependencies": sorted(
            {d for paths in alternatives.values() for p in paths for d in p} - set(nodes) - known
        ),
        "minimization": minimization,
        "minimum_scope": "provided_verified_proof_graph",
        "graph_minimum_proven": graph_minimum,
        "minimum_proven": minimum,
        "selected_proposition_count": len(selected),
        "selected_symbol_count": len({nodes[k].symbol for k in selected}),
        "derived_proposition_count": len(covered - known - set(selected)),
    }
