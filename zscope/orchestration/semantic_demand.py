"""Advisory pre-model demand planning; never authorizes skipping or safety."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping, Sequence

from ..semantics.contract_compiler import read_source_facts
from ..semantics.contracts import ContractRegistry, SymbolIdentity, code_tokens, digest
from ..semantics.security_map import AuditUnit, SecuritySemanticMap

SCHEMA = "zscope.semantic-demand.shadow.v1"
HINT_KINDS = frozenset(
    {
        "candidate_missing_facts",
        "opaque_interface",
        "unknown_callback",
        "unknown_alias",
        "document_conflict",
        "coverage_gap",
    }
)


def source_hash(context: Mapping[str, Any]) -> str:
    return hashlib.sha256(str(context.get("code") or "").encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SemanticDemandHint:
    """Caller-supplied advisory gap, bound to an existing symbol and source.

    Details identify missing facts, not executable instructions or proof. A
    stale hint remains an unknown audit item and cannot bind by bare name.
    """

    symbol: SymbolIdentity
    source_hash: str
    kind: str
    details: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in HINT_KINDS:
            raise ValueError("unsupported semantic demand hint")
        if (
            not isinstance(self.symbol, SymbolIdentity)
            or not self.symbol.file_path
            or not isinstance(self.source_hash, str)
            or not re.fullmatch(r"[0-9a-f]{64}", self.source_hash)
        ):
            raise ValueError("semantic demand hints require a source identity")
        if not isinstance(self.details, tuple) or any(
            not isinstance(value, str) for value in self.details
        ):
            raise ValueError("semantic demand details must be immutable strings")


def plan_semantic_demand(
    *,
    contexts: Mapping[str, Mapping[str, Any]],
    children: Mapping[str, set[str]],
    components: Sequence[Sequence[str]],
    registry: ContractRegistry,
    spec: str,
    hints: Sequence[SemanticDemandHint] = (),
    security_map: SecuritySemanticMap | None = None,
    audit_units: Sequence[AuditUnit] = (),
    unavailable: Sequence[str] = (),
    graph_truncated: bool = False,
) -> dict[str, Any]:
    """Produce a deterministic detached audit view without I/O or model calls.

    All opaque calls are conservatively considered interesting, including ones
    whose security role has not been learned yet. Names do not assign roles.
    Source-parser coverage is explicitly partial; it is not alias analysis.
    D03 coverage is supplemental and never establishes a current build binding.
    """
    reasons: dict[str, set[str]] = {key: set() for key in contexts}
    unknowns: dict[str, set[str]] = {key: set() for key in contexts}
    unbound: list[dict[str, Any]] = []
    coverage: dict[str, list[dict[str, Any]]] = {key: [] for key in contexts}
    for key, context in contexts.items():
        try:
            facts = read_source_facts(context, registry)
            if facts.unknown_calls:
                reasons[key].add("opaque_interface")
            if "<indirect>" in facts.unknown_calls:
                reasons[key].add("unknown_callback")
            # Dereferences/member/index expressions require object/alias facts
            # beyond this source parser. This is a conservative syntax hint,
            # never an alias relation or a defect classification.
            tokens = code_tokens(str(context.get("code") or ""))
            if any(value is None for value in facts.aliases.values()) or any(
                token in {"*", "->", "["} for token in tokens
            ):
                reasons[key].add("unknown_alias")
            if not facts.complete:
                reasons[key].add("source_coverage_gap")
                unknowns[key].add("source_parser_incomplete")
        except (ValueError, TypeError, IndexError, KeyError, RecursionError):
            reasons[key].add("source_coverage_gap")
            unknowns[key].add("source_parser_unavailable")
        if context.get("unresolved_callees") or any(
            row.get("status") == "external_model_missing"
            for row in context.get("external_model_dependencies", [])
            if isinstance(row, dict)
        ):
            reasons[key].add("opaque_interface")
        for row in context.get("project_callees", []):
            if isinstance(row, dict) and "indirect" in (row.get("call_type") or []):
                reasons[key].add("unknown_callback")
        if context.get("source_truncated") or any(
            value for name, value in context.items() if name.endswith("_truncation")
        ):
            reasons[key].add("coverage_gap")
            unknowns[key].add("input_truncated")
        program = context.get("program_facts")
        if not isinstance(program, dict) or not program.get("complete"):
            # Missing backend coverage alone does not select the whole graph,
            # but every unselected row remains unknown, never safe.
            unknowns[key].add("program_coverage_unavailable")
        if graph_truncated:
            reasons[key].add("coverage_gap")
            unknowns[key].add("call_graph_truncated")

    for hint in hints:
        key = hint.symbol.key
        if key not in contexts or hint.source_hash != source_hash(contexts[key]):
            unbound.append({"symbol": key, "reason": "stale_or_unbound_hint", "kind": hint.kind})
            continue
        reasons[key].add(hint.kind)

    if security_map is not None:
        records = {record.function_uid: record for record in security_map.functions}
        for unit in audit_units or security_map.audit_units:
            for item in unit.coverage_keys:
                record = records.get(item.function_uid)
                key = (
                    SymbolIdentity.from_value(
                        {
                            "name": record.function_name,
                            "file_path": record.file_path,
                            "signature": record.signature,
                        }
                    ).key
                    if record is not None
                    else ""
                )
                row = {
                    "unit_id": unit.unit_id,
                    "unit_fingerprint": unit.fingerprint,
                    "key": item.to_dict(),
                    "identity": item.identity(),
                    "occurrences": [occ.to_dict() for occ in unit.occurrences],
                    "migration_status": unit.migration_status,
                    "authority": "advisory_only",
                    "map_project_id": security_map.project_id,
                    "map_revision": security_map.revision,
                    "current_project_revision_build": "unverified",
                }
                if (
                    record is None
                    or key not in contexts
                    or record.code_hash != source_hash(contexts[key])
                    or unit.migration_status != "current"
                    or security_map.migration_status != "current"
                ):
                    unbound.append({**row, "reason": "stale_or_unbound_coverage"})
                    continue
                coverage[key].append(row)
                unknowns[key].add("supplemental_context_unverified")
                if unit.unknown_refs or unit.candidate_desert:
                    reasons[key].add("audit_coverage_gap")
                if item.build_context is None:
                    unknowns[key].add("build_context_unknown")
                if item.object_ref is None:
                    unknowns[key].add("object_identity_unknown")

    # Use the scheduler's components, not a parallel SCC implementation. Take
    # dependency closure too: a selected interface may require a callee contract.
    selected = {key for key, values in reasons.items() if values}
    changed = True
    while changed:
        previous = set(selected)
        for members in components:
            if selected.intersection(members):
                for key in members:
                    if key in contexts and key not in selected:
                        selected.add(key)
                        reasons[key].add("scc_closure")
        for key in sorted(selected):
            for child in sorted(children.get(key, set())):
                if child in contexts and child not in selected:
                    selected.add(child)
                    reasons[child].add("callee_dependency")
        changed = previous != selected

    rows = []
    for key in sorted(contexts):
        rows.append(
            {
                "symbol": key,
                "source_hash": source_hash(contexts[key]),
                "context_fingerprint": digest(contexts[key]),
                "modeling_spec": spec,
                "decision": "selected" if key in selected else "deferred",
                "reasons": sorted(reasons[key]) or ["no_observed_demand"],
                "unknowns": sorted(unknowns[key]),
                "semantic_status": "unknown",
                "safety_status": "unknown",
                "execution": "unchanged_full_schedule",
                "coverage": sorted(
                    coverage[key], key=lambda row: (row["identity"], row["unit_id"])
                ),
            }
        )
    unbound.extend({"symbol": key, "reason": "model_input_unavailable"} for key in unavailable)
    return {
        "schema_version": SCHEMA,
        "mode": "shadow",
        "changes_execution": False,
        "rows": rows,
        "components": sorted(sorted(members) for members in components),
        "selected": sorted(selected),
        "deferred": sorted(set(contexts) - selected),
        "unknown": sorted(set(contexts) | set(unavailable)),
        "unbound": sorted(unbound, key=digest),
        "counts": {
            "planned": len(rows),
            "selected": len(selected),
            "deferred": len(contexts) - len(selected),
            "unknown": len(set(contexts) | set(unavailable)),
            "unbound": len(unbound),
        },
        "usage": {"status": "unknown", "physical_attempts": None, "tokens": None},
    }
