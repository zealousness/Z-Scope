"""System-owned proof offers for bounded P4 audit units."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Mapping, Optional, Sequence

from ...core.validation.function_ir import FunctionIRGraph
from ...core.validation.proof_kernel import (
    PREDICATE_REGISTRY,
    ProofKernelEngine,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
)
from ...semantics.security_map import FunctionSecurityRecord, SecurityEvent
from .resource_proof import ResourceProofBinding, resolve_resource_proof_binding


GraphProvider = Callable[[FunctionSecurityRecord, SecurityEvent], Optional[FunctionIRGraph]]


def _sha(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class HypothesisProofCatalog:
    """Compile finite P2 actions before any hypothesis model is invoked."""

    def __init__(self, graph_provider: GraphProvider) -> None:
        self.graph_provider = graph_provider
        self.engine = ProofKernelEngine()

    def bundles(
        self,
        record: FunctionSecurityRecord,
        event: SecurityEvent,
        identity: Mapping[str, Any],
    ) -> Sequence[Mapping[str, Any]]:
        graph = self.graph_provider(record, event)
        if graph is None:
            return ()
        resource_binding: ResourceProofBinding | None = None
        if event.family == "resource_lifecycle":
            resource_binding = resolve_resource_proof_binding(graph, event)
            if resource_binding is None:
                return ()
        proof_ir = program_proof_ir_from_graph(
            graph,
            project_uid="PROJECT_" + _sha(record.file_path)[:32],
            revision_uid="REV_" + graph.code_snapshot_sha256[:32],
        )
        predicate_id, parameters = self._predicate_and_parameters(
            graph,
            record,
            event,
            resource_binding=resource_binding,
        )
        if not predicate_id:
            return ()
        spec = PREDICATE_REGISTRY.get(predicate_id)
        if spec is None or set(parameters) != set(spec.parameter_keys):
            return ()
        subject_uid = str(identity.get("subject_uid") or "")
        region_uid = str(identity.get("decision_region_uid") or "")
        if resource_binding is not None:
            # Bind the planner identity to the exact acquisition rather than
            # coalescing every resource in one function under the first event.
            subject_uid = (
                "HRESOURCE_"
                + _sha(
                    [
                        record.function_uid,
                        resource_binding.acquisition_event_uid,
                        resource_binding.resource_uid,
                        graph.ir_sha256,
                    ]
                )[:32]
            )
            region_uid = (
                "HREGION_"
                + _sha(
                    [
                        record.file_path,
                        record.function_uid,
                        resource_binding.acquisition_statement_uid,
                    ]
                )[:32]
            )
        if not subject_uid or not region_uid:
            return ()
        terminal_capable = (
            event.family == "resource_lifecycle" and predicate_id == "cleanup_covers_all_exits"
        )
        is_resource_counterproof = bool(
            resource_binding is not None and resource_binding.cleanup_complete
        )
        clause = build_proof_clause(
            role="counterproof" if is_resource_counterproof else "confirmation",
            provider_family=spec.provider_family,
            predicate_id=spec.predicate_id,
            fact_kind=spec.fact_kind,
            quantifier=spec.quantifier,
            expected_value=(
                {"cleanup_complete": True}
                if is_resource_counterproof
                else self._unsafe_expected_value(predicate_id)
            ),
            parameters=parameters,
        )
        # Most semantic-map events identify a useful investigation point, but
        # their currently executable predicate is not itself a sufficient
        # vulnerability proof.  For example, CFG reachability does not prove
        # missing bounds enforcement and external parameter binding does not
        # prove an authorization bypass.  Keep the system-owned action in the
        # catalog for the Hunter, while an explicit open clause prevents that
        # fact from acquiring terminal authority.  A complete resource CFG
        # with an uncovered acquired resource is the one presently supported
        # sufficient confirmation shape.
        open_clauses: tuple[Mapping[str, Any], ...] = ()
        if not terminal_capable:
            open_clauses = (
                build_proof_clause(
                    role="open",
                    provider_family=spec.provider_family,
                    predicate_id=spec.predicate_id,
                    fact_kind=spec.fact_kind,
                    quantifier=spec.quantifier,
                    expected_value=self._unsafe_expected_value(predicate_id),
                    parameters=parameters,
                ),
            )
        defect_family = (
            "resource_leak"
            if terminal_capable
            else str(identity.get("defect_family") or self._defect_family(event))
        )
        obligation = build_proof_obligation(
            validation_cluster_uid="HCLUSTER_"
            + _sha(
                [
                    record.function_uid,
                    event.event_id,
                    predicate_id,
                    (
                        resource_binding.acquisition_event_uid
                        if resource_binding is not None
                        else ""
                    ),
                ]
            )[:32],
            defect_family=defect_family,
            subject_uid=subject_uid,
            decision_region_uid=region_uid,
            confirmation_clauses=(() if is_resource_counterproof else (clause,)),
            counterproof_clauses=((clause,) if is_resource_counterproof else ()),
            open_clauses=open_clauses,
            dependency_hashes=proof_ir["dependency_hashes"],
        )
        actions = self.engine.action_catalog(proof_ir=proof_ir, obligation=obligation)
        if not actions:
            return ()
        location_statement = (
            graph.statement_map.get(resource_binding.acquisition_statement_uid)
            if resource_binding is not None
            else self._target_statement(graph, event)
        )
        if location_statement is None:
            return ()
        location_line = max(1, int(event.line or location_statement.source_line or 1))
        source_ref: str | None = None
        sink_ref: str | None = None
        resource_ref: str | None = None
        if event.family == "resource_lifecycle":
            resource_ref = event.evidence_ref
        else:
            source_ref = self._source_evidence(record, event)
            sink_ref = event.evidence_ref
        return (
            {
                "subject_uid": subject_uid,
                "decision_region_uid": region_uid,
                "defect_family": defect_family,
                "dependency_hashes": list(proof_ir["dependency_hashes"]),
                "location": {
                    "file": record.file_path,
                    "function_uid": record.function_uid,
                    "start_line": location_line,
                    "end_line": location_line,
                    "statement_uid": location_statement.statement_uid,
                },
                "source_ref": source_ref,
                "sink_ref": sink_ref,
                "resource_ref": resource_ref,
                "proof_ir": proof_ir,
                "proof_obligation": obligation,
                "evidence_actions": list(actions),
                "supporting_fact_refs": (),
                "opposing_fact_refs": (),
                "unknown_fact_refs": (),
                "evidence_refs": (event.evidence_ref,),
            },
        )

    @staticmethod
    def _target_statement(graph: FunctionIRGraph, event: SecurityEvent) -> Any | None:
        matching = [
            value
            for value in graph.events
            if (event.line and value.source_line == event.line)
            or (event.kind and value.callee and value.callee in event.expression)
        ]
        if matching:
            statement = graph.statement_map.get(matching[0].statement_uid)
            if statement is not None:
                return statement
        statements = [value for block in graph.blocks for value in block.statements]
        return statements[0] if statements else None

    @classmethod
    def _predicate_and_parameters(
        cls,
        graph: FunctionIRGraph,
        record: FunctionSecurityRecord,
        event: SecurityEvent,
        *,
        resource_binding: ResourceProofBinding | None = None,
    ) -> tuple[str, dict[str, str]]:
        if event.family == "resource_lifecycle":
            if resource_binding is not None:
                return "cleanup_covers_all_exits", {"resource_uid": resource_binding.resource_uid}
            return "", {}
        target = cls._target_statement(graph, event)
        if target is None:
            return "", {}
        if event.family == "callback_concurrency":
            locks = [
                symbol
                for value in graph.events
                if value.kind in {"lock_acquire", "lock_release"}
                for symbol in value.subject_symbols
            ]
            if locks:
                return "lock_must_hold_at_access", {
                    "access_statement_uid": target.statement_uid,
                    "lock_uid": locks[0],
                }
        if event.family in {"auth_boundary", "state_protocol"}:
            return "external_entry_parameter_binding", {
                "parameter_uid": record.function_uid + ":arg0",
                "parameter_slot": "0",
            }
        return "source_sink_path_exists", {
            "source_node_uid": graph.entry_block_uid,
            "sink_node_uid": target.block_uid,
        }

    @staticmethod
    def _source_evidence(record: FunctionSecurityRecord, event: SecurityEvent) -> str:
        for value in record.events:
            if value.family == "input_boundary":
                return value.evidence_ref
        return event.evidence_ref

    @staticmethod
    def _unsafe_expected_value(predicate_id: str) -> Mapping[str, Any]:
        return {
            "lock_must_hold_at_access": {"must_hold": False},
            "cleanup_covers_all_exits": {"cleanup_complete": False},
            "source_sink_path_exists": {"path_exists": True},
            "guard_dominates_sink": {"dominates": False},
            "external_entry_parameter_binding": {"$derived": True},
            "record_layout_matches": {"$derived": True},
        }[predicate_id]

    @staticmethod
    def _defect_family(event: SecurityEvent) -> str:
        return {
            "callback_concurrency": "concurrency_safety",
            "resource_lifecycle": "resource_lifecycle",
            "auth_boundary": "authorization_boundary",
            "state_protocol": "state_protocol",
            "input_boundary": "untrusted_dataflow",
            "memory_bounds": "memory_bounds",
            "sensitive_sink": "sensitive_operation",
        }.get(event.family, "security_hypothesis")
