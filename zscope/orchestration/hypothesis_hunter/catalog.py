"""System-owned proof offers for bounded P4 audit units."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence

from ...core.validation.function_ir import FunctionIRGraph
from ...core.validation.proof_kernel import (
    PREDICATE_REGISTRY,
    ProofKernelEngine,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
)
from ...core.validation.proof_kernel.registry import (
    function_ir_compound_wrappers,
    qualified_bounds_options,
    qualified_resource_leak_options,
)
from ...semantics.security_map import FunctionSecurityRecord, SecurityEvent
from .resource_proof import ResourceProofBinding, resolve_resource_proof_binding


GraphProvider = Callable[[FunctionSecurityRecord, SecurityEvent], Optional[FunctionIRGraph]]
_GRAPH_RECORD_BINDING_FIELDS = frozenset(
    {
        "project_uid",
        "revision_uid",
        "function_uid",
        "function_name",
        "file",
        "code_sha256",
    }
)


@dataclass(frozen=True)
class _FrozenEventOption:
    fixed_parameters: Mapping[str, Any]
    event_uid: str
    statement_uid: str
    source_line: int


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

    def __init__(
        self,
        graph_provider: GraphProvider,
        *,
        project_uid: str,
        revision_uid: str,
        project_root: str | Path | None = None,
    ) -> None:
        if not str(project_uid) or not str(revision_uid):
            raise ValueError("hypothesis_graph_lineage_required")
        self.graph_provider = graph_provider
        self.project_uid = str(project_uid)
        self.revision_uid = str(revision_uid)
        self.project_root = Path(project_root) if project_root is not None else None
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
        graph_record_binding = self._graph_record_binding(
            graph=graph,
            record=record,
            identity=identity,
        )
        if graph_record_binding is None:
            return ()
        resource_binding: ResourceProofBinding | None = None
        if event.family == "resource_lifecycle":
            resource_binding = resolve_resource_proof_binding(graph, event)
            if resource_binding is None:
                return ()
        proof_ir = program_proof_ir_from_graph(
            graph,
            project_uid=self.project_uid,
            revision_uid=self.revision_uid,
            wrapper_summaries=(
                graph_record_binding,
                *function_ir_compound_wrappers(graph),
            ),
        )
        compound = self._qualified_compound_closure(
            proof_ir=proof_ir,
            record=record,
            event=event,
            resource_binding=resource_binding,
        )
        predicate_id, parameters = self._predicate_and_parameters(
            graph,
            record,
            event,
            resource_binding=resource_binding,
            target_statement_uid=str((compound or {}).get("location_statement_uid") or ""),
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
        if compound is not None:
            subject_uid = str(compound["subject_uid"])
            region_uid = str(compound["decision_region_uid"])
        is_resource_counterproof = bool(
            resource_binding is not None and resource_binding.cleanup_complete
        )
        # Complete cleanup of the exact acquired identity is independently
        # sufficient to reject a leak.  A missing cleanup is not sufficient to
        # confirm one until the compound ownership-transfer clauses also close.
        terminal_capable = compound is not None or is_resource_counterproof
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
        defect_family = str(
            compound["defect_family"]
            if compound is not None
            else (
                "resource_leak"
                if resource_binding is not None
                else identity.get("defect_family") or self._defect_family(event)
            )
        )
        confirmation_clauses = (
            tuple(compound["confirmation_clauses"])
            if compound is not None
            else (() if is_resource_counterproof else (clause,))
        )
        counterproof_clauses = (
            tuple(compound["counterproof_clauses"])
            if compound is not None
            else ((clause,) if is_resource_counterproof else ())
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
            confirmation_clauses=confirmation_clauses,
            counterproof_clauses=counterproof_clauses,
            open_clauses=open_clauses,
            dependency_hashes=proof_ir["dependency_hashes"],
        )
        actions = self.engine.action_catalog(proof_ir=proof_ir, obligation=obligation)
        if not actions:
            return ()
        compound_statement_uid = str((compound or {}).get("location_statement_uid") or "")
        compound_source_line = int((compound or {}).get("location_source_line") or 0)
        location_statement = (
            graph.statement_map.get(compound_statement_uid)
            if compound_statement_uid
            else (
                graph.statement_map.get(resource_binding.acquisition_statement_uid)
                if resource_binding is not None
                else self._target_statement(graph, event)
            )
        )
        if location_statement is None:
            return ()
        location_line = int(compound_source_line or location_statement.source_line or 0)
        if location_line <= 0 or location_statement.source_line != location_line:
            return ()
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
    def _normalized_file_identity(value: str, project_root: Path | None) -> str:
        raw = str(value or "").strip()
        if not raw:
            return ""
        candidate = Path(raw)
        if project_root is not None and not candidate.is_absolute():
            candidate = project_root / candidate
        try:
            normalized = str(candidate.resolve(strict=False))
        except OSError:
            normalized = os.path.abspath(os.path.normpath(str(candidate)))
        return os.path.normcase(normalized).replace("\\", "/")

    def _graph_record_binding(
        self,
        *,
        graph: FunctionIRGraph,
        record: FunctionSecurityRecord,
        identity: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        raw = identity.get("graph_record_binding")
        if not isinstance(raw, Mapping) or set(raw) != _GRAPH_RECORD_BINDING_FIELDS:
            return None
        expected = {
            "project_uid": self.project_uid,
            "revision_uid": self.revision_uid,
            "function_uid": record.function_uid,
            "function_name": record.function_name,
            "file": record.file_path,
            "code_sha256": record.code_hash,
        }
        if any(str(raw.get(key) or "") != str(value) for key, value in expected.items()):
            return None
        if (
            not record.function_name
            or graph.function != record.function_name
            or not graph.file
            or not record.file_path
            or self._normalized_file_identity(graph.file, self.project_root)
            != self._normalized_file_identity(record.file_path, self.project_root)
            or len(record.code_hash) != 64
            or any(value not in "0123456789abcdef" for value in record.code_hash)
        ):
            return None
        body = {
            "summary_kind": "hunter_graph_record_binding_v1",
            "project_uid": self.project_uid,
            "revision_uid": self.revision_uid,
            "record_function_uid": record.function_uid,
            "record_function_name": record.function_name,
            "record_file": record.file_path,
            "record_code_sha256": record.code_hash,
            "graph_function": graph.function,
            "graph_file": graph.file,
            "graph_code_snapshot_sha256": graph.code_snapshot_sha256,
            "graph_backend_sha256": graph.backend_sha256,
            "graph_ir_sha256": graph.ir_sha256,
        }
        return {**body, "binding_sha256": _sha(body)}

    @classmethod
    def _qualified_compound_closure(
        cls,
        *,
        proof_ir: Mapping[str, Any],
        record: FunctionSecurityRecord,
        event: SecurityEvent,
        resource_binding: ResourceProofBinding | None,
    ) -> Mapping[str, Any] | None:
        """Return one fully executable, qualification-backed obligation.

        A Hunter event is only a scheduling hint.  Terminal capability comes
        from the same compound predicate registry used by the Validator, never
        from the event family or from completion of one generic fact request.
        Ambiguous qualified options therefore stay on the generic open-clause
        path instead of being guessed into a terminal proof.
        """

        functions = proof_ir.get("functions")
        if not isinstance(functions, list) or len(functions) != 1:
            return None
        summary = functions[0]
        if not isinstance(summary, Mapping):
            return None

        if event.family == "memory_bounds":
            options = cls._options_for_event(
                summary,
                qualified_bounds_options(summary),
                event=event,
                event_uid_key="sink_event_uid",
            )
            if len(options) != 1:
                return None
            selected_option = options[0]
            parameters = dict(selected_option.fixed_parameters)
            subject_uid = str(parameters.get("value_uid") or "")
            if not subject_uid:
                return None
            clauses = cls._registered_clauses(
                parameters,
                (
                    (
                        "qualified_bounds_source_controllable",
                        {"source_controllable": True},
                    ),
                    ("qualified_bounds_path_complete", {"path_exists": True}),
                    (
                        "qualified_bounds_sink_contract",
                        {"dangerous_sink_contract": True},
                    ),
                    ("qualified_bounds_range_violation", {"range_violation": True}),
                ),
            )
            return {
                "subject_uid": subject_uid,
                "decision_region_uid": "HREGION_"
                + _sha(
                    [
                        record.function_uid,
                        subject_uid,
                        parameters.get("sink_event_uid"),
                    ]
                )[:32],
                "defect_family": "memory_bounds",
                "confirmation_clauses": clauses,
                "counterproof_clauses": (),
                "location_statement_uid": selected_option.statement_uid,
                "location_source_line": selected_option.source_line,
            }

        if event.family != "resource_lifecycle" or resource_binding is None:
            return None
        matching = [
            value
            for value in qualified_resource_leak_options(summary)
            if str((value.get("fixed_parameters") or {}).get("resource_uid") or "")
            == resource_binding.resource_uid
        ]
        if len(matching) != 1:
            return None
        option = matching[0]
        parameters = dict(option.get("fixed_parameters") or {})
        actual = dict(option.get("actual") or {})
        subject_uid = str(parameters.get("resource_uid") or "")
        if not subject_uid:
            return None
        if actual.get("cleanup_complete") is True:
            confirmation: tuple[Mapping[str, Any], ...] = ()
            counterproof = cls._registered_clauses(
                parameters,
                (("qualified_leak_cleanup_complete", {"cleanup_complete": True}),),
                role="counterproof",
            )
        elif (
            actual.get("outstanding_on_reachable_exit") is True
            and actual.get("ownership_transfer_excluded") is True
        ):
            confirmation = cls._registered_clauses(
                parameters,
                (
                    (
                        "qualified_leak_acquisition_identity",
                        {"exact_acquisition_identity": True},
                    ),
                    (
                        "qualified_leak_exit_outstanding",
                        {"outstanding_on_reachable_exit": True},
                    ),
                    (
                        "qualified_leak_transfer_excluded",
                        {"ownership_transfer_excluded": True},
                    ),
                ),
            )
            counterproof = ()
        else:
            return None
        return {
            "subject_uid": subject_uid,
            "decision_region_uid": "HREGION_"
            + _sha(
                [
                    record.function_uid,
                    resource_binding.acquisition_event_uid,
                    subject_uid,
                ]
            )[:32],
            "defect_family": "resource_leak",
            "confirmation_clauses": confirmation,
            "counterproof_clauses": counterproof,
        }

    @staticmethod
    def _options_for_event(
        summary: Mapping[str, Any],
        options: Sequence[Mapping[str, Any]],
        *,
        event: SecurityEvent,
        event_uid_key: str,
    ) -> list[_FrozenEventOption]:
        event_line = int(event.line or 0)
        if event_line <= 0:
            return []
        events_by_uid: dict[str, list[Mapping[str, Any]]] = {}
        for value in summary.get("events") or []:
            if not isinstance(value, Mapping):
                continue
            event_uid = str(value.get("event_uid") or "")
            if not event_uid:
                continue
            events_by_uid.setdefault(event_uid, []).append(value)
        statement_counts = Counter(
            str(statement_uid)
            for node in summary.get("cfg_nodes") or []
            if isinstance(node, Mapping) and isinstance(node.get("statement_uids"), list)
            for statement_uid in node.get("statement_uids") or []
            if str(statement_uid)
        )
        option_uids = [str(value.get(event_uid_key) or "") for value in options]
        option_uid_counts = Counter(option_uids)
        matching: list[_FrozenEventOption] = []
        for value in options:
            option_uid = str(value.get(event_uid_key) or "")
            frozen_events = events_by_uid.get(option_uid, [])
            # The semantic-map event is only a scheduling hint.  A qualified
            # option may authorize a compound proof only when its frozen IR
            # option identity and event identity both resolve exactly once,
            # with one exact statement on the same source line.  A sole option
            # or first same-line event is not a safe fallback.
            if not option_uid or option_uid_counts[option_uid] != 1 or len(frozen_events) != 1:
                continue
            frozen_event = frozen_events[0]
            attributes = frozen_event.get("attributes")
            attributes = attributes if isinstance(attributes, Mapping) else {}
            source_line = int(attributes.get("source_line") or 0)
            statement_uid = str(frozen_event.get("statement_uid") or "")
            if (
                source_line <= 0
                or source_line != event_line
                or not statement_uid
                or statement_counts[statement_uid] != 1
            ):
                continue
            matching.append(
                _FrozenEventOption(
                    fixed_parameters=dict(value),
                    event_uid=option_uid,
                    statement_uid=statement_uid,
                    source_line=source_line,
                )
            )
        return matching

    @staticmethod
    def _registered_clauses(
        parameters: Mapping[str, Any],
        definitions: Sequence[tuple[str, Mapping[str, Any]]],
        *,
        role: str = "confirmation",
    ) -> tuple[Mapping[str, Any], ...]:
        clauses: list[Mapping[str, Any]] = []
        for predicate_id, expected_value in definitions:
            spec = PREDICATE_REGISTRY[predicate_id]
            clauses.append(
                build_proof_clause(
                    role=role,
                    provider_family=spec.provider_family,
                    predicate_id=spec.predicate_id,
                    fact_kind=spec.fact_kind,
                    quantifier=spec.quantifier,
                    expected_value=expected_value,
                    parameters=parameters,
                )
            )
        return tuple(clauses)

    @staticmethod
    def _target_statement(graph: FunctionIRGraph, event: SecurityEvent) -> Any | None:
        matching = [
            value for value in graph.events if event.line and value.source_line == event.line
        ]
        if not matching and event.kind and event.expression:
            matching = [
                value for value in graph.events if value.callee and value.callee in event.expression
            ]
        statement_uids = {value.statement_uid for value in matching if value.statement_uid}
        if len(statement_uids) != 1:
            return None
        return graph.statement_map.get(next(iter(statement_uids)))

    @classmethod
    def _predicate_and_parameters(
        cls,
        graph: FunctionIRGraph,
        record: FunctionSecurityRecord,
        event: SecurityEvent,
        *,
        resource_binding: ResourceProofBinding | None = None,
        target_statement_uid: str = "",
    ) -> tuple[str, dict[str, str]]:
        if event.family == "resource_lifecycle":
            if resource_binding is not None:
                return "cleanup_covers_all_exits", {"resource_uid": resource_binding.resource_uid}
            return "", {}
        target = (
            graph.statement_map.get(target_statement_uid)
            if target_statement_uid
            else cls._target_statement(graph, event)
        )
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
