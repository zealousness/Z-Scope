"""Executable fact capabilities and replayable certificate providers.

The registry is the only authority for deciding whether a V3 evidence gap is
actionable.  Repository browsing tools are observations; they are deliberately
absent from this module.  A clause can be closed only by a certificate emitted
from a complete FunctionIRGraph or an equally explicit project fact.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from ...retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider
from .function_ir import FUNCTION_IR_VERSION, FunctionIREvent, FunctionIRGraph, graph_from_mapping
from .proof_kernel.checker import ProofChecker
from .proof_kernel.models import (
    build_evidence_action as build_proof_action,
    build_proof_clause,
    build_proof_obligation,
    program_proof_ir_from_graph,
    validate_certificate_envelope,
)
from .proof_kernel.provider import ProofProvider
from .proof_kernel.registry import PREDICATE_REGISTRY


CAPABILITY_REGISTRY_VERSION = "zscope.fact-capability-registry.v1"
EVIDENCE_ACTION_VERSION = "zscope.evidence-action.v1"
EVIDENCE_CERTIFICATE_VERSION = "zscope.evidence-certificate.v2"

_FACT_PREDICATES = {
    "lockset": "lock_must_hold_at_access",
    "cleanup_coverage": "cleanup_covers_all_exits",
    "source_sink_reachability": "source_sink_path_exists",
    "guard_dominance": "guard_dominates_sink",
    "source_controllability": "external_entry_parameter_binding",
    "type_layout": "record_layout_matches",
}

SUPPORTED_FACT_KINDS = frozenset(
    {
        "guard_dominance",
        "caller_contract",
        "source_controllability",
        "ownership_transfer",
        "cleanup_coverage",
        "lockset",
        "happens_before",
        "object_identity",
        "value_range",
        "source_sink_reachability",
        "type_layout",
    }
)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _normalized(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _subject(issue: Mapping[str, Any]) -> str:
    obligation = issue.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    return str(
        obligation.get("subject_uid")
        or issue.get("subject_uid")
        or issue.get("resource_identity")
        or issue.get("resource_signature")
        or issue.get("source_identity")
        or ""
    )


def _region(issue: Mapping[str, Any]) -> str:
    obligation = issue.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    return str(
        obligation.get("decision_region_uid")
        or issue.get("decision_region_uid")
        or obligation.get("obligation_uid")
        or issue.get("obligation_uid")
        or ""
    )


def _structured_endpoint(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if not isinstance(value, str) or not value.strip().startswith("{"):
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, Mapping) else {}


def _issue_file(issue: Mapping[str, Any]) -> str:
    """Resolve the candidate's structured source file without reading prose."""

    for key in ("file", "file_path"):
        value = str(issue.get(key) or "").strip()
        if value:
            return value
    location = issue.get("location")
    if isinstance(location, Mapping):
        for key in ("file", "path"):
            value = str(location.get(key) or "").strip()
            if value:
                return value
    elif isinstance(location, str):
        match = re.match(r"^(?P<file>.+?):(?P<line>\d+)(?::\d+)?$", location.strip())
        if match:
            return match.group("file")
    obligation = issue.get("security_obligation")
    obligation = obligation if isinstance(obligation, Mapping) else {}
    for key in ("sink_uid", "source_uid", "subject_uid"):
        endpoint = _structured_endpoint(obligation.get(key))
        value = str(endpoint.get("file") or endpoint.get("path") or "").strip()
        if value:
            return value
    evidence_pack = issue.get("evidence_pack")
    evidence_pack = evidence_pack if isinstance(evidence_pack, Mapping) else {}
    path = evidence_pack.get("path")
    path = path if isinstance(path, Mapping) else {}
    return str(path.get("file") or evidence_pack.get("file") or "").strip()


def _issue_line(issue: Mapping[str, Any]) -> int:
    for key in ("start_line", "line", "end_line"):
        try:
            value = int(issue.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    location = issue.get("location")
    if isinstance(location, Mapping):
        try:
            return max(0, int(location.get("line") or location.get("start_line") or 0))
        except (TypeError, ValueError):
            return 0
    if isinstance(location, str):
        match = re.match(r"^.+?:(?P<line>\d+)(?::\d+)?$", location.strip())
        if match:
            return int(match.group("line"))
    return 0


@dataclass(frozen=True)
class FactCapability:
    fact_kind: str
    provider_id: str
    verifier_id: str
    supported: bool
    executable_for_subject_region: bool
    coverage_scope: str
    cost_class: str
    dependency_hashes: Tuple[str, ...]
    unavailable_reason: str = ""
    schema_version: str = CAPABILITY_REGISTRY_VERSION

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["dependency_hashes"] = list(self.dependency_hashes)
        return value


@dataclass(frozen=True)
class EvidenceAction:
    action_id: str
    fact_kind: str
    provider_id: str
    verifier_id: str
    subject_uid: str
    decision_region_uid: str
    fixed_parameters: Dict[str, Any]
    description: str
    cost_class: str = "local_cfg"
    schema_version: str = EVIDENCE_ACTION_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CertificateResult:
    status: str
    reason_code: str
    certificate: Dict[str, Any]
    fact: Optional[Dict[str, Any]] = None
    proof_artifacts: Optional[Dict[str, Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "reason_code": self.reason_code,
            "certificate": dict(self.certificate),
            "verified_fact": dict(self.fact) if isinstance(self.fact, dict) else None,
            "proof_artifacts": (
                {key: dict(value) for key, value in self.proof_artifacts.items()}
                if isinstance(self.proof_artifacts, dict)
                else None
            ),
        }


class _CertificateProvider:
    provider_id = ""
    verifier_id = ""

    def prove(
        self,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        parameters: Mapping[str, Any],
    ) -> CertificateResult:
        raise NotImplementedError

    def result(
        self,
        *,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        status: str,
        reason: str,
        predicate_value: Any,
        coverage: str,
        cfg_nodes: Sequence[str] = (),
        cfg_edges: Sequence[Sequence[str]] = (),
        exit_blocks: Sequence[str] = (),
        assumptions: Sequence[str] = (),
    ) -> CertificateResult:
        body = {
            "schema_version": EVIDENCE_CERTIFICATE_VERSION,
            "provider_id": self.provider_id,
            "verifier_id": self.verifier_id,
            "fact_kind": fact_kind,
            "status": status,
            "reason_code": reason,
            "predicate_value": predicate_value,
            "coverage": coverage,
            "subject_uid": _subject(issue),
            "decision_region_uid": _region(issue),
            "function": graph.function,
            "file": graph.file,
            "cfg_nodes": list(cfg_nodes),
            "cfg_edges": [list(value) for value in cfg_edges],
            "exit_blocks": list(exit_blocks),
            "assumptions": list(assumptions),
            "function_ir_sha256": graph.ir_sha256,
            "code_snapshot_sha256": graph.code_snapshot_sha256,
            "backend_sha256": graph.backend_sha256,
            "quantifier_coverage_complete": coverage == "complete",
        }
        certificate_hash = _sha(body)
        certificate = {**body, "certificate_sha256": certificate_hash}
        fact: Optional[Dict[str, Any]] = None
        if status == "verified_true" and coverage == "complete":
            fact_uid = "FACT_CERT_" + certificate_hash[:32]
            location = {
                "file": graph.file,
                "function": graph.function,
                "decision_region_uid": _region(issue),
            }
            fact = {
                "fact_uid": fact_uid,
                "fact_kind": fact_kind,
                "value": predicate_value,
                "status": "verified_true",
                "provider_id": self.provider_id,
                "producer_engine": self.provider_id,
                "verifier_id": self.verifier_id,
                "subject_uid": _subject(issue),
                "decision_region_uid": _region(issue),
                "location": location,
                "locations": [location],
                "evidence_ref": fact_uid,
                "evidence_refs": [fact_uid],
                "dependency_code_hash": _sha(
                    [graph.code_snapshot_sha256, graph.backend_sha256, graph.ir_sha256]
                ),
                "satisfies_fact_kinds": [fact_kind],
                "verification_certificate": certificate,
                "origin": "function_ir_certificate",
            }
        return CertificateResult(
            status=status,
            reason_code=reason,
            certificate=certificate,
            fact=fact,
        )


class ConcurrencyProofProvider(_CertificateProvider):
    provider_id = "zscope.concurrency-proof-provider"
    verifier_id = "zscope.concurrency-proof-verifier.v1"

    def prove(
        self,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        parameters: Mapping[str, Any],
    ) -> CertificateResult:
        if not graph.coverage_complete or graph.unresolved_dynamic_edges:
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="coverage_incomplete",
                predicate_value=None,
                coverage="partial",
            )
        if fact_kind == "lockset":
            access_statement = str(parameters.get("access_statement_uid") or "")
            locksets = graph.must_hold_locksets_at_statements()
            if access_statement not in locksets:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="access_statement_unresolved",
                    predicate_value=None,
                    coverage="partial",
                )
            locks = sorted(locksets[access_statement])
            statement = next(
                value
                for block in graph.blocks
                for value in block.statements
                if value.statement_uid == access_statement
            )
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="verified_true",
                reason="cfg_must_hold_fixed_point",
                predicate_value={"must_hold_locks": locks},
                coverage="complete",
                cfg_nodes=(statement.block_uid, access_statement),
            )
        if fact_kind == "happens_before":
            left_uid = str(parameters.get("left_event_uid") or "")
            right_uid = str(parameters.get("right_event_uid") or "")
            by_uid = {event.event_uid: event for event in graph.events}
            left = by_uid.get(left_uid)
            right = by_uid.get(right_uid)
            if left is None or right is None:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="sync_event_unresolved",
                    predicate_value=None,
                    coverage="partial",
                )
            same_object = bool(set(left.subject_symbols) & set(right.subject_symbols))
            valid_kinds = (left.kind, right.kind) in {
                ("lock_release", "lock_acquire"),
                ("thread_create", "thread_join"),
            }
            path = graph.event_precedes(left.event_uid, right.event_uid)
            if not same_object or not valid_kinds or not path:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="explicit_sync_relation_not_proved",
                    predicate_value=None,
                    coverage="partial",
                    cfg_nodes=path,
                )
            edges = [(left.event_uid, right.event_uid)]
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="verified_true",
                reason="explicit_sync_edges_recomputed",
                predicate_value={"happens_before": edges},
                coverage="complete",
                cfg_nodes=path,
                cfg_edges=edges,
            )
        return self.result(
            graph=graph,
            issue=issue,
            fact_kind=fact_kind,
            status="unknown",
            reason="unsupported_concurrency_fact",
            predicate_value=None,
            coverage="none",
        )


class ResourceProtocolProofProvider(_CertificateProvider):
    provider_id = "zscope.resource-protocol-proof-provider"
    verifier_id = "zscope.resource-protocol-proof-verifier.v1"

    def prove(
        self,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        parameters: Mapping[str, Any],
    ) -> CertificateResult:
        subject = str(parameters.get("resource_symbol") or "")
        if not graph.coverage_complete or not subject or graph.unresolved_dynamic_edges:
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="coverage_or_resource_identity_incomplete",
                predicate_value=None,
                coverage="partial",
            )
        acquires = [
            event
            for event in graph.events
            if event.kind == "resource_acquire" and subject in event.subject_symbols
        ]
        if not acquires:
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="resource_acquire_not_resolved",
                predicate_value=None,
                coverage="partial",
            )
        outstanding = graph.resource_outstanding_at_exits(subject)
        uncovered = [value for value, is_outstanding in outstanding.items() if is_outstanding]
        covered = [value for value, is_outstanding in outstanding.items() if not is_outstanding]
        if fact_kind == "cleanup_coverage":
            unresolved_subject_calls = [
                event.event_uid
                for event in graph.events
                if event.kind == "call"
                and subject in event.subject_symbols
                and event.callee not in {"free", "close", "fclose", "munmap"}
            ]
            value = {
                "cleanup_complete": not uncovered,
                "covered_exits": covered,
                "uncovered_exits": uncovered,
                "resource_symbol": subject,
                "ownership_transfer_unknown": bool(unresolved_subject_calls),
                "unresolved_subject_calls": unresolved_subject_calls,
            }
        elif fact_kind == "ownership_transfer":
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="callee_ownership_contract_unavailable",
                predicate_value=None,
                coverage="partial",
            )
        else:
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="unsupported_resource_fact",
                predicate_value=None,
                coverage="none",
            )
        return self.result(
            graph=graph,
            issue=issue,
            fact_kind=fact_kind,
            status="verified_true",
            reason="all_reachable_exits_enumerated",
            predicate_value=value,
            coverage="complete",
            cfg_nodes=tuple((*covered, *uncovered)),
            exit_blocks=graph.exit_block_uids,
            assumptions=("no external ownership transfer assumed",),
        )


class PathAndGuardProofProvider(_CertificateProvider):
    provider_id = "zscope.path-guard-proof-provider"
    verifier_id = "zscope.path-guard-proof-verifier.v1"

    def prove(
        self,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        parameters: Mapping[str, Any],
    ) -> CertificateResult:
        if not graph.coverage_complete:
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="coverage_incomplete",
                predicate_value=None,
                coverage="partial",
            )
        source_statement = str(parameters.get("source_statement_uid") or "")
        sink_statement = str(parameters.get("sink_statement_uid") or "")
        source = str(parameters.get("source_block_uid") or graph.entry_block_uid)
        sink = str(parameters.get("sink_block_uid") or "")
        if sink_statement:
            sink_record = graph.statement_map.get(sink_statement)
            sink = sink_record.block_uid if sink_record else ""
        if source_statement:
            source_record = graph.statement_map.get(source_statement)
            source = source_record.block_uid if source_record else ""
        if not sink:
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="sink_block_unresolved",
                predicate_value=None,
                coverage="partial",
            )
        if fact_kind == "source_sink_reachability":
            path = (
                graph.statement_reachable(source_statement, sink_statement)
                if source_statement and sink_statement
                else graph.reachable(source, sink)
            )
            if not path and graph.unresolved_dynamic_edges:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="dynamic_edge_coverage_incomplete",
                    predicate_value=None,
                    coverage="partial",
                )
            edges = tuple(zip(path, path[1:])) if path else ()
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="verified_true",
                reason="cfg_reachability_recomputed",
                predicate_value={"path_exists": bool(path)},
                coverage="complete",
                cfg_nodes=path,
                cfg_edges=edges,
            )
        if fact_kind == "guard_dominance":
            guard_statement = str(parameters.get("guard_statement_uid") or "")
            if not guard_statement or not sink_statement:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="guard_or_sink_statement_unresolved",
                    predicate_value=None,
                    coverage="partial",
                )
            guard_record = graph.statement_map.get(guard_statement)
            sink_record = graph.statement_map.get(sink_statement)
            if guard_record is None or sink_record is None:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="guard_or_sink_statement_unresolved",
                    predicate_value=None,
                    coverage="partial",
                )
            dominates = graph.statement_dominates(guard_statement, sink_statement)
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="verified_true",
                reason="cfg_dominance_recomputed",
                predicate_value={"guard_dominates_sink": dominates},
                coverage="complete",
                cfg_nodes=(
                    guard_record.block_uid,
                    guard_statement,
                    sink_record.block_uid,
                    sink_statement,
                ),
            )
        if fact_kind == "value_range":
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="value_range_domain_not_available",
                predicate_value=None,
                coverage="partial",
            )
        return self.result(
            graph=graph,
            issue=issue,
            fact_kind=fact_kind,
            status="unknown",
            reason="unsupported_path_fact",
            predicate_value=None,
            coverage="none",
        )


class ContractAndTypeProofProvider(_CertificateProvider):
    provider_id = "zscope.contract-type-proof-provider"
    verifier_id = "zscope.contract-type-proof-verifier.v1"

    def prove(
        self,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        parameters: Mapping[str, Any],
    ) -> CertificateResult:
        if fact_kind == "source_controllability":
            entry = issue.get("entry_context")
            entry = entry if isinstance(entry, Mapping) else {}
            explicit = bool(
                issue.get("reachable_from_entry") and entry.get("entry_is_external_root")
            )
            if not explicit:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="entry_exposure_not_proved",
                    predicate_value=None,
                    coverage="partial",
                )
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="verified_true",
                reason="entry_exposure_fact_replayed",
                predicate_value={"externally_controllable": True},
                coverage="complete",
            )
        if fact_kind == "type_layout":
            subject = str(parameters.get("type_subject") or _subject(issue))
            matches = []
            for call in graph.ast_calls:
                if subject and subject in _canonical(call):
                    matches.append(dict(call))
            if not matches:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="unknown",
                    reason="type_subject_not_resolved",
                    predicate_value=None,
                    coverage="partial",
                )
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="verified_true",
                reason="clang_ast_type_replayed",
                predicate_value={"matches": matches},
                coverage="complete",
            )
        if fact_kind == "caller_contract":
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="external_caller_contract_not_program_provable",
                predicate_value=None,
                coverage="partial",
            )
        if fact_kind == "object_identity":
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="field_sensitive_alias_certificate_unavailable",
                predicate_value=None,
                coverage="partial",
            )
        return self.result(
            graph=graph,
            issue=issue,
            fact_kind=fact_kind,
            status="unknown",
            reason="unsupported_contract_fact",
            predicate_value=None,
            coverage="none",
        )


class FunctionIRFactService:
    """Build one cached FunctionIRGraph and expose finite proof actions."""

    def __init__(self, compile_commands_path: Optional[Path], *, enabled: bool) -> None:
        self.enabled = bool(enabled)
        self._clang = ClangToolingEvidenceProvider(
            compile_commands_path,
            execute=self.enabled,
            timeout=30,
        )
        self._graphs: Dict[str, Optional[FunctionIRGraph]] = {}
        self._graph_build_locks: Dict[str, Lock] = {}
        self._graph_failures: Dict[str, str] = {}
        self._results: Dict[str, CertificateResult] = {}
        self._lock = Lock()
        self._providers = {
            "lockset": ConcurrencyProofProvider(),
            "happens_before": ConcurrencyProofProvider(),
            "cleanup_coverage": ResourceProtocolProofProvider(),
            "ownership_transfer": ResourceProtocolProofProvider(),
            "source_sink_reachability": PathAndGuardProofProvider(),
            "guard_dominance": PathAndGuardProofProvider(),
            "value_range": PathAndGuardProofProvider(),
            "caller_contract": ContractAndTypeProofProvider(),
            "source_controllability": ContractAndTypeProofProvider(),
            "object_identity": ContractAndTypeProofProvider(),
            "type_layout": ContractAndTypeProofProvider(),
        }
        self._proof_provider = ProofProvider()
        self._proof_checker = ProofChecker()

    def graph(
        self,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
    ) -> Optional[FunctionIRGraph]:
        raw_existing = issue.get("function_ir_graph")
        if isinstance(raw_existing, Mapping):
            try:
                return graph_from_mapping(raw_existing)
            except (TypeError, ValueError):
                return None
        function = str(issue.get("function_signature") or issue.get("function") or "")
        file = _issue_file(issue)
        if not self.enabled or not function or not file:
            return None
        key = _sha({"function": function, "file": file})
        with self._lock:
            if key in self._graphs:
                return self._graphs[key]
            build_lock = self._graph_build_locks.setdefault(key, Lock())
        # Several validation clusters commonly point at one function.  Build
        # its large Clang AST/CFG exactly once; otherwise concurrent subprocess
        # storms can all time out and permanently cache an unavailable graph.
        with build_lock:
            with self._lock:
                if key in self._graphs:
                    return self._graphs[key]
            line = _issue_line(issue)
            collected = self._clang.collect_for_function(
                func_name=function,
                file_path=file,
                start_line=line,
                end_line=line,
            )
            graph = FunctionIRGraph.from_clang_evidence(
                collected,
                function=function,
                file=file,
            )
            failure = "" if graph is not None else self._graph_failure(collected)
            with self._lock:
                self._graphs[key] = graph
                self._graph_failures[key] = failure
        if graph is not None and isinstance(issue, dict):
            issue["function_ir_graph"] = graph.to_dict()
        return graph

    @staticmethod
    def _graph_failure(collected: Mapping[str, Any]) -> str:
        status = _normalized(collected.get("status"))
        if status and status != "executed":
            return "function_ir_" + status
        cfg_dump = collected.get("cfg_dump")
        cfg_dump = cfg_dump if isinstance(cfg_dump, Mapping) else {}
        if cfg_dump.get("ok") is not True:
            if cfg_dump.get("error"):
                return "function_ir_cfg_execution_error"
            return "function_ir_cfg_command_failed"
        summary = cfg_dump.get("summary")
        summary = summary if isinstance(summary, Mapping) else {}
        if summary.get("function_section_unique") is not True:
            return "function_ir_cfg_function_missing_or_ambiguous"
        if summary.get("parse_ok") is not True:
            return "function_ir_cfg_parse_failed"
        return "function_ir_unavailable"

    def unavailable_reason(self, issue: Mapping[str, Any]) -> str:
        if not self.enabled:
            return "function_ir_disabled"
        function = str(issue.get("function_signature") or issue.get("function") or "")
        file = _issue_file(issue)
        if not function:
            return "function_ir_function_missing"
        if not file:
            return "function_ir_file_missing"
        key = _sha({"function": function, "file": file})
        with self._lock:
            return self._graph_failures.get(key, "function_ir_unavailable")

    def actions(
        self,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
        fact_kinds: Iterable[str],
    ) -> Tuple[EvidenceAction, ...]:
        graph = self.graph(issue, evidence)
        if graph is None:
            return ()
        actions: list[EvidenceAction] = []
        for fact_kind in sorted({_normalized(value) for value in fact_kinds if _normalized(value)}):
            if fact_kind not in self._providers:
                continue
            for parameters in self._parameter_options(graph, issue, fact_kind):
                body = {
                    "fact_kind": fact_kind,
                    "subject_uid": _subject(issue),
                    "decision_region_uid": _region(issue),
                    "parameters": parameters,
                    "ir": graph.ir_sha256,
                }
                provider = self._providers[fact_kind]
                proof_parameters = dict(parameters)
                if fact_kind == "lockset" and "lock_uid" not in proof_parameters:
                    locks = tuple(
                        dict.fromkeys(
                            symbol
                            for event in graph.events
                            if event.kind in {"lock_acquire", "lock_release"}
                            for symbol in event.subject_symbols
                        )
                    )
                    if len(locks) == 1:
                        proof_parameters["lock_uid"] = locks[0]
                compiled = self._compile_proof_artifacts(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    parameters=proof_parameters,
                )
                strict_action = compiled.get("action") if compiled else None
                actions.append(
                    EvidenceAction(
                        action_id=(
                            str(strict_action["action_uid"])
                            if isinstance(strict_action, Mapping)
                            else "EVACTION_" + _sha(body)[:32]
                        ),
                        fact_kind=fact_kind,
                        provider_id=(
                            str(strict_action["provider_id"])
                            if isinstance(strict_action, Mapping)
                            else provider.provider_id
                        ),
                        verifier_id=(
                            str(strict_action["verifier_id"])
                            if isinstance(strict_action, Mapping)
                            else provider.verifier_id
                        ),
                        subject_uid=_subject(issue),
                        decision_region_uid=_region(issue),
                        fixed_parameters=parameters,
                        description=(
                            f"Recompute {fact_kind} over frozen FunctionIRGraph "
                            f"{graph.ir_sha256[:12]}"
                        ),
                    )
                )
        return tuple(actions)

    def execute(
        self,
        action: EvidenceAction,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
    ) -> CertificateResult:
        graph = self.graph(issue, evidence)
        if graph is None:
            return self._unavailable_result(action, "function_ir_unavailable")
        expected = {
            value.action_id: value for value in self.actions(issue, evidence, (action.fact_kind,))
        }.get(action.action_id)
        if expected is None or expected.to_dict() != action.to_dict():
            return self._unavailable_result(action, "evidence_action_identity_mismatch")
        cache_key = _sha(action.to_dict())
        with self._lock:
            cached = self._results.get(cache_key)
        if cached is not None:
            return cached
        provider = self._providers[action.fact_kind]
        stable_result = provider.prove(graph, issue, action.fact_kind, action.fixed_parameters)
        if isinstance(stable_result.fact, dict):
            stable_fact = dict(stable_result.fact)
            proof = self._decision_proof(stable_result, issue)
            if proof is not None:
                stable_fact["deterministic_proof"] = proof
            stable_result = CertificateResult(
                status=stable_result.status,
                reason_code=stable_result.reason_code,
                certificate=dict(stable_result.certificate),
                fact=stable_fact,
            )
        parameters = dict(action.fixed_parameters)
        if action.fact_kind == "lockset" and "lock_uid" not in parameters:
            locks = tuple(
                dict.fromkeys(
                    symbol
                    for event in graph.events
                    if event.kind in {"lock_acquire", "lock_release"}
                    for symbol in event.subject_symbols
                )
            )
            if len(locks) == 1:
                parameters["lock_uid"] = locks[0]
        artifacts = self._compile_proof_artifacts(
            graph=graph,
            issue=issue,
            fact_kind=action.fact_kind,
            parameters=parameters,
        )
        if artifacts is None:
            result = stable_result
            with self._lock:
                self._results[cache_key] = result
            return result
        certificate = self._proof_provider.produce(
            proof_ir=artifacts["program_proof_ir"],
            obligation=artifacts["proof_obligation"],
            action=artifacts["action"],
        )
        check_result = self._proof_checker.check(
            proof_ir=artifacts["program_proof_ir"],
            obligation=artifacts["proof_obligation"],
            action=artifacts["action"],
            certificate=certificate,
        )
        result = CertificateResult(
            status=stable_result.status,
            reason_code=stable_result.reason_code,
            certificate=stable_result.certificate,
            fact=stable_result.fact,
            proof_artifacts={
                **artifacts,
                "evidence_certificate": certificate,
                "proof_check_result": check_result,
            },
        )
        with self._lock:
            self._results[cache_key] = result
        return result

    @staticmethod
    def _compile_proof_artifacts(
        *,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        parameters: Mapping[str, Any],
    ) -> Optional[Dict[str, Dict[str, Any]]]:
        predicate_id = _FACT_PREDICATES.get(fact_kind)
        spec = PREDICATE_REGISTRY.get(predicate_id or "")
        subject_uid = _subject(issue)
        region_uid = _region(issue)
        if spec is None or not subject_uid or not region_uid:
            return None
        fixed = dict(parameters)
        if predicate_id == "source_sink_path_exists":
            source_statement = str(fixed.pop("source_statement_uid", ""))
            sink_statement = str(fixed.pop("sink_statement_uid", ""))
            if source_statement:
                record = graph.statement_map.get(source_statement)
                fixed["source_node_uid"] = record.block_uid if record else ""
            if sink_statement:
                record = graph.statement_map.get(sink_statement)
                fixed["sink_node_uid"] = record.block_uid if record else ""
            fixed.setdefault("source_node_uid", str(fixed.pop("source_block_uid", "")))
            fixed.setdefault("sink_node_uid", str(fixed.pop("sink_block_uid", "")))
        elif predicate_id == "cleanup_covers_all_exits":
            fixed = {"resource_uid": str(fixed.get("resource_symbol") or "")}
        if set(fixed) != set(spec.parameter_keys) or any(
            value in (None, "") for value in fixed.values()
        ):
            return None
        proof_ir = program_proof_ir_from_graph(
            graph,
            project_uid="PROJECT_" + _sha({"file": graph.file})[:32],
            revision_uid="REV_" + graph.code_snapshot_sha256[:32],
        )
        clause = build_proof_clause(
            role="confirmation",
            provider_family=spec.provider_family,
            predicate_id=spec.predicate_id,
            fact_kind=spec.fact_kind,
            quantifier=spec.quantifier,
            expected_value={"$derived": True},
            parameters=fixed,
        )
        security_obligation = issue.get("security_obligation")
        security_obligation = (
            security_obligation if isinstance(security_obligation, Mapping) else {}
        )
        obligation = build_proof_obligation(
            validation_cluster_uid=str(
                issue.get("validation_cluster_uid")
                or security_obligation.get("obligation_uid")
                or region_uid
            ),
            defect_family=str(issue.get("defect_family") or issue.get("type") or "generic"),
            subject_uid=subject_uid,
            decision_region_uid=region_uid,
            confirmation_clauses=(clause,),
            counterproof_clauses=(),
            open_clauses=(),
            dependency_hashes=proof_ir["dependency_hashes"],
        )
        proof_action = build_proof_action(
            obligation=obligation,
            clause=clause,
            proof_ir=proof_ir,
            provider_id=spec.provider_id,
            verifier_id=spec.verifier_id,
        )
        return {
            "program_proof_ir": proof_ir,
            "proof_obligation": obligation,
            "action": proof_action,
        }

    def resolve_first(
        self,
        fact_kind: str,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        actions = self.actions(issue, evidence, (fact_kind,))
        if not actions:
            return None
        if len(actions) != 1:
            return {
                "fact_kind": fact_kind,
                "status": "unknown",
                "provider_id": "zscope.fact-capability-registry",
                "producer_engine": "zscope.fact-capability-registry",
                "satisfies_fact_kinds": [],
                "value": {
                    "reason": "ambiguous_evidence_action_selection",
                    "available_action_ids": [value.action_id for value in actions],
                },
            }
        results = [self.execute(actions[0], issue, evidence)]
        verified = next((value for value in results if value.fact is not None), None)
        if verified is not None:
            fact = dict(verified.fact or {})
            return fact
        # Persist one observation so the miss reason remains auditable, but it
        # deliberately has no satisfies_fact_kinds and cannot close a clause.
        first = results[0]
        return {
            "fact_kind": fact_kind,
            "status": first.status,
            "provider_id": first.certificate.get("provider_id"),
            "producer_engine": first.certificate.get("provider_id"),
            "satisfies_fact_kinds": [],
            "verification_certificate": first.certificate,
            "value": None,
        }

    def capabilities(
        self,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
        fact_kinds: Iterable[str],
    ) -> Tuple[FactCapability, ...]:
        graph = self.graph(issue, evidence)
        actions = self.actions(issue, evidence, fact_kinds) if graph else ()
        by_kind = {action.fact_kind for action in actions}
        result = []
        for fact_kind in sorted({_normalized(value) for value in fact_kinds if _normalized(value)}):
            provider = self._providers.get(fact_kind)
            supported = provider is not None
            executable = fact_kind in by_kind
            result.append(
                FactCapability(
                    fact_kind=fact_kind,
                    provider_id=provider.provider_id if provider else "",
                    verifier_id=provider.verifier_id if provider else "",
                    supported=supported,
                    executable_for_subject_region=executable,
                    coverage_scope=(
                        "function_cfg_complete" if graph and graph.coverage_complete else "none"
                    ),
                    cost_class="local_cfg",
                    dependency_hashes=(
                        tuple(
                            value
                            for value in (
                                graph.code_snapshot_sha256,
                                graph.backend_sha256,
                                graph.ir_sha256,
                            )
                            if value
                        )
                        if graph
                        else ()
                    ),
                    unavailable_reason=(
                        ""
                        if executable
                        else (
                            self.unavailable_reason(issue)
                            if graph is None
                            else "subject_region_not_executable"
                        )
                    ),
                )
            )
        return tuple(result)

    @staticmethod
    def _unavailable_result(action: EvidenceAction, reason: str) -> CertificateResult:
        body = {
            "schema_version": EVIDENCE_CERTIFICATE_VERSION,
            "provider_id": action.provider_id,
            "verifier_id": action.verifier_id,
            "fact_kind": action.fact_kind,
            "status": "unknown",
            "reason_code": reason,
            "subject_uid": action.subject_uid,
            "decision_region_uid": action.decision_region_uid,
            "coverage": "none",
        }
        return CertificateResult(
            status="unknown",
            reason_code=reason,
            certificate={**body, "certificate_sha256": _sha(body)},
        )

    @staticmethod
    def _decision_proof(
        result: CertificateResult,
        issue: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        fact = result.fact
        if not isinstance(fact, Mapping):
            return None
        certificate = result.certificate
        witness = certificate.get("witness")
        witness = witness if isinstance(witness, Mapping) else {}
        fact_kind = str(fact.get("fact_kind") or "")
        value = fact.get("value")
        value = value if isinstance(value, Mapping) else {}
        outcome = ""
        proof_kind = ""
        facts: list[str] = []
        if fact_kind == "cleanup_coverage":
            if value.get("cleanup_complete") is True:
                outcome = "reject"
                proof_kind = "ownership_cleanup_complete"
                facts = ["cleanup_all_paths"]
            elif value.get("cleanup_complete") is False and value.get("uncovered_exits"):
                if value.get("ownership_transfer_unknown") is not True:
                    outcome = "confirm"
                    proof_kind = "missing_cleanup_path"
                    facts = ["allocation_reachable", "cleanup_missing"]
        elif fact_kind == "source_sink_reachability" and value.get("path_exists") is False:
            outcome = "reject"
            proof_kind = "sink_unreachable"
            facts = ["sink_unreachable"]
        # Dominance alone says only that a condition executes before a sink.
        # It does not prove that the condition enforces the security predicate
        # (for example, that a bounds check is sufficiently strong).  Keep the
        # certificate as a model-consumable fact, but never turn it into a
        # deterministic safety counterproof without a value-domain proof.
        if not outcome:
            return None
        return {
            "outcome": outcome,
            "proof_kind": proof_kind,
            "producer_engine": str(certificate.get("verifier_id") or "function_ir_verifier"),
            "proof_version": "zscope.decision-proof.v4",
            "fact_ids": [str(fact.get("fact_uid") or "")],
            "cfg_nodes": list(witness.get("cfg_nodes") or certificate.get("cfg_nodes") or []),
            "subject_identity": _subject(issue),
            "code_hash": str(
                certificate.get("code_sha256") or certificate.get("code_snapshot_sha256") or ""
            ),
            "facts": facts,
            "completeness": "complete",
            "scope": str(
                (certificate.get("coverage") or {}).get("domain")
                if isinstance(certificate.get("coverage"), Mapping)
                else certificate.get("coverage") or "function CFG"
            ),
            "summary": result.reason_code or proof_kind,
            "assumptions": list(
                certificate.get("assumption_ids") or certificate.get("assumptions") or []
            ),
            "certificate_sha256": str(
                certificate.get("content_sha256") or certificate.get("certificate_sha256") or ""
            ),
            "verification_certificate": dict(certificate),
        }

    @staticmethod
    def _parameter_options(
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
    ) -> Tuple[Dict[str, Any], ...]:
        pack = issue.get("evidence_pack")
        pack = pack if isinstance(pack, Mapping) else {}
        source_blocks = FunctionIRFactService._endpoint_blocks(
            graph, issue.get("source") or pack.get("source")
        )
        sink_blocks = FunctionIRFactService._endpoint_blocks(
            graph, issue.get("sink") or pack.get("sink")
        )
        source_statements = FunctionIRFactService._endpoint_statements(
            graph, issue.get("source") or pack.get("source")
        )
        sink_statements = FunctionIRFactService._endpoint_statements(
            graph, issue.get("sink") or pack.get("sink")
        )
        if not sink_blocks:
            line = int(issue.get("line") or issue.get("start_line") or 0)
            sink_blocks = tuple(
                dict.fromkeys(
                    event.block_uid for event in graph.events if line and event.source_line == line
                )
            )
        if fact_kind == "source_sink_reachability":
            if source_statements and sink_statements:
                return tuple(
                    {
                        "source_statement_uid": source,
                        "sink_statement_uid": sink,
                    }
                    for source in source_statements
                    for sink in sink_statements
                    if graph.statement_reachable(source, sink)
                )[:16]
            sources = source_blocks or ((graph.entry_block_uid,) if graph.entry_block_uid else ())
            return tuple(
                {"source_block_uid": source, "sink_block_uid": sink}
                for source in sources
                for sink in sink_blocks
            )[:16]
        if fact_kind == "guard_dominance":
            guard_statements = tuple(
                statement.statement_uid
                for block in graph.blocks
                for statement in block.statements
                if re.search(r"\b(if|switch)\b|\?|&&|\|\|", statement.text)
            )
            return tuple(
                {
                    "guard_statement_uid": guard,
                    "sink_statement_uid": sink,
                }
                for guard in guard_statements
                for sink in sink_statements
            )[:16]
        if fact_kind == "lockset":
            statements = FunctionIRFactService._endpoint_statements(
                graph, issue.get("sink") or pack.get("sink")
            )
            if not statements:
                line = int(issue.get("line") or issue.get("start_line") or 0)
                statements = tuple(
                    statement.statement_uid
                    for block in graph.blocks
                    for statement in block.statements
                    if line and statement.source_line == line
                )
            locks = tuple(
                dict.fromkeys(
                    symbol
                    for event in graph.events
                    if event.kind in {"lock_acquire", "lock_release"}
                    for symbol in event.subject_symbols
                )
            )
            return tuple({"access_statement_uid": value} for value in statements)[:16]
        if fact_kind == "happens_before":
            sync_events = [
                event
                for event in graph.events
                if event.kind in {"lock_acquire", "lock_release", "thread_create", "thread_join"}
            ]
            return tuple(
                {
                    "left_event_uid": left.event_uid,
                    "right_event_uid": right.event_uid,
                }
                for left in sync_events
                for right in sync_events
                if left.event_uid != right.event_uid
                and (left.kind, right.kind)
                in {("lock_release", "lock_acquire"), ("thread_create", "thread_join")}
                and set(left.subject_symbols) & set(right.subject_symbols)
                and graph.event_precedes(left.event_uid, right.event_uid)
            )[:16]
        if fact_kind == "cleanup_coverage":
            symbols = tuple(
                dict.fromkeys(
                    symbol
                    for event in graph.events
                    if event.kind == "resource_acquire"
                    for symbol in event.subject_symbols
                )
            )
            return tuple({"resource_symbol": value} for value in symbols)[:16]
        if fact_kind == "source_controllability":
            entry = issue.get("entry_context")
            entry = entry if isinstance(entry, Mapping) else {}
            if issue.get("reachable_from_entry") and entry.get("entry_is_external_root"):
                return ({"source": str(issue.get("source") or "")},)
            return ()
        if fact_kind == "type_layout":
            # AST call summaries are not a field-layout certificate.  Keep
            # the provider registered but non-executable until Clang record
            # layout output is part of FunctionIRGraph.
            return ()
        if fact_kind in {"caller_contract", "object_identity", "ownership_transfer", "value_range"}:
            return ()
        return ()

    @staticmethod
    def _endpoint_blocks(graph: FunctionIRGraph, raw: Any) -> Tuple[str, ...]:
        statements = set(FunctionIRFactService._endpoint_statements(graph, raw))
        return tuple(
            dict.fromkeys(
                statement.block_uid
                for statement in graph.statement_map.values()
                if statement.statement_uid in statements
            )
        )

    @staticmethod
    def _endpoint_statements(graph: FunctionIRGraph, raw: Any) -> Tuple[str, ...]:
        if isinstance(raw, Mapping):
            line = int(raw.get("line") or raw.get("start_line") or 0)
            name = str(raw.get("callee") or raw.get("function") or raw.get("name") or "")
            expression = str(
                raw.get("operation")
                or raw.get("expression")
                or raw.get("statement")
                or raw.get("text")
                or raw.get("code")
                or ""
            )
        else:
            text = str(raw or "")
            line_match = re.search(r"(?::|line\s+)(\d+)\b", text, re.I)
            line = int(line_match.group(1)) if line_match else 0
            names = re.findall(r"\b([A-Za-z_]\w*)\s*\(", text)
            name = names[-1] if names else ""
            expression = text
        normalized_expression = FunctionIRFactService._normalized_expression(expression)
        event_uids = {
            event.statement_uid
            for event in graph.events
            if (line and event.source_line == line) or (name and event.callee == name)
        }
        statement_uids = [
            statement.statement_uid
            for block in graph.blocks
            for statement in block.statements
            if statement.statement_uid in event_uids
            or (line and statement.source_line == line)
            or FunctionIRFactService._expressions_match(
                normalized_expression,
                FunctionIRFactService._normalized_expression(statement.text),
            )
        ]
        return tuple(dict.fromkeys(statement_uids))

    @staticmethod
    def _normalized_expression(value: Any) -> str:
        text = re.sub(r"\s+", "", str(value or "")).lower().rstrip(";")
        # A location-bearing endpoint may be serialized as a JSON identity.
        # Retain only the expression/operation value when it can be decoded.
        if text.startswith("{"):
            try:
                parsed = json.loads(str(value))
            except (TypeError, ValueError, json.JSONDecodeError):
                return text
            if isinstance(parsed, Mapping):
                return FunctionIRFactService._normalized_expression(
                    parsed.get("operation") or parsed.get("expression") or parsed.get("text")
                )
        return text

    @staticmethod
    def _expressions_match(endpoint: str, statement: str) -> bool:
        if len(endpoint) < 6 or len(statement) < 6:
            return False
        return endpoint == statement or endpoint in statement or statement in endpoint


class FactCapabilityRegistry:
    """Stable facade used by eligibility, fact-first and V3 action planning."""

    def __init__(self, service: FunctionIRFactService) -> None:
        self.service = service

    def inspect(
        self,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
        fact_kinds: Iterable[str],
    ) -> Tuple[FactCapability, ...]:
        return self.service.capabilities(issue, evidence, fact_kinds)

    def executable_actions(
        self,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
        fact_kinds: Iterable[str],
    ) -> Tuple[EvidenceAction, ...]:
        return self.service.actions(issue, evidence, fact_kinds)


def verify_certificate_v2(certificate: Mapping[str, Any]) -> bool:
    valid, _ = validate_certificate_envelope(certificate)
    if valid:
        return True
    if str(certificate.get("schema_version") or "") != EVIDENCE_CERTIFICATE_VERSION:
        return False
    supplied = str(certificate.get("certificate_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", supplied):
        return False
    body = dict(certificate)
    body.pop("certificate_sha256", None)
    return _sha(body) == supplied
