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
from threading import BoundedSemaphore, Lock
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from ...retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider
from ..candidates.decision_facts import (
    SECURITY_OBLIGATION_VERSION,
    security_obligation_for,
)
from .function_ir import FUNCTION_IR_VERSION, FunctionIREvent, FunctionIRGraph, graph_from_mapping
from .proof_kernel.checker import ProofChecker
from .proof_kernel.engine import PROOF_KERNEL_AUTHORITY_INPUT_VERSION
from .proof_kernel.models import (
    build_evidence_action as build_proof_action,
    build_proof_clause,
    build_proof_obligation,
    function_summary_from_graph,
    program_proof_ir_from_graph,
    validate_certificate_envelope,
)
from .proof_kernel.provider import ProofProvider
from .proof_kernel.registry import (
    PREDICATE_REGISTRY,
    build_cross_thread_function_ir,
    function_ir_compound_wrappers,
    qualified_bounds_options,
    qualified_command_flow_options,
    qualified_race_options,
    qualified_resource_leak_options,
    signed_unsigned_flow_options,
)


CAPABILITY_REGISTRY_VERSION = "zscope.fact-capability-registry.v1"
EVIDENCE_ACTION_VERSION = "zscope.evidence-action.v1"
EVIDENCE_CERTIFICATE_VERSION = "zscope.evidence-certificate.v2"

# A complete FunctionIR build launches two comparatively heavy Clang
# subprocesses.  The Validator may run eight independent candidates at once,
# but allowing every distinct function to launch Clang concurrently causes the
# subprocesses to contend until their fixed timeout expires.  Same-function
# locks below prevent duplicate work; this process-wide gate also bounds work
# across different FunctionIRFactService instances and different functions.
FUNCTION_IR_MAX_CONCURRENT_BUILDS = 1
_FUNCTION_IR_BUILD_SLOTS = BoundedSemaphore(FUNCTION_IR_MAX_CONCURRENT_BUILDS)

_FACT_PREDICATES = {
    "lockset": "lock_must_hold_at_access",
    "cleanup_coverage": "cleanup_covers_all_exits",
    "source_sink_reachability": "source_sink_path_exists",
    "guard_dominance": "guard_dominates_sink",
    "source_controllability": "external_entry_parameter_binding",
    "type_layout": "record_layout_matches",
    "value_range": "signed_value_reaches_unsigned_sink",
}

# Product-owned composite proof shapes.  These are vulnerability obligations,
# not a restatement of a model verdict or of a RequiredFactPlan.  Every shape
# freezes the complete set of clauses needed for one terminal decision.  A
# clause for which the current registry has no closed-world predicate remains
# in ``open_clauses`` so the sole ProofKernel reducer fails closed.
_RACE_FAMILY_TOKENS = frozenset({"race", "lock", "thread", "concurr"})
_LEAK_FAMILY_TOKENS = frozenset({"leak", "release", "acquire", "ownership", "resource", "free"})
_BOUNDS_FAMILY_TOKENS = frozenset(
    {"bound", "overflow", "length", "size", "index", "range", "integer"}
)
_DATAFLOW_FAMILY_TOKENS = frozenset(
    {"dataflow", "injection", "taint", "source", "sink", "path", "command"}
)

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


def _candidate_subject(issue: Mapping[str, Any]) -> str:
    """Rebuild the candidate subject without trusting its frozen obligation."""

    return str(
        issue.get("resource_identity")
        or issue.get("thread_object")
        or issue.get("subject_uid")
        or issue.get("resource")
        or issue.get("source_identity")
        or issue.get("source")
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


def _identity_text(value: Any) -> str:
    return str(value or "").strip().casefold()


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
        if fact_kind == "value_range":
            options = signed_unsigned_flow_options(
                function_summary_from_graph(
                    graph,
                    wrapper_summaries=function_ir_compound_wrappers(graph),
                )
            )
            fixed = {str(key): str(value) for key, value in parameters.items()}
            if fixed in options:
                return self.result(
                    graph=graph,
                    issue=issue,
                    fact_kind=fact_kind,
                    status="verified_true",
                    reason="signed_unsigned_sink_flow_recomputed",
                    predicate_value={
                        "range_violation": True,
                        "value_uid": fixed["value_uid"],
                    },
                    coverage="complete",
                )
            return self.result(
                graph=graph,
                issue=issue,
                fact_kind=fact_kind,
                status="unknown",
                reason="signed_unsigned_flow_identity_unresolved",
                predicate_value=None,
                coverage="partial",
            )
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

    def __init__(
        self,
        compile_commands_path: Optional[Path],
        *,
        enabled: bool,
        code_index: Any = None,
    ) -> None:
        self.enabled = bool(enabled)
        self._code_index = code_index
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

    @staticmethod
    def _thread_entry_target(statement: str, callee: str) -> str:
        if callee == "pthread_create":
            match = re.fullmatch(
                r"\s*pthread_create\s*\(\s*[^,()]+\s*,\s*[^,()]+\s*,\s*&?\s*"
                r"([A-Za-z_]\w*)\s*,\s*[^,()]+\s*\)\s*;?\s*",
                statement,
            )
        elif callee == "thrd_create":
            match = re.fullmatch(
                r"\s*thrd_create\s*\(\s*[^,()]+\s*,\s*&?\s*([A-Za-z_]\w*)\s*,\s*"
                r"[^,()]+\s*\)\s*;?\s*",
                statement,
            )
        else:
            return ""
        return str(match.group(1)) if match else ""

    @staticmethod
    def _same_file(left: str, right: str) -> bool:
        first = str(left or "").replace("\\", "/").lstrip("./")
        second = str(right or "").replace("\\", "/").lstrip("./")
        return bool(
            first
            and second
            and (first == second or first.endswith("/" + second) or second.endswith("/" + first))
        )

    def _unique_function_identity(
        self,
        function: str,
        file_hint: str = "",
    ) -> Optional[Dict[str, Any]]:
        finder = getattr(self._code_index, "find_function_identities", None)
        if not callable(finder):
            return None
        try:
            raw = finder(function, file_path=file_hint)
        except Exception:
            return None
        identities = [dict(value) for value in raw or [] if isinstance(value, Mapping)]
        if len(identities) != 1:
            return None
        identity = identities[0]
        if (
            str(identity.get("function_name") or "") != function
            or not str(identity.get("file_path") or "")
            or int(identity.get("start_line") or 0) <= 0
        ):
            return None
        return identity

    def _graph_for_identity(self, identity: Mapping[str, Any]) -> Optional[FunctionIRGraph]:
        return self.graph(
            {
                "function": str(identity.get("function_name") or ""),
                "function_signature": str(identity.get("function_name") or ""),
                "file": str(identity.get("file_path") or ""),
                "line": int(identity.get("start_line") or 0),
            },
            {},
        )

    def _qualified_global_binding(
        self,
        *,
        worker_identities: Sequence[Mapping[str, Any]],
        object_uid: str,
    ) -> Optional[Dict[str, Any]]:
        finder = getattr(self._code_index, "find_function_infos", None)
        if not callable(finder):
            return None
        bindings: list[Dict[str, Any]] = []
        for identity in worker_identities:
            try:
                raw_infos = finder(
                    str(identity.get("function_name") or ""),
                    file_path=str(identity.get("file_path") or ""),
                )
            except Exception:
                return None
            infos = [dict(value) for value in raw_infos or [] if isinstance(value, Mapping)]
            if len(infos) != 1 or "referenced_globals_truncation" in infos[0]:
                return None
            matches = [
                dict(value)
                for value in infos[0].get("referenced_globals") or []
                if isinstance(value, Mapping) and str(value.get("name") or "") == object_uid
            ]
            if len(matches) != 1:
                return None
            binding = matches[0]
            if (
                not str(binding.get("type") or "")
                or not str(binding.get("file_path") or "")
                or int(binding.get("line") or 0) <= 0
                or str(binding.get("access") or "") not in {"read", "write", "read_write"}
                or re.search(
                    r"\b(?:_Atomic|atomic_)\w*",
                    str(binding.get("type") or ""),
                    re.IGNORECASE,
                )
            ):
                return None
            bindings.append(binding)
        identity_keys = {
            (
                str(value.get("name") or ""),
                str(value.get("type") or ""),
                str(value.get("file_path") or "").replace("\\", "/"),
                int(value.get("line") or 0),
                str(value.get("storage_class") or ""),
                tuple(map(str, value.get("qualifiers") or [])),
            )
            for value in bindings
        }
        if len(identity_keys) != 1:
            return None
        name, type_name, file_path, line, storage_class, qualifiers = next(iter(identity_keys))
        return {
            "name": name,
            "type": type_name,
            "file_path": file_path,
            "line": line,
            "storage_class": storage_class,
            "qualifiers": list(qualifiers),
        }

    def _product_cross_thread_function_ir(
        self,
        issue: Mapping[str, Any],
        candidate_graph: FunctionIRGraph,
    ) -> Optional[Dict[str, Any]]:
        """Construct race proof input exclusively from product-owned indexes.

        Candidate evidence and Validator/model envelopes are deliberately not
        consulted.  Any ambiguity in callback registration, function identity,
        global identity, Clang graph coverage, or thread topology leaves the
        compound race clauses open.
        """

        if self._code_index is None or not self.enabled:
            return None
        candidate_function = candidate_graph.function
        object_uid = _subject(issue)
        if not re.fullmatch(r"[A-Za-z_]\w*", object_uid):
            return None
        pointer_finder = getattr(self._code_index, "find_function_pointers", None)
        if not callable(pointer_finder):
            return None
        try:
            raw_pointers = pointer_finder(candidate_function)
        except Exception:
            return None
        pointer_identities = {
            (
                str(value.get("caller") or value.get("name") or ""),
                str(value.get("file") or value.get("filename") or ""),
            )
            for value in raw_pointers or []
            if isinstance(value, Mapping)
            and str(value.get("caller") or value.get("name") or "")
            and str(value.get("file") or value.get("filename") or "")
        }
        if len(pointer_identities) != 1:
            return None
        creator_name, creator_file = next(iter(pointer_identities))
        creator_identity = self._unique_function_identity(creator_name, creator_file)
        if creator_identity is None:
            return None
        creator_graph = self._graph_for_identity(creator_identity)
        if creator_graph is None:
            return None
        worker_names = []
        for event in creator_graph.events:
            if event.kind != "thread_create":
                continue
            statement = creator_graph.statement_map.get(event.statement_uid)
            if statement is None:
                return None
            target = self._thread_entry_target(statement.text, event.callee)
            if not target:
                return None
            worker_names.append(target)
        if len(worker_names) != 2 or len(set(worker_names)) != 2:
            return None
        if candidate_function not in set(worker_names):
            return None
        worker_identities = []
        worker_graphs = []
        for worker_name in sorted(worker_names):
            identity = self._unique_function_identity(worker_name)
            if identity is None:
                return None
            worker_identities.append(identity)
            graph: Optional[FunctionIRGraph]
            if worker_name == candidate_function:
                if not self._same_file(
                    candidate_graph.file,
                    str(identity.get("file_path") or ""),
                ):
                    return None
                graph = candidate_graph
            else:
                graph = self._graph_for_identity(identity)
            if graph is None:
                return None
            worker_graphs.append(graph)
        global_binding = self._qualified_global_binding(
            worker_identities=worker_identities,
            object_uid=object_uid,
        )
        if global_binding is None:
            return None
        binding_sha = _sha(global_binding)
        project_revision_sha256 = _sha(
            {
                "creator_ir_sha256": creator_graph.ir_sha256,
                "worker_ir_sha256": sorted(value.ir_sha256 for value in worker_graphs),
                "global_binding_sha256": binding_sha,
            }
        )
        try:
            return build_cross_thread_function_ir(
                candidate_graph=candidate_graph,
                creator_graph=creator_graph,
                worker_graphs=worker_graphs,
                object_uid=object_uid,
                declaration_uid="GLOBAL_" + binding_sha[:32],
                declaration_file=str(global_binding["file_path"]),
                declaration_line=int(global_binding["line"]),
                project_revision_sha256=project_revision_sha256,
            )
        except (KeyError, TypeError, ValueError):
            return None

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
            with _FUNCTION_IR_BUILD_SLOTS:
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
        if graph is None or not graph.coverage_complete:
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
                actions.append(
                    EvidenceAction(
                        action_id="EVACTION_" + _sha(body)[:32],
                        fact_kind=fact_kind,
                        provider_id=provider.provider_id,
                        verifier_id=provider.verifier_id,
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

    @staticmethod
    def composite_family(issue: Mapping[str, Any]) -> str:
        """Return the frozen product proof shape for an ordinary candidate.

        Family selection uses only governed candidate/SecurityObligation
        fields.  It never consults a Validator verdict, answer key, or a
        post-score label.
        """

        obligation = issue.get("security_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        required = {
            _normalized(value)
            for value in (
                issue.get("obligation_required_fact_kinds")
                or obligation.get("required_fact_kinds")
                or ()
            )
            if _normalized(value)
        }
        text = " ".join(
            _normalized(value)
            for value in (
                obligation.get("defect_family"),
                issue.get("defect_family"),
                issue.get("defect_class"),
                issue.get("category"),
                issue.get("subcategory"),
                issue.get("type"),
                issue.get("rule"),
                issue.get("rule_id"),
            )
            if value
        )
        if required & {
            "lockset",
            "happens_before",
            "object_identity",
            "event:shared_state_access",
        } or any(value in text for value in _RACE_FAMILY_TOKENS):
            return "race"
        if required & {
            "cleanup_coverage",
            "ownership_transfer",
            "event:acquire",
            "event:exit",
        } or any(value in text for value in _LEAK_FAMILY_TOKENS):
            return "leak"
        if required & {"value_range", "guard_dominance"} or any(
            value in text for value in _BOUNDS_FAMILY_TOKENS
        ):
            return "bounds"
        if required & {
            "source_controllability",
            "source_sink_reachability",
            "caller_contract",
            "source",
            "sink",
        } or any(value in text for value in _DATAFLOW_FAMILY_TOKENS):
            return "dataflow"
        return ""

    @staticmethod
    def _validated_governed_obligation(
        issue: Mapping[str, Any],
    ) -> Optional[Mapping[str, Any]]:
        """Rebuild the product SecurityObligation and require exact anchors.

        ``security_obligation_v1`` is a governance assertion, not permission to
        trust an arbitrary mapping supplied by a candidate.  Rebuilding from
        the candidate's independently frozen source/sink/subject fields binds
        the region hash to those anchors before any compound clause can close.
        """

        if issue.get("security_obligation_v1") is not True:
            return None
        raw = issue.get("security_obligation")
        if not isinstance(raw, Mapping):
            return None
        source_uid = issue.get("source_identity")
        sink_uid = issue.get("sink_identity")
        subject_uid = _candidate_subject(issue)
        if (
            not isinstance(source_uid, str)
            or not source_uid
            or not isinstance(sink_uid, str)
            or not sink_uid
            or not subject_uid
        ):
            return None
        defect_family = str(issue.get("defect_class") or issue.get("category") or "")
        if not defect_family:
            return None
        try:
            expected = security_obligation_for(
                issue,
                project_id=str(issue.get("project_id") or ""),
                revision=str(issue.get("revision") or ""),
                defect_family=defect_family,
                source_uid=source_uid,
                sink_uid=sink_uid,
                subject_uid=subject_uid,
            ).to_dict()
        except (KeyError, TypeError, ValueError):
            return None
        identity_fields = (
            "version",
            "obligation_uid",
            "defect_family",
            "obligation_shape",
            "subject_uid",
            "source_uid",
            "sink_uid",
            "decision_region_uid",
        )

        def _identity_equal(raw_value: Any, expected_value: Any) -> bool:
            # A stored obligation round-trips through JSON, so its sequence
            # fields come back as lists while ``to_dict`` emits tuples.  The
            # frozen identity is the ordered content, not the container type.
            if isinstance(raw_value, (list, tuple)) and isinstance(
                expected_value, (list, tuple)
            ):
                return list(raw_value) == list(expected_value)
            return raw_value == expected_value

        if raw.get("version") != SECURITY_OBLIGATION_VERSION or any(
            not _identity_equal(raw.get(key), expected.get(key))
            for key in identity_fields
        ) or list(raw.get("required_fact_kinds") or []) != list(
            expected.get("required_fact_kinds") or []
        ):
            return None
        return raw

    @staticmethod
    def _endpoint_mapping(value: str) -> Mapping[str, Any]:
        structured = _structured_endpoint(value)
        if structured:
            return structured
        # Source-centric resource obligations use a stable
        # ``function:line:event-kind:identity`` anchor.
        parts = str(value or "").rsplit(":", 3)
        if len(parts) == 4 and parts[1].isdigit():
            return {
                "function": parts[0],
                "line": parts[1],
                "kind": parts[2],
                "resource": parts[3],
            }
        return {"identity": str(value or "")} if str(value or "") else {}

    @staticmethod
    def _semantic_anchor_matches(text: str, expected: Any) -> bool:
        def normalized(value: Any) -> str:
            return re.sub(r"\s+", "", _identity_text(value)).replace("->", ".")

        needle = normalized(expected)
        haystack = normalized(text)
        if not needle or not haystack:
            return False
        if re.fullmatch(r"[a-z_]\w*", needle):
            return re.search(rf"\b{re.escape(needle)}\b", haystack) is not None
        return needle in haystack

    @classmethod
    def _endpoint_matches_graph_anchor(
        cls,
        endpoint_uid: str,
        graph: FunctionIRGraph,
        *,
        event_uid: str = "",
        statement_uid: str = "",
    ) -> bool:
        endpoint = cls._endpoint_mapping(endpoint_uid)
        if not endpoint:
            return False
        event = next(
            (value for value in graph.events if value.event_uid == event_uid),
            None,
        )
        if event_uid and event is None:
            return False
        resolved_statement_uid = statement_uid or (event.statement_uid if event is not None else "")
        statement = graph.statement_map.get(resolved_statement_uid)
        if resolved_statement_uid and statement is None:
            return False

        imposed = 0
        endpoint_file = str(endpoint.get("file") or endpoint.get("file_path") or "")
        if endpoint_file:
            imposed += 1
            if not cls._same_file(endpoint_file, graph.file):
                return False
        endpoint_function = str(endpoint.get("function") or "")
        if endpoint_function:
            imposed += 1
            normalized = _identity_text(endpoint_function).split("(", 1)[0]
            if normalized != _identity_text(graph.function).split("(", 1)[0]:
                return False
        try:
            endpoint_line = int(endpoint.get("line") or 0)
        except (TypeError, ValueError):
            return False
        if endpoint_line:
            imposed += 1
            actual_line = int(
                (event.source_line if event is not None else 0)
                or (statement.source_line if statement is not None else 0)
                or 0
            )
            if actual_line != endpoint_line:
                return False

        semantic_values = [
            endpoint.get(key)
            for key in (
                "expression",
                "operation",
                "object",
                "object_id",
                "resource",
                "symbol",
                "field",
                "identity",
            )
            if endpoint.get(key) not in (None, "")
        ]
        if semantic_values:
            imposed += len(semantic_values)
            searchable = " ".join(
                [
                    statement.text if statement is not None else "",
                    event.callee if event is not None else "",
                    *(event.subject_symbols if event is not None else ()),
                ]
            )
            if not all(
                cls._semantic_anchor_matches(searchable, value) for value in semantic_values
            ):
                return False
        endpoint_kind = _identity_text(endpoint.get("kind"))
        if endpoint_kind and endpoint_kind not in {"source", "sink", "event"}:
            imposed += 1
            actual_kind = _identity_text(event.kind if event is not None else "access")
            if endpoint_kind not in actual_kind and actual_kind not in endpoint_kind:
                return False
        return imposed > 0

    @classmethod
    def _governed_option_anchors_match(
        cls,
        *,
        family: str,
        obligation: Mapping[str, Any],
        graph: FunctionIRGraph,
        parameters: Mapping[str, Any],
        cross_thread_ir: Optional[Mapping[str, Any]],
    ) -> bool:
        source_uid = str(obligation.get("source_uid") or "")
        sink_uid = str(obligation.get("sink_uid") or "")
        if family in {"bounds", "dataflow"}:
            return bool(
                cls._endpoint_matches_graph_anchor(
                    source_uid,
                    graph,
                    event_uid=str(parameters.get("source_event_uid") or ""),
                )
                and cls._endpoint_matches_graph_anchor(
                    sink_uid,
                    graph,
                    event_uid=str(parameters.get("sink_event_uid") or ""),
                )
            )
        if family == "leak":
            return cls._endpoint_matches_graph_anchor(
                source_uid,
                graph,
                event_uid=str(parameters.get("acquisition_event_uid") or ""),
            )
        if family != "race" or not isinstance(cross_thread_ir, Mapping):
            return False
        worker_graphs = []
        for value in cross_thread_ir.get("worker_graphs") or []:
            if not isinstance(value, Mapping):
                return False
            try:
                restored = graph_from_mapping(value)
            except (KeyError, TypeError, ValueError):
                return False
            if restored is None:
                return False
            worker_graphs.append(restored)
        by_function = {value.function: value for value in worker_graphs}
        left = by_function.get(str(parameters.get("left_function_uid") or ""))
        right = by_function.get(str(parameters.get("right_function_uid") or ""))
        if left is None or right is None or left is right:
            return False
        left_statement_uid = str(parameters.get("left_statement_uid") or "")
        right_statement_uid = str(parameters.get("right_statement_uid") or "")
        return bool(
            (
                cls._endpoint_matches_graph_anchor(
                    source_uid,
                    left,
                    statement_uid=left_statement_uid,
                )
                and cls._endpoint_matches_graph_anchor(
                    sink_uid,
                    right,
                    statement_uid=right_statement_uid,
                )
            )
            or (
                cls._endpoint_matches_graph_anchor(
                    source_uid,
                    right,
                    statement_uid=right_statement_uid,
                )
                and cls._endpoint_matches_graph_anchor(
                    sink_uid,
                    left,
                    statement_uid=left_statement_uid,
                )
            )
        )

    @staticmethod
    def _open_composite_clause(
        *,
        semantic_id: str,
        provider_family: str,
        fact_kind: str,
        quantifier: str,
        expected_value: Any,
        parameters: Mapping[str, Any],
    ) -> Dict[str, Any]:
        return build_proof_clause(
            role="open",
            provider_family=provider_family,
            predicate_id=f"zscope.composite.{semantic_id}.v1",
            fact_kind=fact_kind,
            quantifier=quantifier,
            expected_value=expected_value,
            parameters=parameters,
        )

    @staticmethod
    def _proof_parameters_for_action(
        graph: FunctionIRGraph,
        action: EvidenceAction,
    ) -> Optional[Dict[str, Any]]:
        """Project a fact action onto the frozen ProofKernel predicate schema."""

        predicate_id = _FACT_PREDICATES.get(action.fact_kind)
        spec = PREDICATE_REGISTRY.get(predicate_id or "")
        if spec is None:
            return None
        fixed = dict(action.fixed_parameters)
        if predicate_id == "source_sink_path_exists":
            source_statement = str(fixed.pop("source_statement_uid", ""))
            sink_statement = str(fixed.pop("sink_statement_uid", ""))
            if source_statement:
                statement = graph.statement_map.get(source_statement)
                fixed["source_node_uid"] = statement.block_uid if statement else ""
            if sink_statement:
                statement = graph.statement_map.get(sink_statement)
                fixed["sink_node_uid"] = statement.block_uid if statement else ""
            fixed.setdefault("source_node_uid", str(fixed.pop("source_block_uid", "")))
            fixed.setdefault("sink_node_uid", str(fixed.pop("sink_block_uid", "")))
        elif predicate_id == "cleanup_covers_all_exits":
            fixed = {"resource_uid": str(fixed.get("resource_symbol") or "")}
        elif predicate_id == "lock_must_hold_at_access":
            locks = tuple(
                dict.fromkeys(
                    symbol
                    for event in graph.events
                    if event.kind in {"lock_acquire", "lock_release"}
                    for symbol in event.subject_symbols
                )
            )
            if "lock_uid" not in fixed and len(locks) == 1:
                fixed["lock_uid"] = locks[0]
        if set(fixed) != set(spec.parameter_keys) or any(
            value in (None, "") for value in fixed.values()
        ):
            return None
        return fixed

    def proof_parameters_for_action(
        self,
        action: EvidenceAction,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        predicate_id = _FACT_PREDICATES.get(action.fact_kind)
        spec = PREDICATE_REGISTRY.get(predicate_id or "")
        supplied = dict(action.fixed_parameters)
        if (
            spec is not None
            and set(supplied) == set(spec.parameter_keys)
            and all(value not in (None, "") for value in supplied.values())
        ):
            return supplied
        graph = self.graph(issue, evidence)
        if graph is None or not graph.coverage_complete:
            return None
        return self._proof_parameters_for_action(graph, action)

    def build_composite_proof_input(
        self,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Build one content-addressed v4 obligation for a Validator candidate.

        The returned mapping has the same strict shape as a Hunter
        ``proof_kernel_input``.  All executable clauses come from the frozen
        FunctionIR action catalog.  Unsupported clauses remain explicit open
        clauses, so a partial fact plan can never become a terminal proof.
        """

        family = self.composite_family(issue)
        governed_obligation = (
            self._validated_governed_obligation(issue)
            if issue.get("security_obligation_v1") is True
            else None
        )
        if issue.get("security_obligation_v1") is True and governed_obligation is None:
            return None
        graph = self.graph(issue, evidence)
        subject_uid = str(
            governed_obligation.get("subject_uid")
            if governed_obligation is not None
            else _subject(issue)
        )
        region_uid = str(
            governed_obligation.get("decision_region_uid")
            if governed_obligation is not None
            else _region(issue)
        )
        if not family or graph is None or not graph.coverage_complete:
            return None
        if not subject_uid or not region_uid:
            return None
        product_cross_thread_ir = (
            self._product_cross_thread_function_ir(issue, graph) if family == "race" else None
        )
        proof_ir = program_proof_ir_from_graph(
            graph,
            project_uid="PROJECT_" + _sha({"file": graph.file})[:32],
            revision_uid="REV_" + graph.code_snapshot_sha256[:32],
            wrapper_summaries=function_ir_compound_wrappers(
                graph,
                cross_thread_function_ir=product_cross_thread_ir,
            ),
        )
        confirmation: list[Dict[str, Any]] = []
        counterproof: list[Dict[str, Any]] = []
        open_clauses: list[Dict[str, Any]] = []

        def open_clause(
            semantic_id: str,
            provider_family: str,
            fact_kind: str,
            quantifier: str,
            expected_value: Any,
        ) -> None:
            open_clauses.append(
                self._open_composite_clause(
                    semantic_id=semantic_id,
                    provider_family=provider_family,
                    fact_kind=fact_kind,
                    quantifier=quantifier,
                    expected_value=expected_value,
                    parameters={
                        "subject_uid": subject_uid,
                        "decision_region_uid": region_uid,
                    },
                )
            )

        def exact_action(fact_kind: str) -> tuple[EvidenceAction, Dict[str, Any]] | None:
            normalized = []
            for action in self.actions(issue, evidence, (fact_kind,)):
                parameters = self._proof_parameters_for_action(graph, action)
                if parameters is not None:
                    normalized.append((action, parameters))
            return normalized[0] if len(normalized) == 1 else None

        def executable_clause(
            fact_kind: str,
            expected_value: Any,
        ) -> bool:
            selected = exact_action(fact_kind)
            predicate_id = _FACT_PREDICATES.get(fact_kind)
            spec = PREDICATE_REGISTRY.get(predicate_id or "")
            if selected is None or spec is None:
                return False
            _action, parameters = selected
            confirmation.append(
                build_proof_clause(
                    role="confirmation",
                    provider_family=spec.provider_family,
                    predicate_id=spec.predicate_id,
                    fact_kind=spec.fact_kind,
                    quantifier=spec.quantifier,
                    expected_value=expected_value,
                    parameters=parameters,
                )
            )
            return True

        def registered_clause(
            predicate_id: str,
            expected_value: Any,
            parameters: Mapping[str, Any],
            *,
            role: str = "confirmation",
        ) -> None:
            spec = PREDICATE_REGISTRY[predicate_id]
            target = confirmation if role == "confirmation" else counterproof
            target.append(
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

        summary = proof_ir["functions"][0]
        compound_closed = False
        if family == "race":
            options = qualified_race_options(summary)
            matching = [
                value
                for value in options
                if str(value["fixed_parameters"].get("object_uid") or "") == subject_uid
                and (
                    governed_obligation is None
                    or self._governed_option_anchors_match(
                        family=family,
                        obligation=governed_obligation,
                        graph=graph,
                        parameters=value["fixed_parameters"],
                        cross_thread_ir=product_cross_thread_ir,
                    )
                )
            ]
            if len(matching) == 1:
                parameters = matching[0]["fixed_parameters"]
                for predicate_id, expected_value in (
                    (
                        "qualified_race_shared_object_identity",
                        {"shared_object_identity": True},
                    ),
                    (
                        "qualified_race_conflicting_accesses",
                        {"conflicting_accesses": True},
                    ),
                    (
                        "qualified_race_cross_thread_reachability",
                        {"cross_thread_reachable": True},
                    ),
                    (
                        "qualified_race_empty_locksets",
                        {"must_hold_locks": []},
                    ),
                    (
                        "qualified_race_no_happens_before",
                        {"happens_before": False},
                    ),
                ):
                    registered_clause(predicate_id, expected_value, parameters)
                compound_closed = True
        elif family == "bounds":
            options = [
                value
                for value in qualified_bounds_options(summary)
                if str(value.get("value_uid") or "") == subject_uid
                and (
                    governed_obligation is None
                    or self._governed_option_anchors_match(
                        family=family,
                        obligation=governed_obligation,
                        graph=graph,
                        parameters=value,
                        cross_thread_ir=product_cross_thread_ir,
                    )
                )
            ]
            if len(options) == 1:
                parameters = options[0]
                for predicate_id, expected_value in (
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
                ):
                    registered_clause(predicate_id, expected_value, parameters)
                compound_closed = True
        elif family == "dataflow":
            options = [
                value
                for value in qualified_command_flow_options(summary)
                if str(value.get("value_uid") or "") == subject_uid
                and (
                    governed_obligation is None
                    or self._governed_option_anchors_match(
                        family=family,
                        obligation=governed_obligation,
                        graph=graph,
                        parameters=value,
                        cross_thread_ir=product_cross_thread_ir,
                    )
                )
            ]
            if len(options) == 1:
                parameters = options[0]
                for predicate_id, expected_value in (
                    (
                        "qualified_command_source_controllable",
                        {"source_controllable": True},
                    ),
                    ("qualified_command_path_complete", {"path_exists": True}),
                    (
                        "qualified_command_sink_contract",
                        {"dangerous_sink_contract": True},
                    ),
                    (
                        "qualified_command_counterproof_absent",
                        {"guard_or_sanitizer_counterproof_absent": True},
                    ),
                ):
                    registered_clause(predicate_id, expected_value, parameters)
                compound_closed = True
        elif family == "leak":
            matching = [
                value
                for value in qualified_resource_leak_options(summary)
                if str(value["fixed_parameters"].get("resource_uid") or "") == subject_uid
                and (
                    governed_obligation is None
                    or self._governed_option_anchors_match(
                        family=family,
                        obligation=governed_obligation,
                        graph=graph,
                        parameters=value["fixed_parameters"],
                        cross_thread_ir=product_cross_thread_ir,
                    )
                )
            ]
            if len(matching) == 1:
                parameters = matching[0]["fixed_parameters"]
                actual = matching[0]["actual"]
                if actual.get("cleanup_complete") is True:
                    # A proved cleanup is an alternative terminal obligation,
                    # never a simultaneously required confirmation clause.
                    registered_clause(
                        "qualified_leak_cleanup_complete",
                        {"cleanup_complete": True},
                        parameters,
                        role="counterproof",
                    )
                    compound_closed = True
                elif (
                    actual.get("outstanding_on_reachable_exit") is True
                    and actual.get("ownership_transfer_excluded") is True
                ):
                    for predicate_id, expected_value in (
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
                    ):
                        registered_clause(predicate_id, expected_value, parameters)
                    compound_closed = True

        if compound_closed:
            pass
        elif family == "race":
            # Five independent conditions are required.  The current registry
            # cannot establish cross-thread alias/conflict/reachability/HB.
            open_clause(
                "race.shared_object_identity",
                "contract_type",
                "object_identity",
                "exact_binding",
                {"shared_object_identity": True},
            )
            open_clause(
                "race.conflicting_accesses",
                "concurrency",
                "conflicting_accesses",
                "must_at_point",
                {"conflicting_accesses": True},
            )
            open_clause(
                "race.cross_thread_reachability",
                "concurrency",
                "cross_thread_reachability",
                "exists_path",
                {"cross_thread_reachable": True},
            )
            if not executable_clause("lockset", {"must_hold": False, "must_hold_locks": []}):
                open_clause(
                    "race.empty_lockset",
                    "concurrency",
                    "lockset",
                    "must_at_point",
                    {"must_hold_locks": []},
                )
            open_clause(
                "race.no_happens_before",
                "concurrency",
                "happens_before",
                "for_all_paths",
                {"happens_before": False},
            )
        elif family in {"dataflow", "bounds"}:
            if not executable_clause(
                "source_controllability", {"external_entry_parameter_bound": True}
            ):
                open_clause(
                    f"{family}.controllable_source",
                    "contract_type",
                    "source_controllability",
                    "exact_binding",
                    {"source_controllable": True},
                )
            if not executable_clause("source_sink_reachability", {"path_exists": True}):
                open_clause(
                    f"{family}.complete_source_sink_path",
                    "path_guard",
                    "source_sink_reachability",
                    "exists_path",
                    {"path_exists": True},
                )
            open_clause(
                f"{family}.sink_contract",
                "contract_type",
                "caller_contract",
                "exact_binding",
                {"dangerous_sink_contract": True},
            )
            terminal_fact = "value_range" if family == "bounds" else "guard_dominance"
            terminal_expected = (
                {"range_violation": True} if family == "bounds" else {"guard_dominates_sink": False}
            )
            if not executable_clause(terminal_fact, terminal_expected):
                open_clause(
                    f"{family}.guard_or_value_range",
                    "path_guard",
                    terminal_fact,
                    "exists_path" if terminal_fact == "value_range" else "for_all_paths",
                    terminal_expected,
                )
        elif family == "leak":
            open_clause(
                "leak.acquisition_identity",
                "contract_type",
                "object_identity",
                "exact_binding",
                {"exact_acquisition_identity": True},
            )
            if not executable_clause("cleanup_coverage", {"cleanup_complete": False}):
                open_clause(
                    "leak.outstanding_on_reachable_exit",
                    "resource",
                    "cleanup_coverage",
                    "for_all_exits",
                    {"cleanup_complete": False},
                )
            open_clause(
                "leak.ownership_transfer_excluded",
                "resource",
                "ownership_transfer",
                "for_all_paths",
                {"ownership_transferred": False},
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
            defect_family=str(
                security_obligation.get("defect_family")
                or issue.get("defect_family")
                or issue.get("defect_class")
                or issue.get("category")
                or family
            ),
            subject_uid=subject_uid,
            decision_region_uid=region_uid,
            confirmation_clauses=confirmation,
            counterproof_clauses=counterproof,
            open_clauses=open_clauses,
            dependency_hashes=proof_ir["dependency_hashes"],
        )
        selected_action_uids = [
            str(
                build_proof_action(
                    obligation=obligation,
                    clause=clause,
                    proof_ir=proof_ir,
                    provider_id=PREDICATE_REGISTRY[str(clause["predicate_id"])].provider_id,
                    verifier_id=PREDICATE_REGISTRY[str(clause["predicate_id"])].verifier_id,
                )["action_uid"]
            )
            for clause in (*confirmation, *counterproof)
        ]
        return {
            "schema_version": PROOF_KERNEL_AUTHORITY_INPUT_VERSION,
            "proof_ir": proof_ir,
            "proof_obligation": obligation,
            "selected_action_uids": selected_action_uids,
        }

    def execute(
        self,
        action: EvidenceAction,
        issue: Mapping[str, Any],
        evidence: Optional[Mapping[str, Any]],
    ) -> CertificateResult:
        graph = self.graph(issue, evidence)
        if graph is None:
            return self._unavailable_result(action, "function_ir_unavailable")
        if not graph.coverage_complete:
            return self._unavailable_result(action, "function_ir_cfg_incomplete")
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
        decision_proof = (
            stable_result.fact.get("deterministic_proof")
            if isinstance(stable_result.fact, Mapping)
            else None
        )
        artifacts = self._compile_terminal_proof_artifacts(
            graph=graph,
            issue=issue,
            fact_kind=action.fact_kind,
            parameters=parameters,
            decision_proof=(decision_proof if isinstance(decision_proof, Mapping) else None),
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
    def _compile_terminal_proof_artifacts(
        *,
        graph: FunctionIRGraph,
        issue: Mapping[str, Any],
        fact_kind: str,
        parameters: Mapping[str, Any],
        decision_proof: Mapping[str, Any] | None,
    ) -> Optional[Dict[str, Dict[str, Any]]]:
        if not decision_proof:
            return None
        outcome = str(decision_proof.get("outcome") or "")
        proof_kind = str(decision_proof.get("proof_kind") or "")
        terminal_contracts: dict[tuple[str, str, str], tuple[str, Mapping[str, Any]]] = {
            (
                "cleanup_coverage",
                "confirm",
                "missing_cleanup_path",
            ): ("confirmation", {"cleanup_complete": False}),
            (
                "cleanup_coverage",
                "reject",
                "ownership_cleanup_complete",
            ): ("counterproof", {"cleanup_complete": True}),
            (
                "source_sink_reachability",
                "reject",
                "sink_unreachable",
            ): ("counterproof", {"path_exists": False}),
            (
                "value_range",
                "confirm",
                "signed_value_reaches_unsigned_sink",
            ): ("confirmation", {"range_violation": True}),
        }
        terminal_contract = terminal_contracts.get((fact_kind, outcome, proof_kind))
        if terminal_contract is None:
            return None
        role, expected_value = terminal_contract
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
            wrapper_summaries=function_ir_compound_wrappers(graph),
        )
        clause = build_proof_clause(
            role=role,
            provider_family=spec.provider_family,
            predicate_id=spec.predicate_id,
            fact_kind=spec.fact_kind,
            quantifier=spec.quantifier,
            expected_value=expected_value,
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
            defect_family=str(
                issue.get("defect_family")
                or issue.get("defect_class")
                or issue.get("category")
                or issue.get("type")
                or "generic"
            ),
            subject_uid=subject_uid,
            decision_region_uid=region_uid,
            confirmation_clauses=((clause,) if role == "confirmation" else ()),
            counterproof_clauses=((clause,) if role == "counterproof" else ()),
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
                            else (
                                "function_ir_cfg_incomplete"
                                if not graph.coverage_complete
                                else "subject_region_not_executable"
                            )
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
        elif fact_kind == "value_range" and value.get("range_violation") is True:
            outcome = "confirm"
            proof_kind = "signed_value_reaches_unsigned_sink"
            facts = ["signed_source_value", "unsigned_length_sink", "range_guard_absent"]
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
        if fact_kind == "value_range":
            summary = function_summary_from_graph(
                graph,
                wrapper_summaries=function_ir_compound_wrappers(graph),
            )
            return tuple(signed_unsigned_flow_options(summary))[:16]
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
        if fact_kind in {"caller_contract", "object_identity", "ownership_transfer"}:
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
