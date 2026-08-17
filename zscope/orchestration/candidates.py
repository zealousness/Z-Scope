"""Candidate registration and lifecycle ledger."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, cast

from .candidate_envelope import (
    CANDIDATE_SCHEMA_VERSION,
    DECISION_CONTEXT_VERSION,
    annotate_issue_identity,
    context_signature_for,
    occurrence_uid_for,
    validation_cluster_uid_for,
)
from .decision_trace import DecisionTraceStore
from ..reporting.attribution import (
    FindingAttribution,
    finding_attribution_mapping_errors,
)


TERMINAL_DISPOSITIONS = frozenset(
    {
        "confirmed",
        "rejected_with_proof",
        "needs_review",
        "deferred_budget",
        "engine_failed",
        "interrupted",
        "deduplicated_alias",
        "shadow_observation",
    }
)
NONTERMINAL_STATUSES = frozenset({"pending", "queued", "planned", "running"})


@dataclass
class CandidateTicket:
    """Structured data accepted by the Candidate Ledger.

    Candidate tickets have no worker-spawn or model-execution semantics. They
    are emitted by deterministic providers or registrars and consumed only by
    the shared lifecycle ledger.
    """

    id: str
    skill: str
    task: str
    trigger: str
    line: int
    context_slice: str
    priority_score: int = 0
    priority_reasons: List[str] = field(default_factory=list)
    origin: str = ""
    sink: str = ""
    resource_kind: str = ""
    source: str = "source_rule"
    sources: List[str] = field(default_factory=list)
    call_paths: List[List[str]] = field(default_factory=list)
    dedup_key: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "skill": self.skill,
            "task": self.task,
            "trigger": self.trigger,
            "line": self.line,
            "context_slice": self.context_slice,
            "priority_score": self.priority_score,
            "priority_reasons": self.priority_reasons or [],
            "origin": self.origin,
            "sink": self.sink,
            "resource_kind": self.resource_kind,
            "source": self.source,
            "sources": self.sources or ([self.source] if self.source else []),
            "call_paths": self.call_paths or [],
            "dedup_key": self.dedup_key,
            "evidence": self.evidence or {},
        }


def _as_dict(value: Any) -> Dict[str, Any]:
    """Narrow candidate evidence mappings while preserving mutability."""
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


@dataclass(frozen=True)
class CandidateRegistrationResult:
    """Summary returned by the shared candidate-to-ledger boundary."""

    submitted_issue_count: int
    registered_occurrence_count: int
    new_validation_group_count: int
    candidate_ids: Tuple[str, ...]


class CandidateRegistrar:
    """Canonical boundary for turning untrusted observations into obligations.

    Producers are deliberately not allowed to mutate ledger lifecycle state.
    In particular, an LLM discovery hypothesis enters as an open validation
    obligation even if its source payload claims a confirmed verdict.  Only
    the Validator-owned lifecycle path may later assign a terminal
    disposition.
    """

    def __init__(
        self,
        ledger: "CandidateLedger",
        *,
        project_id: str = "",
        project_root: str = "",
        revision: str = "",
        run_id: str = "",
        decision_fact_cache: Any = None,
    ) -> None:
        self.ledger = ledger
        self.project_id = str(project_id or ledger.project_id)
        self.project_root = str(project_root or ledger.project_root)
        self.revision = str(revision or ledger.revision)
        self.run_id = str(run_id or "")
        self.decision_fact_cache = decision_fact_cache

    @staticmethod
    def _ensure_explicit_attribution(issue: Dict[str, Any], *, producer_source: str) -> None:
        """Attach a strict v1 attribution before the candidate enters the Ledger.

        Existing producers may still describe provenance through legacy
        ``candidate_source``/``candidate_kind``/rule fields.  Those fields stay
        untouched and are used only to construct the explicit contract when it
        is absent.  A producer that already supplies ``attribution`` must supply
        a valid, versioned object; silently repairing a malformed explicit
        object would make formal attribution coverage unauditable.
        """

        explicit = issue.get("attribution")
        if explicit is not None:
            if not isinstance(explicit, Mapping):
                raise ValueError("candidate attribution must be an object")
            errors = finding_attribution_mapping_errors(explicit)
            if errors:
                raise ValueError("invalid candidate attribution: " + "; ".join(errors))
            issue["attribution"] = FindingAttribution.from_mapping(explicit).to_dict()
            return

        evidence_pack = issue.get("evidence_pack")
        evidence_pack = evidence_pack if isinstance(evidence_pack, Mapping) else {}
        evidence_sources = issue.get("evidence_sources")
        legacy_evidence_sources: Tuple[Any, ...]
        if isinstance(evidence_sources, str):
            legacy_evidence_sources = (evidence_sources,)
        elif isinstance(evidence_sources, (list, tuple, set, frozenset)):
            legacy_evidence_sources = tuple(evidence_sources)
        else:
            legacy_evidence_sources = ()
        raw_sources = [
            producer_source,
            issue.get("candidate_source"),
            issue.get("candidate_kind"),
            issue.get("finding_kind"),
            issue.get("signal_source"),
            evidence_pack.get("candidate_source"),
            evidence_pack.get("signal_source"),
            *legacy_evidence_sources,
        ]
        normalized = {
            str(value or "").strip().lower().replace("-", "_") for value in raw_sources if value
        }
        discovered: set[str] = set()
        if any(
            "active_discovery" in value
            or "llm_observation" in value
            or value == "llm_active_discovery"
            for value in normalized
        ):
            discovered.add("llm_active_discovery")
        if any(
            "backend_signal" in value or value.startswith(("svf", "saber", "joern"))
            for value in normalized
        ):
            discovered.add("backend_signal")
        if (
            issue.get("rule")
            or issue.get("rule_id")
            or any(
                value == "deterministic_rule"
                or value.endswith("_rule")
                or value.startswith(("clang_", "cpp_", "java_local"))
                for value in normalized
            )
        ):
            discovered.add("deterministic_rule")
        if not discovered:
            raise ValueError(
                "candidate attribution cannot be inferred from legacy provenance fields"
            )

        detail_ids = {
            "llm_active_discovery": str(
                issue.get("audit_unit_uid")
                or issue.get("audit_unit_id")
                or issue.get("id")
                or producer_source
            ),
            "backend_signal": str(
                issue.get("signal_source") or issue.get("native_rule_id") or producer_source
            ),
            "deterministic_rule": str(issue.get("rule_id") or issue.get("rule") or producer_source),
        }
        issue["attribution"] = FindingAttribution(
            discovered_by=tuple(discovered),
            discovery_details=tuple(
                {"kind": kind, "source_id": detail_ids[kind]} for kind in sorted(discovered)
            ),
        ).to_dict()

    def register_issues(
        self,
        issues: Iterable[Dict[str, Any]],
        *,
        source: str,
        default_entry_identity: str = "",
        force_unconfirmed: bool = False,
    ) -> CandidateRegistrationResult:
        submitted = 0
        occurrences = 0
        new_groups = 0
        candidate_ids: List[str] = []
        for ordinal, issue in enumerate(issues):
            if not isinstance(issue, dict):
                continue
            submitted += 1
            entry_identity = str(
                issue.get("entry_identity")
                or issue.get("entry_function")
                or issue.get("entry_func")
                or default_entry_identity
                or "__project__"
            )
            issue["entry_identity"] = entry_identity
            self._ensure_explicit_attribution(issue, producer_source=source)
            issue["record_role"] = "validation_obligation"
            issue["decision_fact_graph_v1"] = True
            issue["security_obligation_v1"] = True
            issue["decision_context_v31"] = True
            issue["decision_context_v32"] = True
            issue["decision_context_v33"] = True
            if force_unconfirmed:
                # These fields are producer assertions, not proof.  Keeping
                # them would allow an active-discovery model to bypass the
                # shared Validator's only terminal-disposition boundary.
                for key in (
                    "confirmed",
                    "is_confirmed",
                    "status",
                    "verdict",
                    "terminal_disposition",
                ):
                    issue.pop(key, None)
                issue["candidate_disposition"] = "needs_review"
                issue["discovery_status"] = "hypothesis"

            envelope = annotate_issue_identity(
                issue,
                project_id=self.project_id,
                project_root=self.project_root,
                revision=self.revision,
                entry_function=entry_identity,
                run_id=self.run_id,
                ordinal=ordinal,
                default_disposition="needs_review",
                decision_fact_cache=self.decision_fact_cache,
            )
            if force_unconfirmed and str(issue.get("rollout_visibility") or "").lower() == "shadow":
                # Decision-fact attachment owns its general promotion fields,
                # but a release rollout shadow is a stronger, independent
                # visibility gate.  Re-assert it at the registrar boundary so
                # no producer or fact refresh can promote the hypothesis.
                issue["candidate_promotion_eligible"] = False
                issue["candidate_promotion_reason"] = "active_discovery_rollout_shadow"
                issue["candidate_promotion_terminal_status"] = "shadow_observation"
            evidence = dict(issue.get("evidence_pack") or {})
            evidence.update(
                {
                    "candidate_id": str(issue.get("candidate_id") or issue.get("id") or ""),
                    "candidate_schema_version": envelope.schema_version,
                    "candidate_uid": envelope.candidate_uid,
                    "occurrence_uid": envelope.occurrence_uid,
                    "history_key": envelope.history_key,
                    "obligation_uid": envelope.obligation_uid,
                    "obligation_shape": envelope.obligation_shape,
                    "decision_context_version": envelope.decision_context_version,
                    "decision_fact_version": issue.get("decision_fact_version")
                    or envelope.decision_fact_version,
                    "decision_fact_coverage": issue.get("decision_fact_coverage"),
                    "decision_fact_slice": deepcopy(issue.get("decision_fact_slice") or {}),
                    "missing_fact_kinds": list(issue.get("missing_fact_kinds") or []),
                    "security_obligation": deepcopy(issue.get("security_obligation") or {}),
                    "candidate_promotion_eligible": issue.get("candidate_promotion_eligible"),
                    "candidate_promotion_reason": issue.get("candidate_promotion_reason"),
                    "candidate_promotion_terminal_status": issue.get(
                        "candidate_promotion_terminal_status"
                    ),
                    "evidence_hash": envelope.evidence_hash,
                    "decision_evidence_hash": envelope.decision_evidence_hash,
                    "provenance_hash": envelope.provenance_hash,
                    "validation_cluster_uid": envelope.validation_cluster_uid,
                    "context_signature": envelope.context_signature,
                    "entry_identity": entry_identity,
                    "record_role": "validation_obligation",
                    "defect_class": str(
                        issue.get("defect_class")
                        or issue.get("subcategory")
                        or issue.get("category")
                        or "security_review"
                    ),
                    "source": issue.get("source") or evidence.get("source"),
                    "sink": issue.get("sink") or evidence.get("sink"),
                    "resource": issue.get("resource_signature")
                    or issue.get("resource")
                    or evidence.get("resource"),
                    "positive_evidence": issue.get("positive_evidence") or [],
                    "negative_evidence": issue.get("negative_evidence") or [],
                    "candidate_payload": {
                        key: deepcopy(value)
                        for key, value in issue.items()
                        if key not in {"evidence_pack", "code_snippet", "candidate_payload"}
                    },
                }
            )
            raw_paths = issue.get("call_paths")
            if isinstance(raw_paths, list) and raw_paths and isinstance(raw_paths[0], list):
                call_paths = raw_paths
            else:
                raw_path = issue.get("call_path")
                call_paths = [raw_path] if isinstance(raw_path, list) else []
            if not call_paths:
                entry_paths = issue.get("entry_paths")
                if (
                    isinstance(entry_paths, list)
                    and entry_paths
                    and isinstance(entry_paths[0], list)
                ):
                    call_paths = entry_paths
            if not call_paths:
                call_paths = [[entry_identity]]

            for raw_path in call_paths:
                call_path = [str(item) for item in raw_path if str(item)]
                if not call_path:
                    call_path = [entry_identity]
                ticket = CandidateTicket(
                    id=str(issue.get("candidate_id") or issue.get("id") or envelope.run_issue_uid),
                    skill=str(
                        issue.get("skill")
                        or issue.get("defect_class")
                        or issue.get("subcategory")
                        or issue.get("category")
                        or "security_review"
                    ),
                    task=str(
                        issue.get("description") or issue.get("root_cause") or "Validate candidate"
                    ),
                    trigger=str(
                        issue.get("rule") or issue.get("sink") or issue.get("category") or ""
                    ),
                    line=self._line_number(issue),
                    context_slice=str(issue.get("code_snippet") or ""),
                    priority_score=self.priority_score(issue),
                    priority_reasons=[str(source)],
                    origin=str(issue.get("source") or issue.get("location") or ""),
                    sink=str(issue.get("sink") or issue.get("location") or ""),
                    resource_kind=str(
                        issue.get("resource_signature") or issue.get("resource") or "unknown"
                    ),
                    source=str(issue.get("candidate_source") or source),
                    evidence=dict(evidence),
                )
                record, is_new = self.ledger.add(
                    ticket,
                    source=str(issue.get("candidate_source") or source),
                    call_path=call_path,
                    record_role="validation_obligation",
                    entry_identity=entry_identity,
                )
                occurrences += 1
                if is_new:
                    new_groups += 1
                if record.candidate_id not in candidate_ids:
                    candidate_ids.append(record.candidate_id)
                if force_unconfirmed and record.disposition:
                    raise RuntimeError(
                        "candidate registrar assigned a terminal disposition to a hypothesis"
                    )

        return CandidateRegistrationResult(
            submitted_issue_count=submitted,
            registered_occurrence_count=occurrences,
            new_validation_group_count=new_groups,
            candidate_ids=tuple(candidate_ids),
        )

    @staticmethod
    def _line_number(issue: Mapping[str, Any]) -> int:
        explicit = issue.get("line")
        if explicit not in (None, ""):
            try:
                return max(0, int(str(explicit)))
            except (TypeError, ValueError):
                pass
        matches = re.findall(r":(\d+)(?::|\b)", str(issue.get("location") or ""))
        return int(matches[-1]) if matches else 0

    @staticmethod
    def priority_score(issue: Mapping[str, Any]) -> int:
        explicit = issue.get("priority_score")
        if explicit not in (None, ""):
            try:
                return max(0, min(100, int(float(str(explicit)))))
            except (TypeError, ValueError):
                pass
        severity = str(issue.get("impact_level") or "").lower()
        base = {"critical": 95, "high": 85, "medium": 65, "low": 35}.get(severity, 60)
        try:
            confidence = float(issue.get("rule_confidence") or issue.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        return max(base, min(100, int(round(confidence * 100))))


@dataclass(frozen=True)
class CandidateOccurrence:
    """Immutable attribution for one entry/path occurrence."""

    occurrence_uid: str
    entry_identity: str
    call_paths: Tuple[Tuple[str, ...], ...] = ()
    context_signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "occurrence_uid": self.occurrence_uid,
            "entry_identity": self.entry_identity,
            "call_paths": [list(path) for path in self.call_paths],
            "context_signature": self.context_signature,
        }


@dataclass(frozen=True)
class ValidationGroupOutcome:
    """One immutable, reportable decision for a validation group.

    Candidate records are mutable while discovery and validation are in flight.
    A report must instead consume this projection, which has exactly one
    terminal disposition per validation cluster and retains occurrence
    attribution as aliases rather than additional findings.
    """

    validation_cluster_uid: str
    terminal_disposition: str
    decision_evidence_hash: str
    primary_occurrence_uid: str
    alias_occurrence_uids: Tuple[str, ...] = ()
    decision_proof: Mapping[str, Any] = field(default_factory=dict)
    validation_attempt_count: int = 0
    evidence_completion_status: str = "not_requested"
    engine_status: str = "complete"
    issue: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "validation_cluster_uid": self.validation_cluster_uid,
            "terminal_disposition": self.terminal_disposition,
            "candidate_disposition": self.terminal_disposition,
            "decision_evidence_hash": self.decision_evidence_hash,
            "primary_occurrence_uid": self.primary_occurrence_uid,
            "alias_occurrence_uids": list(self.alias_occurrence_uids),
            "occurrence_uids": (
                [
                    self.primary_occurrence_uid,
                    *self.alias_occurrence_uids,
                ]
                if self.primary_occurrence_uid
                else list(self.alias_occurrence_uids)
            ),
            "decision_proof": deepcopy(dict(self.decision_proof)),
            "validation_attempt_count": self.validation_attempt_count,
            "evidence_completion_status": self.evidence_completion_status,
            "engine_status": self.engine_status,
            "issue": deepcopy(dict(self.issue)),
        }


@dataclass
class CandidateRecord:
    """One canonical vulnerability candidate and all evidence paths that found it."""

    candidate_id: str
    dedup_key: str
    ticket: CandidateTicket
    status: str = "pending"
    sources: List[str] = field(default_factory=list)
    call_paths: List[List[str]] = field(default_factory=list)
    duplicate_count: int = 0
    worker_report_id: Optional[str] = None
    defect_class: str = ""
    canonical_source: str = ""
    canonical_sink: str = ""
    root_cause_key: str = ""
    candidate_uid: str = ""
    history_key: str = ""
    obligation_uid: str = ""
    decision_context_version: str = DECISION_CONTEXT_VERSION
    evidence_hash: str = ""
    decision_evidence_hash: str = ""
    provenance_hashes: List[str] = field(default_factory=list)
    evidence_hashes: List[str] = field(default_factory=list)
    validation_cluster_uid: str = ""
    context_signature: str = ""
    context_signatures: List[str] = field(default_factory=list)
    occurrence_uids: List[str] = field(default_factory=list)
    occurrences: List[CandidateOccurrence] = field(default_factory=list)
    record_role: str = "triage_lead"
    disposition: str = ""
    decision_proof: Dict[str, Any] = field(default_factory=dict)
    terminal_issue: Dict[str, Any] = field(default_factory=dict)
    validation_attempt_count: int = 0
    evidence_completion_status: str = "not_requested"
    engine_status: str = "complete"
    schema_version: str = CANDIDATE_SCHEMA_VERSION

    def to_ticket(self) -> CandidateTicket:
        ticket = self.ticket
        ticket.id = self.candidate_id
        ticket.sources = list(self.sources)
        ticket.call_paths = [list(path) for path in self.call_paths]
        ticket.dedup_key = self.dedup_key
        ticket.evidence.setdefault("candidate_record", {})
        ticket.evidence["candidate_record"].update(
            {
                "defect_class": self.defect_class,
                "canonical_source": self.canonical_source,
                "canonical_sink": self.canonical_sink,
                "root_cause_key": self.root_cause_key,
            }
        )
        return ticket

    def to_dict(self, include_context: bool = True) -> Dict[str, Any]:
        ticket_dict = self.to_ticket().to_dict()
        if not include_context:
            ticket_dict.pop("context_slice", None)
        return {
            "candidate_id": self.candidate_id,
            "dedup_key": self.dedup_key,
            "status": self.status,
            "duplicate_count": self.duplicate_count,
            "defect_class": self.defect_class,
            "canonical_source": self.canonical_source,
            "canonical_sink": self.canonical_sink,
            "root_cause_key": self.root_cause_key,
            "candidate_schema_version": self.schema_version,
            "candidate_uid": self.candidate_uid or self.candidate_id,
            "history_key": self.history_key,
            "obligation_uid": self.obligation_uid,
            "decision_context_version": self.decision_context_version,
            "evidence_hash": self.evidence_hash,
            "decision_evidence_hash": self.decision_evidence_hash,
            "provenance_hash": (self.provenance_hashes[0] if self.provenance_hashes else ""),
            "provenance_hashes": list(self.provenance_hashes),
            "evidence_hashes": list(self.evidence_hashes),
            "validation_cluster_uid": self.validation_cluster_uid,
            "context_signature": self.context_signature,
            "validation_contexts": list(self.context_signatures),
            "occurrence_uids": list(self.occurrence_uids),
            "alias_occurrence_uids": list(self.occurrence_uids[1:]),
            "occurrences": [item.to_dict() for item in self.occurrences],
            "occurrence_count": len(self.occurrence_uids),
            "grouped_alias_count": max(0, len(self.occurrence_uids) - 1),
            "entry_count": len(
                {item.entry_identity for item in self.occurrences if item.entry_identity}
            ),
            "entries": sorted(
                {item.entry_identity for item in self.occurrences if item.entry_identity}
            ),
            "record_role": self.record_role,
            "candidate_disposition": self.disposition,
            "decision_proof": deepcopy(self.decision_proof),
            "validation_attempt_count": self.validation_attempt_count,
            "evidence_completion_status": self.evidence_completion_status,
            "engine_status": self.engine_status,
            "sources": list(self.sources),
            "call_paths": [list(path) for path in self.call_paths],
            "entry_paths": [list(path) for path in self.call_paths],
            "worker_report_id": self.worker_report_id,
            "ticket": ticket_dict,
        }


class CandidateLedger:
    """Central de-duplication ledger for every candidate source."""

    def __init__(
        self,
        *,
        project_id: str = "project",
        project_root: str = "",
        revision: str = "",
        decision_trace_store: Optional[DecisionTraceStore] = None,
    ) -> None:
        self._records: Dict[str, CandidateRecord] = {}
        self._lock = threading.RLock()
        self.project_id = self._normalize_project_id(project_id)
        self.project_root = str(project_root or "")
        self.revision = str(revision or "")
        self.decision_trace_store = decision_trace_store
        self._frozen = False

    def add(
        self,
        ticket: CandidateTicket,
        source: str,
        call_path: Optional[Iterable[str]] = None,
        *,
        record_role: str = "triage_lead",
        entry_identity: str = "",
    ) -> Tuple[CandidateRecord, bool]:
        with self._lock:
            if self._frozen:
                raise RuntimeError("candidate ledger is frozen")
            dedup_key = self.canonical_key(ticket)
            normalized_path = [str(item) for item in (call_path or []) if str(item)]
            evidence = ticket.evidence if isinstance(ticket.evidence, dict) else {}
            context_signature = str(
                evidence.get("context_signature") or ""
            ) or self._context_signature(ticket, normalized_path)
            candidate_uid = str(evidence.get("candidate_uid") or "") or self._candidate_uid(
                dedup_key
            )
            history_key = str(evidence.get("history_key") or "") or self._history_key(dedup_key)
            evidence_hash = str(evidence.get("evidence_hash") or "") or self._evidence_hash(ticket)
            decision_evidence_hash = str(
                evidence.get("decision_evidence_hash") or ""
            ) or self._decision_evidence_hash(ticket, candidate_uid)
            obligation_uid = str(evidence.get("obligation_uid") or "") or candidate_uid
            decision_context_version = str(
                evidence.get("decision_context_version") or DECISION_CONTEXT_VERSION
            )
            evidence.setdefault("obligation_uid", obligation_uid)
            evidence.setdefault("decision_context_version", decision_context_version)
            validation_cluster_uid = str(
                evidence.get("validation_cluster_uid") or ""
            ) or validation_cluster_uid_for(
                candidate_uid,
                decision_evidence_hash=decision_evidence_hash,
                validator_contract=evidence.get("validator_contract")
                or evidence.get("validation_requirements"),
                obligation_uid=obligation_uid,
                decision_context_version=decision_context_version,
            )
            provenance_hash = str(evidence.get("provenance_hash") or "") or self._provenance_hash(
                ticket, source
            )
            validation_key = validation_cluster_uid
            record = self._records.get(validation_key)
            is_new = record is None
            if record is None:
                record = CandidateRecord(
                    candidate_id=self._candidate_id(validation_key),
                    dedup_key=dedup_key,
                    ticket=ticket,
                    defect_class=self._ticket_defect_class(ticket),
                    canonical_source=self._ticket_source(ticket),
                    canonical_sink=self._ticket_sink(ticket),
                    root_cause_key=self._ticket_root_cause_key(ticket, dedup_key),
                    candidate_uid=candidate_uid,
                    history_key=history_key,
                    obligation_uid=obligation_uid,
                    decision_context_version=decision_context_version,
                    evidence_hash=evidence_hash,
                    decision_evidence_hash=decision_evidence_hash,
                    provenance_hashes=[provenance_hash] if provenance_hash else [],
                    evidence_hashes=[evidence_hash] if evidence_hash else [],
                    validation_cluster_uid=validation_cluster_uid,
                    context_signature=context_signature,
                    context_signatures=[context_signature] if context_signature else [],
                    record_role=(
                        "validation_obligation"
                        if record_role == "validation_obligation"
                        else "triage_lead"
                    ),
                    status=("queued" if record_role == "validation_obligation" else "pending"),
                    disposition=(""),
                )
                self._records[validation_key] = record
            else:
                record.duplicate_count += 1
                self._merge_ticket_evidence(record.ticket, ticket)
                if (
                    record_role == "validation_obligation"
                    and record.record_role != "validation_obligation"
                ):
                    record.record_role = "validation_obligation"
                    record.status = "queued"
                    record.disposition = ""
                if ticket.priority_score > record.ticket.priority_score:
                    ticket.id = record.ticket.id
                    self._merge_ticket_evidence(ticket, record.ticket)
                    record.ticket = ticket
                if evidence_hash and evidence_hash not in record.evidence_hashes:
                    record.evidence_hashes.append(evidence_hash)
                if provenance_hash and provenance_hash not in record.provenance_hashes:
                    record.provenance_hashes.append(provenance_hash)
                if context_signature and context_signature not in record.context_signatures:
                    record.context_signatures.append(context_signature)

            if source and source not in record.sources:
                record.sources.append(source)

            if normalized_path and normalized_path not in record.call_paths:
                record.call_paths.append(normalized_path)
            occurrence_uid = str(evidence.get("occurrence_uid") or "") or self._occurrence_uid(
                record.candidate_uid,
                normalized_path,
                entry_identity=str(evidence.get("entry_identity") or ""),
            )
            if occurrence_uid not in record.occurrence_uids:
                record.occurrence_uids.append(occurrence_uid)
            resolved_entry = str(
                entry_identity
                or evidence.get("entry_identity")
                or (normalized_path[0] if normalized_path else "")
            )
            occurrence = CandidateOccurrence(
                occurrence_uid=occurrence_uid,
                entry_identity=resolved_entry,
                call_paths=(tuple(normalized_path),) if normalized_path else (),
                context_signature=context_signature,
            )
            if occurrence not in record.occurrences:
                record.occurrences.append(occurrence)

            trace_store = self.decision_trace_store
            if trace_store is not None and record.record_role == "validation_obligation":
                trace_store.bind_candidate(
                    record.validation_cluster_uid,
                    candidate_uids=(record.candidate_uid,),
                    occurrence_uids=(occurrence_uid,),
                )
                trace_store.append_event(
                    record.validation_cluster_uid,
                    stage="registrar",
                    actor="candidate_ledger",
                    reason_code=("CANDIDATE_REGISTERED" if is_new else "LEDGER_ALIAS_MERGED"),
                    after_state={
                        "candidate_uid": record.candidate_uid,
                        "validation_cluster_uid": record.validation_cluster_uid,
                        "occurrence_uid": occurrence_uid,
                        "record_role": record.record_role,
                        "source": source,
                    },
                    disposition_after=str(record.disposition or ""),
                    details={
                        "candidate_id": record.candidate_id,
                        "entry_identity": resolved_entry,
                        "duplicate_count": record.duplicate_count,
                        "source": source,
                    },
                    dedupe_key=(
                        f"registrar:{record.validation_cluster_uid}:{occurrence_uid}:"
                        f"{'new' if is_new else 'alias'}"
                    ),
                )

            return record, is_new

    def add_many(
        self,
        tickets: Iterable[CandidateTicket],
        source: str,
        call_path: Optional[Iterable[str]] = None,
    ) -> None:
        for ticket in tickets:
            self.add(ticket, source=source, call_path=call_path)

    def pending_tickets(self) -> List[CandidateTicket]:
        with self._lock:
            return [
                record.to_ticket()
                for record in self._records.values()
                if record.status == "pending"
            ]

    def mark_planned(self, tickets: Iterable[CandidateTicket]) -> None:
        ids = {ticket.id for ticket in tickets}
        with self._lock:
            for record in self._records.values():
                if record.candidate_id in ids:
                    record.status = "planned"

    def claim_pending(self, tickets: Iterable[CandidateTicket]) -> List[CandidateTicket]:
        """Atomically claim pending candidates for exactly one worker/entry."""
        requested = [ticket for ticket in tickets]
        requested_ids = {ticket.id for ticket in requested}
        claimed_ids: set[str] = set()
        with self._lock:
            for record in self._records.values():
                if record.candidate_id in requested_ids and record.status == "pending":
                    record.status = "planned"
                    claimed_ids.add(record.candidate_id)
        return [ticket for ticket in requested if ticket.id in claimed_ids]

    def mark_unassigned(self, tickets: Iterable[CandidateTicket]) -> None:
        ids = {ticket.id for ticket in tickets}
        with self._lock:
            for record in self._records.values():
                if record.candidate_id in ids and record.status == "pending":
                    # Investigator ticket budgets are soft triage policy.  A
                    # lead that was not assigned is not a failed validation
                    # obligation and must not become a security finding.
                    record.status = "triage_unassigned"
                    record.disposition = ""

    def mark_reported(self, reports: Iterable[Dict[str, Any]]) -> None:
        """Record investigator completion without treating it as validation."""
        with self._lock:
            for report in reports:
                ticket = report.get("ticket") or {}
                candidate_id = ticket.get("id") or ticket.get("candidate_id")
                if not candidate_id:
                    continue
                for record in self._records.values():
                    if record.candidate_id == candidate_id:
                        # An investigation worker is an evidence producer, not a proof
                        # authority.  It must never turn a queued validation
                        # obligation into a security review finding.
                        if record.record_role == "validation_obligation":
                            record.evidence_completion_status = "evidence_collected"
                        else:
                            report_status = str(report.get("status") or "analyzed").lower()
                            record.status = (
                                "triage_failed"
                                if report_status in {"failed", "engine_failed"}
                                else "investigated"
                            )
                            record.disposition = ""
                        record.worker_report_id = candidate_id
                        break

    def mark_issue_terminal(
        self,
        issue: Dict[str, Any],
        *,
        disposition: str,
        status: str = "",
    ) -> int:
        """Backfill the main validator disposition into matching records."""

        pack = _as_dict(issue.get("evidence_pack"))
        occurrence_uid = str(issue.get("occurrence_uid") or pack.get("occurrence_uid") or "")
        candidate_uid = str(issue.get("candidate_uid") or pack.get("candidate_uid") or "")
        evidence_hash = str(issue.get("evidence_hash") or pack.get("evidence_hash") or "")
        context_signature = str(
            issue.get("context_signature") or pack.get("context_signature") or ""
        )
        validation_cluster_uid = str(
            issue.get("validation_cluster_uid") or pack.get("validation_cluster_uid") or ""
        )
        has_exact_validation_identity = bool(candidate_uid and evidence_hash and context_signature)
        if not occurrence_uid and not has_exact_validation_identity and not validation_cluster_uid:
            return 0

        updated = 0
        with self._lock:
            for record in self._records.values():
                if validation_cluster_uid:
                    matches = record.validation_cluster_uid == validation_cluster_uid
                elif has_exact_validation_identity:
                    matches = bool(
                        record.candidate_uid == candidate_uid
                        and record.evidence_hash == evidence_hash
                        and record.context_signature == context_signature
                    )
                else:
                    matches = occurrence_uid in record.occurrence_uids
                if not matches:
                    continue
                record.disposition = (
                    disposition if disposition in TERMINAL_DISPOSITIONS else "needs_review"
                )
                record.status = status or record.disposition
                record.terminal_issue = deepcopy(issue)
                proof = issue.get("decision_proof") or issue.get("rejection_proof")
                record.decision_proof = deepcopy(proof) if isinstance(proof, dict) else {}
                record.evidence_completion_status = str(
                    issue.get("evidence_completion_status") or record.evidence_completion_status
                )
                record.engine_status = str(
                    issue.get("engine_status")
                    or (
                        "failed"
                        if record.disposition == "engine_failed"
                        else "interrupted" if record.disposition == "interrupted" else "complete"
                    )
                )
                updated += 1
        return updated

    def mark_validation_running(self, issue: Mapping[str, Any]) -> int:
        """Claim a validation group without assigning a security disposition."""

        pack = _as_dict(issue.get("evidence_pack"))
        cluster_uid = str(
            issue.get("validation_cluster_uid") or pack.get("validation_cluster_uid") or ""
        )
        if not cluster_uid:
            return 0
        with self._lock:
            record = self._records.get(cluster_uid)
            if record is None or record.record_role != "validation_obligation":
                return 0
            if record.disposition in TERMINAL_DISPOSITIONS:
                return 0
            record.status = "running"
            record.validation_attempt_count += 1
            return 1

    def records(self) -> List[CandidateRecord]:
        with self._lock:
            return list(self._records.values())

    def lifecycle_snapshot(
        self,
        *,
        entry_identity: str = "",
        include_triage: bool = False,
    ) -> Dict[str, Any]:
        """Atomically project immutable lifecycle data for reporting.

        Report assemblers consume this snapshot and never traverse the shared
        mutable ledger directly.
        """

        with self._lock:
            projected: List[Dict[str, Any]] = []
            for record in self._records.values():
                if not include_triage and record.record_role != "validation_obligation":
                    continue
                value = record.to_dict(include_context=False)
                occurrences = [
                    item.to_dict()
                    for item in record.occurrences
                    if not entry_identity or item.entry_identity == entry_identity
                ]
                if entry_identity and not occurrences:
                    continue
                if occurrences:
                    value["occurrences"] = occurrences
                    value["occurrence_uids"] = [item["occurrence_uid"] for item in occurrences]
                    value["call_paths"] = [
                        path for item in occurrences for path in item.get("call_paths", [])
                    ]
                    value["entries"] = sorted(
                        {
                            str(item.get("entry_identity") or "")
                            for item in occurrences
                            if item.get("entry_identity")
                        }
                    )
                    value["entry_count"] = len(value["entries"])
                    value["occurrence_count"] = len(value["occurrence_uids"])
                projected.append(value)
            projected.sort(
                key=lambda item: (
                    str(item.get("validation_cluster_uid") or ""),
                    str(item.get("candidate_uid") or ""),
                )
            )
            outcomes = []
            for record in self._records.values():
                if record.record_role != "validation_obligation":
                    continue
                outcome = self._outcome_for_record(
                    record,
                    entry_identity=entry_identity,
                )
                if outcome is not None:
                    outcomes.append(outcome)
            outcomes.sort(key=lambda item: item.validation_cluster_uid)
            return {
                "candidate_schema_version": CANDIDATE_SCHEMA_VERSION,
                "entry_identity": entry_identity,
                "records": projected,
                "outcomes": [item.to_dict() for item in outcomes],
                "summary": self._summary_unlocked(),
            }

    def freeze(self) -> Dict[str, Any]:
        """Seal candidate discovery and return the final atomic snapshot."""

        with self._lock:
            self._frozen = True
            trace_store = self.decision_trace_store
            if trace_store is not None:
                for record in self._records.values():
                    if record.record_role != "validation_obligation":
                        continue
                    trace_store.append_event(
                        record.validation_cluster_uid,
                        stage="registrar",
                        actor="candidate_ledger",
                        reason_code="LEDGER_FROZEN",
                        after_state={
                            "candidate_uid": record.candidate_uid,
                            "validation_cluster_uid": record.validation_cluster_uid,
                            "occurrence_uids": list(record.occurrence_uids),
                            "validation_group_count": len(
                                [
                                    item
                                    for item in self._records.values()
                                    if item.record_role == "validation_obligation"
                                ]
                            ),
                        },
                        dedupe_key=f"ledger-frozen:{record.validation_cluster_uid}",
                    )
            return self.lifecycle_snapshot()

    def to_context(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            records = sorted(
                self._records.values(),
                key=lambda item: (-item.ticket.priority_score, item.candidate_id),
            )
            return [record.to_dict(include_context=False) for record in records[:limit]]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return self._summary_unlocked()

    def _summary_unlocked(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        obligations = [
            record
            for record in self._records.values()
            if record.record_role == "validation_obligation"
        ]
        triage = [
            record
            for record in self._records.values()
            if record.record_role != "validation_obligation"
        ]
        for record in obligations:
            counts[record.status] = counts.get(record.status, 0) + 1
        return {
            "total": len(self._records),
            "validation_group_count": len(obligations),
            "triage_lead_count": len(triage),
            "raw_occurrence_count": sum(
                len(record.occurrence_uids) for record in self._records.values()
            ),
            "by_status": counts,
            "triage_by_status": {
                status: sum(1 for record in triage if record.status == status)
                for status in sorted({record.status for record in triage})
            },
            "by_disposition": {
                disposition: sum(1 for record in obligations if record.disposition == disposition)
                for disposition in sorted(
                    {record.disposition for record in obligations if record.disposition}
                )
            },
            "incomplete": any(
                record.disposition in {"deferred_budget", "engine_failed", "interrupted"}
                or (self._frozen and record.status in NONTERMINAL_STATUSES)
                for record in obligations
            ),
            "nonterminal_validation_count": sum(
                1 for record in obligations if record.status in NONTERMINAL_STATUSES
            ),
            "duplicates_merged": sum(record.duplicate_count for record in self._records.values()),
        }

    def _outcome_for_record(
        self,
        record: CandidateRecord,
        *,
        entry_identity: str = "",
    ) -> Optional[ValidationGroupOutcome]:
        """Create the only reportable projection for a closed validation group."""

        if record.disposition not in TERMINAL_DISPOSITIONS:
            return None
        occurrences = [
            item
            for item in record.occurrences
            if not entry_identity or item.entry_identity == entry_identity
        ]
        if entry_identity and not occurrences:
            return None
        occurrence_uids = sorted(
            {item.occurrence_uid for item in occurrences} or set(record.occurrence_uids)
        )
        primary = occurrence_uids[0] if occurrence_uids else ""
        issue = deepcopy(record.terminal_issue)
        if not issue:
            ticket_evidence = (
                record.ticket.evidence if isinstance(record.ticket.evidence, dict) else {}
            )
            issue = deepcopy(ticket_evidence.get("candidate_payload") or {})
        canonical = record.to_dict(include_context=False)
        # Preserve validator-produced content but make lifecycle identity and
        # disposition authoritative.
        issue.update(
            {
                key: deepcopy(value)
                for key, value in canonical.items()
                if key
                not in {"ticket", "occurrence_uids", "occurrences", "call_paths", "entry_paths"}
            }
        )
        issue.update(
            {
                "candidate_disposition": record.disposition,
                "status": record.status,
                "validation_cluster_uid": record.validation_cluster_uid,
                "occurrence_uid": primary,
                "occurrence_uids": occurrence_uids,
                "alias_occurrence_uids": occurrence_uids[1:],
                "occurrences": [item.to_dict() for item in occurrences],
                "occurrence_count": len(occurrence_uids),
                "entry_count": len(
                    {item.entry_identity for item in occurrences if item.entry_identity}
                ),
                "entries": sorted(
                    {item.entry_identity for item in occurrences if item.entry_identity}
                ),
                "entry_paths": [list(path) for item in occurrences for path in item.call_paths],
                "decision_proof": deepcopy(record.decision_proof),
                "validation_attempt_count": record.validation_attempt_count,
                "evidence_completion_status": record.evidence_completion_status,
                "engine_status": record.engine_status,
            }
        )
        return ValidationGroupOutcome(
            validation_cluster_uid=record.validation_cluster_uid,
            terminal_disposition=record.disposition,
            decision_evidence_hash=record.decision_evidence_hash,
            primary_occurrence_uid=primary,
            alias_occurrence_uids=tuple(occurrence_uids[1:]),
            decision_proof=record.decision_proof,
            validation_attempt_count=record.validation_attempt_count,
            evidence_completion_status=record.evidence_completion_status,
            engine_status=record.engine_status,
            issue=issue,
        )

    @classmethod
    def canonical_key(cls, ticket: CandidateTicket) -> str:
        return cls._ticket_root_cause_key(ticket, "")

    @staticmethod
    def _candidate_id(validation_key: str) -> str:
        digest = hashlib.sha256(validation_key.encode("utf-8")).hexdigest()[:12]
        return f"CAND_{digest}"

    def _candidate_uid(self, dedup_key: str) -> str:
        payload = {
            "project": self.project_id,
            "revision": self.revision,
            "root": dedup_key,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[
            :24
        ]
        return f"CAND_{digest}"

    def _history_key(self, dedup_key: str) -> str:
        payload = {
            "project": self.project_id,
            "root": dedup_key,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[
            :24
        ]
        return f"HIST_{digest}"

    @staticmethod
    def _evidence_hash(ticket: CandidateTicket) -> str:
        import json

        payload = {
            "skill": ticket.skill,
            "origin": ticket.origin,
            "sink": ticket.sink,
            "trigger": ticket.trigger,
            "resource_kind": ticket.resource_kind,
            "evidence": ticket.evidence or {},
        }
        stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    @staticmethod
    def _decision_evidence_hash(
        ticket: CandidateTicket,
        candidate_uid: str,
    ) -> str:
        evidence = ticket.evidence if isinstance(ticket.evidence, dict) else {}
        path = _as_dict(evidence.get("path"))
        payload = {
            "candidate_uid": candidate_uid,
            "negative_evidence": evidence.get("negative_evidence") or [],
            "path_constraints": evidence.get("path_constraints")
            or path.get("path_constraints")
            or [],
            "guards": evidence.get("guards") or evidence.get("guard"),
            "sanitizers": evidence.get("sanitizers") or evidence.get("sanitizer"),
            "ownership_facts": evidence.get("ownership_facts"),
            "reachability_facts": evidence.get("reachability_facts"),
            "concurrency_facts": evidence.get("concurrency_facts"),
            "value_domain_facts": evidence.get("value_domain_facts"),
            "dependency_code_hash": evidence.get("dependency_code_hash")
            or evidence.get("code_hash")
            or evidence.get("source_fingerprint"),
            "evidence_models": evidence.get("evidence_models") or {},
        }
        stable = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    @staticmethod
    def _provenance_hash(ticket: CandidateTicket, source: str) -> str:
        payload = {
            "display_id": ticket.id,
            "source": source,
            "skill": ticket.skill,
            "origin": ticket.origin,
            "sink": ticket.sink,
            "trigger": ticket.trigger,
            "task": ticket.task,
        }
        stable = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    @staticmethod
    def _occurrence_uid(
        candidate_uid: str,
        call_path: List[str],
        *,
        entry_identity: str = "",
    ) -> str:
        return occurrence_uid_for(
            candidate_uid,
            entry=entry_identity or (call_path[0] if call_path else ""),
            entry_paths=[call_path] if call_path else [],
        )

    @classmethod
    def _context_signature(
        cls,
        ticket: CandidateTicket,
        call_path: List[str],
    ) -> str:
        evidence = ticket.evidence if isinstance(ticket.evidence, dict) else {}
        path = _as_dict(evidence.get("path"))
        return context_signature_for(
            entry=str(evidence.get("entry_identity") or "") or (call_path[0] if call_path else ""),
            entry_paths=[call_path] if call_path else [],
            constraints=(
                path.get("path_constraints")
                or evidence.get("path_constraints")
                or evidence.get("path")
            ),
        )

    @staticmethod
    def _validation_key(
        candidate_uid: str,
        evidence_hash: str,
        context_signature: str,
    ) -> str:
        return f"{candidate_uid}|evidence={evidence_hash}" f"|context={context_signature}"

    @staticmethod
    def _merge_ticket_evidence(
        primary: CandidateTicket,
        secondary: CandidateTicket,
    ) -> None:
        primary_evidence = primary.evidence if isinstance(primary.evidence, dict) else {}
        secondary_evidence = secondary.evidence if isinstance(secondary.evidence, dict) else {}
        for key, value in secondary_evidence.items():
            if key not in primary_evidence or primary_evidence.get(key) in (
                None,
                "",
                [],
                {},
            ):
                primary_evidence[key] = value
                continue
            existing = primary_evidence.get(key)
            if isinstance(existing, list) and isinstance(value, list):
                for item in value:
                    if item not in existing:
                        existing.append(item)
            elif isinstance(existing, dict) and isinstance(value, dict):
                CandidateLedger._merge_evidence_mapping(existing, value)
        primary.evidence = primary_evidence
        for value in secondary.priority_reasons:
            if value not in primary.priority_reasons:
                primary.priority_reasons.append(value)

    @staticmethod
    def _merge_evidence_mapping(primary: Dict[str, Any], secondary: Mapping[str, Any]) -> None:
        """Recursively preserve multi-producer attribution as set-like lists."""

        for key, value in secondary.items():
            if key not in primary or primary.get(key) in (None, "", [], {}):
                primary[key] = deepcopy(value)
                continue
            existing = primary.get(key)
            if isinstance(existing, list) and isinstance(value, list):
                for item in value:
                    if item not in existing:
                        existing.append(deepcopy(item))
            elif isinstance(existing, dict) and isinstance(value, Mapping):
                CandidateLedger._merge_evidence_mapping(existing, value)

    @staticmethod
    def _normalize_project_id(value: Any) -> str:
        text = str(value or "project").strip().replace("\\", "/").rstrip("/")
        if re.match(r"^[A-Za-z]:/", text) or text.startswith("/"):
            text = text.rsplit("/", 1)[-1]
        return re.sub(r"\s+", " ", text.lower()) or "project"

    @staticmethod
    def _infer_resource_kind(ticket: CandidateTicket) -> str:
        text = f"{ticket.skill} {ticket.trigger} {ticket.task}".lower()
        if any(word in text for word in ("malloc", "calloc", "realloc", "free", "memory")):
            return "memory"
        if any(word in text for word in ("open", "close", "fopen", "fclose", "file", "socket")):
            return "handle"
        if any(word in text for word in ("lock", "mutex", "rwlock", "spin")):
            return "lock"
        if any(word in text for word in ("string", "strcmp", "strlen", "format")):
            return "string"
        return "unknown"

    @staticmethod
    def _site_key(value: Any) -> str:
        text = str(value or "").strip()
        match = re.match(r"^([^:\s]+):(\d+)(?::.*)?$", text)
        if match:
            return f"{match.group(1)}:{match.group(2)}"
        return text

    @staticmethod
    def _normalize(value: Any) -> str:
        text = str(value or "").strip().lower()
        text = re.sub(r"\s+", " ", text)
        return text

    @classmethod
    def _ticket_defect_class(cls, ticket: CandidateTicket) -> str:
        evidence = ticket.evidence or {}
        return cls._normalize(
            evidence.get("defect_class") or evidence.get("subcategory") or ticket.skill
        )

    @classmethod
    def _ticket_source(cls, ticket: CandidateTicket) -> str:
        evidence = ticket.evidence or {}
        source = evidence.get("source")
        if isinstance(source, dict):
            source = source.get("expression") or source.get("object") or source.get("line")
        return cls._normalize(source or ticket.origin)

    @classmethod
    def _ticket_sink(cls, ticket: CandidateTicket) -> str:
        evidence = ticket.evidence or {}
        sink = evidence.get("sink")
        if isinstance(sink, dict):
            sink = sink.get("operation") or sink.get("line")
        return cls._normalize(sink or ticket.sink)

    @classmethod
    def _ticket_root_cause_key(cls, ticket: CandidateTicket, fallback: str) -> str:
        evidence = ticket.evidence or {}
        explicit = evidence.get("root_cause_key") or evidence.get("dedup_key")
        defect = cls._ticket_defect_class(ticket)
        source = cls._ticket_source(ticket)
        sink = cls._ticket_sink(ticket)
        location = cls._site_key(ticket.origin or ticket.sink or f"{ticket.task}:{ticket.line}")
        parts = [
            explicit,
            defect,
            ticket.resource_kind or cls._infer_resource_kind(ticket),
            location,
            source,
            sink,
        ]
        key = "|".join(cls._normalize(part) for part in parts if cls._normalize(part))
        return key or fallback
