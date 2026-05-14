"""Candidate ledger for focused subagent de-duplication."""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .subagents import SubAgentTicket


@dataclass
class CandidateRecord:
    """One canonical vulnerability candidate and all evidence paths that found it."""

    candidate_id: str
    dedup_key: str
    ticket: SubAgentTicket
    status: str = "pending"
    sources: List[str] = field(default_factory=list)
    call_paths: List[List[str]] = field(default_factory=list)
    duplicate_count: int = 0
    worker_report_id: Optional[str] = None
    defect_class: str = ""
    canonical_source: str = ""
    canonical_sink: str = ""
    root_cause_key: str = ""

    def to_ticket(self) -> SubAgentTicket:
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
            "sources": list(self.sources),
            "call_paths": [list(path) for path in self.call_paths],
            "worker_report_id": self.worker_report_id,
            "ticket": ticket_dict,
        }


class CandidateLedger:
    """Central de-duplication ledger for semantic, heuristic, and VA candidates."""

    def __init__(self) -> None:
        self._records: Dict[str, CandidateRecord] = {}
        self._lock = threading.RLock()

    def add(
        self,
        ticket: SubAgentTicket,
        source: str,
        call_path: Optional[Iterable[str]] = None,
    ) -> Tuple[CandidateRecord, bool]:
        with self._lock:
            dedup_key = self.canonical_key(ticket)
            record = self._records.get(dedup_key)
            is_new = record is None
            if record is None:
                record = CandidateRecord(
                    candidate_id=self._candidate_id(dedup_key),
                    dedup_key=dedup_key,
                    ticket=ticket,
                    defect_class=self._ticket_defect_class(ticket),
                    canonical_source=self._ticket_source(ticket),
                    canonical_sink=self._ticket_sink(ticket),
                    root_cause_key=self._ticket_root_cause_key(ticket, dedup_key),
                )
                self._records[dedup_key] = record
            else:
                record.duplicate_count += 1
                if ticket.priority_score > record.ticket.priority_score:
                    ticket.id = record.ticket.id
                    record.ticket = ticket

            if source and source not in record.sources:
                record.sources.append(source)

            normalized_path = [str(item) for item in (call_path or []) if str(item)]
            if normalized_path and normalized_path not in record.call_paths:
                record.call_paths.append(normalized_path)

            return record, is_new

    def add_many(
        self,
        tickets: Iterable[SubAgentTicket],
        source: str,
        call_path: Optional[Iterable[str]] = None,
    ) -> None:
        for ticket in tickets:
            self.add(ticket, source=source, call_path=call_path)

    def pending_tickets(self) -> List[SubAgentTicket]:
        with self._lock:
            return [
                record.to_ticket()
                for record in self._records.values()
                if record.status == "pending"
            ]

    def mark_planned(self, tickets: Iterable[SubAgentTicket]) -> None:
        ids = {ticket.id for ticket in tickets}
        with self._lock:
            for record in self._records.values():
                if record.candidate_id in ids:
                    record.status = "planned"

    def mark_unassigned(self, tickets: Iterable[SubAgentTicket]) -> None:
        ids = {ticket.id for ticket in tickets}
        with self._lock:
            for record in self._records.values():
                if record.candidate_id in ids and record.status == "pending":
                    record.status = "unassigned"

    def mark_reported(self, reports: Iterable[Dict[str, Any]]) -> None:
        with self._lock:
            for report in reports:
                ticket = report.get("ticket") or {}
                candidate_id = ticket.get("id") or ticket.get("candidate_id")
                if not candidate_id:
                    continue
                for record in self._records.values():
                    if record.candidate_id == candidate_id:
                        record.status = str(report.get("status") or "analyzed")
                        record.worker_report_id = candidate_id
                        break

    def records(self) -> List[CandidateRecord]:
        with self._lock:
            return list(self._records.values())

    def to_context(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            records = sorted(
                self._records.values(),
                key=lambda item: (-item.ticket.priority_score, item.candidate_id),
            )
            return [record.to_dict(include_context=False) for record in records[:limit]]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            counts: Dict[str, int] = {}
            for record in self._records.values():
                counts[record.status] = counts.get(record.status, 0) + 1
            return {
                "total": len(self._records),
                "by_status": counts,
                "duplicates_merged": sum(
                    record.duplicate_count for record in self._records.values()
                ),
            }

    @classmethod
    def canonical_key(cls, ticket: SubAgentTicket) -> str:
        root_key = cls._ticket_root_cause_key(ticket, "")
        if root_key:
            return root_key
        parts = [
            ticket.skill,
            ticket.resource_kind or cls._infer_resource_kind(ticket),
            cls._site_key(ticket.origin or f"{ticket.task}:{ticket.line}"),
            cls._site_key(ticket.sink or f"{ticket.trigger}:{ticket.line}"),
        ]
        return "|".join(cls._normalize(part) for part in parts)

    @staticmethod
    def _candidate_id(dedup_key: str) -> str:
        digest = hashlib.sha256(dedup_key.encode("utf-8")).hexdigest()[:12]
        return f"CAND_{digest}"

    @staticmethod
    def _infer_resource_kind(ticket: SubAgentTicket) -> str:
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
    def _ticket_defect_class(cls, ticket: SubAgentTicket) -> str:
        evidence = ticket.evidence or {}
        return cls._normalize(
            evidence.get("defect_class")
            or evidence.get("subcategory")
            or ticket.skill
        )

    @classmethod
    def _ticket_source(cls, ticket: SubAgentTicket) -> str:
        evidence = ticket.evidence or {}
        source = evidence.get("source")
        if isinstance(source, dict):
            source = source.get("expression") or source.get("object") or source.get("line")
        return cls._normalize(source or ticket.origin)

    @classmethod
    def _ticket_sink(cls, ticket: SubAgentTicket) -> str:
        evidence = ticket.evidence or {}
        sink = evidence.get("sink")
        if isinstance(sink, dict):
            sink = sink.get("operation") or sink.get("line")
        return cls._normalize(sink or ticket.sink)

    @classmethod
    def _ticket_root_cause_key(cls, ticket: SubAgentTicket, fallback: str) -> str:
        evidence = ticket.evidence or {}
        explicit = evidence.get("root_cause_key") or evidence.get("dedup_key")
        if explicit:
            return cls._normalize(explicit)
        defect = cls._ticket_defect_class(ticket)
        source = cls._ticket_source(ticket)
        sink = cls._ticket_sink(ticket)
        location = cls._site_key(ticket.origin or ticket.sink or f"{ticket.task}:{ticket.line}")
        parts = [defect, ticket.resource_kind or cls._infer_resource_kind(ticket), location, source, sink]
        key = "|".join(cls._normalize(part) for part in parts if cls._normalize(part))
        return key or fallback
