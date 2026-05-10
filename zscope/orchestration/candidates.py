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

    def to_ticket(self) -> SubAgentTicket:
        ticket = self.ticket
        ticket.id = self.candidate_id
        ticket.sources = list(self.sources)
        ticket.call_paths = [list(path) for path in self.call_paths]
        ticket.dedup_key = self.dedup_key
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
