"""Read-only projection of frozen candidates and persisted backend signals."""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..semantics.build_scope import current_build_id
from .contracts import (
    ContractTool,
    ToolContract,
    invalid_request,
    object_schema,
    output_schema,
    page_result,
    tool_result,
)
from .symbols import SymbolCatalog, normalize_project_path, valid_symbol_id

_BACKEND_SIGNAL_LIMIT = 1_000_000

DESCRIPTION = """Read frozen candidates and persisted rule/graph/SVF/Saber/Java/discovery signals.
Does not scan; returns evidence references, authority, provenance and validation.
Unvalidated records are hypotheses."""


FINDINGS_CONTRACT = ToolContract(
    name="query_static_findings",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "symbol_id": {
                "type": ["string", "null"],
                "maxLength": 128,
            },
            "producers": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "deterministic_rule",
                        "graph_rule",
                        "backend_signal",
                        "active_discovery",
                    ],
                },
                "maxItems": 4,
                "uniqueItems": True,
            },
            "rule_id": {"type": ["string", "null"], "maxLength": 256},
            "category": {"type": ["string", "null"], "maxLength": 256},
            "validation_states": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "unvalidated",
                        "pending",
                        "confirmed",
                        "rejected",
                        "deferred",
                        "engine_failed",
                    ],
                },
                "maxItems": 6,
                "uniqueItems": True,
            },
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
        }
    ),
    output_schema=output_schema(
        object_schema(
            {
                "findings": {
                    "type": "array",
                    "items": object_schema(
                        {
                            "finding_id": {"type": "string"},
                            "record_type": {
                                "type": "string",
                                "enum": ["candidate", "backend_signal"],
                            },
                            "producer": {
                                "type": "string",
                                "enum": [
                                    "deterministic_rule",
                                    "graph_rule",
                                    "backend_signal",
                                    "active_discovery",
                                ],
                            },
                            "authority": {
                                "type": "string",
                                "enum": ["deterministic", "backend_signal", "hypothesis"],
                            },
                            "rule": object_schema(
                                {
                                    "id": {"type": ["string", "null"]},
                                    "category": {"type": "string"},
                                    "severity": {"type": ["string", "null"]},
                                },
                                required=["id", "category", "severity"],
                            ),
                            "validation": object_schema(
                                {
                                    "state": {
                                        "type": "string",
                                        "enum": [
                                            "unvalidated",
                                            "pending",
                                            "confirmed",
                                            "rejected",
                                            "deferred",
                                            "engine_failed",
                                        ],
                                    },
                                    "disposition": {"type": ["string", "null"]},
                                    "attempt_count": {"type": "integer", "minimum": 0},
                                },
                                required=["state", "disposition", "attempt_count"],
                            ),
                            "location": object_schema(
                                {
                                    "file": {"type": ["string", "null"]},
                                    "line": {"type": ["integer", "null"], "minimum": 1},
                                    "column": {"type": ["integer", "null"], "minimum": 1},
                                },
                                required=["file", "line", "column"],
                            ),
                            "summary": {"type": "string"},
                            "symbol_refs": {"type": "array", "items": {"type": "string"}},
                            "evidence_refs": {
                                "type": "array",
                                "items": {"type": "object"},
                            },
                            "confidence": {"type": ["number", "null"]},
                            "provenance": {"type": "object"},
                        },
                        required=[
                            "finding_id",
                            "record_type",
                            "producer",
                            "authority",
                            "rule",
                            "validation",
                            "location",
                            "summary",
                            "symbol_refs",
                            "evidence_refs",
                            "confidence",
                            "provenance",
                        ],
                    ),
                }
            },
            required=["findings"],
        )
    ),
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
)


class QueryStaticFindingsTool(ContractTool):
    def __init__(
        self,
        code_index: Any,
        catalog: SymbolCatalog,
        candidate_ledger: Any = None,
    ) -> None:
        super().__init__(FINDINGS_CONTRACT)
        self.code_index = code_index
        self.catalog = catalog
        self.candidate_ledger = candidate_ledger

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if arguments.get("symbol_id") and not valid_symbol_id(arguments["symbol_id"]):
            return invalid_request(
                code="invalid_symbol_id",
                path="symbol_id",
                message="symbol_id must be passed unchanged from search_code",
            )
        return None

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        pinned = str(getattr(self.code_index, "pinned_build_context_id", "") or "")
        active = current_build_id()
        if pinned and active and pinned != active:
            return tool_result(
                status="unavailable", data={"findings": []}, missing=["conflicting_build_context"]
            )
        build_context_id = pinned or active
        requested_symbol = str(arguments.get("symbol_id") or "")
        if requested_symbol and self.catalog.resolve(requested_symbol) is None:
            return tool_result(
                status="not_found",
                data=None,
                providers=list(self.catalog.snapshot().providers),
                next_actions=["Run search_code again and pass the returned symbol_id unchanged."],
                warnings=["The symbol ID may belong to an older index revision."],
            )
        records: List[Dict[str, Any]] = []
        symbols_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for symbol in self.catalog.snapshot().records:
            symbols_by_file.setdefault(normalize_project_path(symbol.get("file")), []).append(
                symbol
            )
        providers: set[str] = set()
        missing: List[str] = []
        warnings: List[str] = []
        ledger = self.candidate_ledger
        if ledger is None:
            missing.append("ledger")
        elif not bool(getattr(ledger, "is_frozen", False)):
            missing.append("ledger_not_frozen")
            warnings.append("CandidateLedger is still mutable and was not exposed.")
        else:
            providers.add("candidate_ledger")
            for item in ledger.frozen_records():
                if build_context_id and item.get("build_context_id") != build_context_id:
                    if not item.get("build_context_id"):
                        missing.append("candidate_build_identity")
                    continue
                records.append(self._candidate_record(item, symbols_by_file))

        if build_context_id:
            getter = getattr(self.code_index, "get_instance_backend_signals", None)
            signals = (
                getter(build_context_id=build_context_id, limit=_BACKEND_SIGNAL_LIMIT)
                if callable(getter)
                else {}
            )
            if (
                signals.get("status") == "complete"
                and signals.get("build_context_id") == build_context_id
            ):
                providers.add("knowledge_db")
                rows = signals["rows"]
                if len(rows) >= _BACKEND_SIGNAL_LIMIT:
                    missing.append("backend_signal_limit")
                records.extend(self._backend_record(item, symbols_by_file) for item in rows)
            else:
                missing.append(str(signals.get("reason") or "instance_backend_signals"))
        else:
            database = self._database()
            getter = getattr(database, "get_enriched_taint_bugs", None) if database else None
            if callable(getter):
                providers.add("knowledge_db")
                rows = getter(limit=_BACKEND_SIGNAL_LIMIT)
                if len(rows) >= _BACKEND_SIGNAL_LIMIT:
                    missing.append("backend_signal_limit")
                records.extend(self._backend_record(item, symbols_by_file) for item in rows)
            else:
                missing.append("persisted_backend_signals")

        filtered = self._filter(records, arguments)
        filtered.sort(
            key=lambda item: (
                str((item.get("location") or {}).get("file") or ""),
                int((item.get("location") or {}).get("line") or 0),
                str((item.get("rule") or {}).get("id") or ""),
                str(item.get("finding_id") or ""),
            )
        )
        limit = int(arguments.get("limit", 20))
        offset = int(arguments.get("offset", 0))
        selected = filtered[offset : offset + limit]
        status = "partial" if missing else ("ok" if filtered else "not_found")
        return tool_result(
            status=status,
            data={"findings": selected},
            providers=sorted(providers),
            missing=list(dict.fromkeys(missing)),
            coverage_details={
                **({"build_context_id": build_context_id} if build_context_id else {}),
                "ledger": (
                    "frozen"
                    if ledger is not None and bool(getattr(ledger, "is_frozen", False))
                    else "unavailable" if ledger is None else "not_frozen"
                ),
            },
            page=page_result(offset, limit, len(selected), len(filtered)),
            warnings=warnings,
        )

    def _candidate_record(
        self, item: Dict[str, Any], symbols_by_file: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        ticket = item.get("ticket") or {}
        evidence = ticket.get("evidence") or {}
        payload = evidence.get("candidate_payload") or {}
        terminal = item.get("terminal_issue") or {}
        combined = {**payload, **terminal}
        producer = self._producer(item, combined)
        location = self._location(combined, ticket)
        symbol_refs = self._symbols_at(location, symbols_by_file)
        rule_id = str(
            combined.get("rule_id") or combined.get("rule") or ticket.get("trigger") or ""
        )
        category = str(
            combined.get("category")
            or combined.get("defect_class")
            or item.get("defect_class")
            or ticket.get("skill")
            or "security_review"
        )
        disposition = str(item.get("candidate_disposition") or "")
        state = self._validation_state(disposition, str(item.get("status") or ""))
        summary = str(
            combined.get("description")
            or combined.get("root_cause")
            or ticket.get("task")
            or category
        )
        refs = []
        if location.get("file") and location.get("line"):
            refs.append({"kind": "source", **location})
        for raw_ref in [
            *(evidence.get("evidence_refs") or []),
            *(combined.get("evidence_refs") or []),
        ]:
            compact = self._evidence_ref(raw_ref)
            if compact and compact not in refs:
                refs.append(compact)
        for key in ("flow_path_id", "path_id"):
            if combined.get(key):
                compact = {"kind": "flow_path", "id": str(combined[key])}
                if compact not in refs:
                    refs.append(compact)
        return {
            "finding_id": "candidate:"
            + str(item.get("candidate_uid") or item.get("candidate_id") or ""),
            "record_type": "candidate",
            "producer": producer,
            "authority": (
                "hypothesis"
                if producer == "active_discovery"
                else (
                    "deterministic"
                    if producer in {"deterministic_rule", "graph_rule"}
                    else "backend_signal"
                )
            ),
            "rule": {
                "id": rule_id or None,
                "category": category,
                "severity": (
                    str(combined.get("severity") or combined.get("impact_level"))
                    if combined.get("severity") or combined.get("impact_level")
                    else None
                ),
            },
            "validation": {
                "state": state,
                "disposition": disposition or None,
                "attempt_count": int(item.get("validation_attempt_count") or 0),
            },
            "location": location,
            "summary": self._one_line(summary),
            "symbol_refs": symbol_refs,
            "evidence_refs": refs,
            "confidence": self._confidence(combined.get("confidence")),
            "provenance": {
                "backend": ",".join(item.get("sources") or []),
                "revision": getattr(self.candidate_ledger, "revision", ""),
            },
        }

    def _backend_record(
        self, item: Dict[str, Any], symbols_by_file: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        location = {
            "file": normalize_project_path(item.get("file_path")) or None,
            "line": self._positive_coordinate(item.get("line")),
            "column": None,
        }
        identity = json.dumps(item, sort_keys=True, default=str)
        source_func = str(item.get("source_func") or "")
        sink_func = str(item.get("sink_func") or "")
        return {
            "finding_id": "signal:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
            "record_type": "backend_signal",
            "producer": "backend_signal",
            "authority": "backend_signal",
            "rule": {
                "id": str(item.get("bug_type") or "") or None,
                "category": str(item.get("bug_type") or "backend_signal"),
                "severity": None,
            },
            "validation": {
                "state": "unvalidated",
                "disposition": None,
                "attempt_count": 0,
            },
            "location": location,
            "summary": self._one_line(
                f"{source_func} -> {sink_func}: {item.get('bug_type') or 'backend signal'}"
            ),
            "symbol_refs": self._symbols_at(location, symbols_by_file),
            "evidence_refs": (
                [{"kind": "source", **location}] if location["file"] and location["line"] else []
            ),
            "confidence": self._confidence(item.get("confidence")),
            "provenance": {
                "backend": str(item.get("tool") or "unknown"),
                "revision": "",
                "svf_groups": item.get("svf_groups") or [],
            },
        }

    def _filter(
        self, records: Iterable[Dict[str, Any]], arguments: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        symbol_id = str(arguments.get("symbol_id") or "")
        producers = set(arguments.get("producers") or [])
        states = set(arguments.get("validation_states") or [])
        rule_id = str(arguments.get("rule_id") or "")
        category = str(arguments.get("category") or "")
        return [
            item
            for item in records
            if (not symbol_id or symbol_id in item.get("symbol_refs", []))
            and (not producers or item.get("producer") in producers)
            and (not states or (item.get("validation") or {}).get("state") in states)
            and (not rule_id or (item.get("rule") or {}).get("id") == rule_id)
            and (not category or (item.get("rule") or {}).get("category") == category)
        ]

    def _symbols_at(
        self, location: Dict[str, Any], symbols_by_file: Dict[str, List[Dict[str, Any]]]
    ) -> List[str]:
        file_path = normalize_project_path(location.get("file"))
        line = int(location.get("line") or 0)
        if not file_path or not line:
            return []
        refs = []
        for record in symbols_by_file.get(file_path, []):
            start = int(record.get("start_line") or 0)
            end = int(record.get("end_line") or start)
            if start <= line <= end:
                refs.append(str(record["symbol_id"]))
        return sorted(refs)

    @staticmethod
    def _producer(item: Dict[str, Any], payload: Dict[str, Any]) -> str:
        sources = " ".join(
            str(value or "").lower()
            for value in [
                *(item.get("sources") or []),
                payload.get("candidate_source"),
                payload.get("finding_kind"),
            ]
        )
        attribution = payload.get("attribution") or {}
        discovered = set(attribution.get("discovered_by") or [])
        if "llm_active_discovery" in discovered or "active_discovery" in sources:
            return "active_discovery"
        if "backend_signal" in discovered or any(
            value in sources
            for value in ("svf", "saber", "joern", "java_provider", "backend_signal")
        ):
            return "backend_signal"
        if "graph" in sources:
            return "graph_rule"
        return "deterministic_rule"

    @staticmethod
    def _validation_state(disposition: str, status: str) -> str:
        if disposition == "confirmed":
            return "confirmed"
        if disposition in {"rejected_with_proof", "rejected_with_evidence"}:
            return "rejected"
        if disposition in {
            "needs_review",
            "deferred_budget",
            "interrupted",
            "shadow_observation",
        }:
            return "deferred"
        if disposition == "engine_failed":
            return "engine_failed"
        if status in {"pending", "queued", "planned", "running"}:
            return "pending"
        return "unvalidated"

    @staticmethod
    def _evidence_ref(value: Any) -> Optional[Dict[str, Any]]:
        if isinstance(value, str) and value:
            return {"kind": "backend_record", "id": value[:500]}
        if not isinstance(value, dict):
            return None
        kind = str(value.get("kind") or "evidence")[:80]
        result: Dict[str, Any] = {"kind": kind}
        if value.get("id") is not None:
            result["id"] = str(value["id"])[:500]
        file_path = normalize_project_path(value.get("file") or value.get("file_path"))
        if file_path:
            result["file"] = file_path
        if value.get("line") is not None:
            result["line"] = int(value["line"])
        if value.get("column") is not None:
            result["column"] = int(value["column"])
        return result if len(result) > 1 else None

    @staticmethod
    def _location(payload: Dict[str, Any], ticket: Dict[str, Any]) -> Dict[str, Any]:
        raw = payload.get("location")
        if isinstance(raw, dict):
            file_path = raw.get("file") or raw.get("file_path")
            line = raw.get("line") or raw.get("lineNumber")
            column = raw.get("column")
        else:
            origin = str(ticket.get("origin") or payload.get("file_path") or "")
            match = re.match(r"^(.*?):(\d+)(?::(\d+))?$", origin)
            file_path = match.group(1) if match else origin
            line = match.group(2) if match else ticket.get("line") or payload.get("line")
            column = match.group(3) if match and match.group(3) else payload.get("column")
        return {
            "file": normalize_project_path(file_path) or None,
            "line": QueryStaticFindingsTool._positive_coordinate(line),
            "column": QueryStaticFindingsTool._positive_coordinate(column),
        }

    @staticmethod
    def _one_line(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip()[:500]

    @staticmethod
    def _confidence(value: Any) -> Optional[float]:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, min(1.0, number)) if math.isfinite(number) else None

    @staticmethod
    def _positive_coordinate(value: Any) -> Optional[int]:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    def _database(self) -> Any:
        backend = getattr(self.code_index, "_backend", None)
        db = getattr(backend, "db", None)
        if db is not None:
            return db
        return getattr(getattr(backend, "_clang", None), "db", None)
