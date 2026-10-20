"""Evidence-backed, zero-LLM security semantics for selective active discovery.

The security map is intentionally separate from the historical per-function
semantic snapshot.  It contains only program/user facts that can be rebuilt
without an LLM, plus explicitly unverified published contracts and bounded audit
units planned from those observations. LLM
discovery reports are persisted alongside the map but never mutate a claim
into a confirmed finding.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..config.function_entry import FunctionEntry
from .contracts import CallSemanticMatch, code_tokens
from .models import LocalPatternSemantics


SECURITY_MAP_SCHEMA_VERSION = "zscope.security_semantic_map.v2"
SEMANTIC_CLAIM_SCHEMA_VERSION = "zscope.semantic_claim.v1"
AUDIT_UNIT_SCHEMA_VERSION = "zscope.audit_unit.v2"
FINE_COVERAGE_FAMILIES = frozenset({"resource_lifecycle", "callback_concurrency"})
DISCOVERY_REPORT_SCHEMA_VERSION = "zscope.discovery_report.v1"
SEMANTIC_CLAIM_DELTA_SCHEMA_VERSION = "zscope.semantic_claim_delta.v1"

SEMANTIC_CLAIM_KINDS = frozenset(
    {
        "input_origin",
        "trust_boundary",
        "authorization_guard",
        "sanitizer",
        "resource_transition",
        "ownership_transfer",
        "bounds_contract",
        "error_contract",
        "state_transition",
        "lock_order",
        "happens_before",
        "callback_lifetime",
        "sensitive_sink",
    }
)
SEMANTIC_CLAIM_ORIGINS = frozenset({"program", "user", "llm"})
SEMANTIC_CLAIM_STATUSES = frozenset({"known", "unknown", "conflicting"})
AUDIT_UNIT_KINDS = frozenset(
    {
        "source_sink_path",
        "resource_protocol",
        "state_machine",
        "callback_concurrency",
        "auth_boundary",
        "known_variant",
    }
)
DISCOVERY_COVERAGE_STATUSES = frozenset({"complete", "partial", "failed"})
IMPACT_LEVELS = frozenset({"low", "medium", "high", "critical"})

_EVENT_PATTERNS: Tuple[Tuple[str, str, re.Pattern[str]], ...] = (
    (
        "memory_bounds",
        "copy_or_length_sink",
        re.compile(
            r"\b(memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|"
            r"read|recv|fread|arraycopy|copyOf|System\.arraycopy)\s*\(",
            re.IGNORECASE,
        ),
    ),
    (
        "resource_lifecycle",
        "resource_transition",
        re.compile(
            r"\b(malloc|calloc|realloc|strdup|free|open|close|fopen|fclose|socket|"
            r"mmap|munmap|new|delete|FileInputStream|FileOutputStream)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "callback_concurrency",
        "callback_or_lock_event",
        re.compile(
            r"\b(pthread_create|pthread_mutex_(?:lock|unlock)|pthread_rwlock_|"
            r"pthread_cond_(?:wait|signal|broadcast)|sem_(?:wait|post|trywait)|"
            r"std::thread|Thread\s*\(|Executor|CompletableFuture|register_callback|"
            r"callback|schedule|timer|atomic_)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "state_protocol",
        "state_or_dispatch_event",
        re.compile(
            r"\b(switch|case|state|status|opcode|command|dispatch|publish|register|"
            r"unregister|initialize|shutdown)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "input_boundary",
        "external_input",
        re.compile(
            r"\b(recv|read|fread|getenv|argv|getParameter|getHeader|RequestBody|"
            r"PathVariable|RequestParam|bodyToMono)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "auth_boundary",
        "authorization_event",
        re.compile(
            r"\b(authoriz|authn|authz|permission|tenant|principal|role|PreAuthorize|"
            r"Secured|permitAll|denyAll|checkAccess)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "sensitive_sink",
        "security_sensitive_sink",
        re.compile(
            r"\b(system|popen|exec|ProcessBuilder|executeQuery|executeUpdate|"
            r"createQuery|lookup|InitialContext|URL\s*\(|URI\s*\(|Files\.|"
            r"ObjectInputStream|readObject|Cipher\.getInstance)\b",
            re.IGNORECASE,
        ),
    ),
)
_INDIRECT_CALL_RE = re.compile(
    r"(?:\(\s*\*\s*[A-Za-z_]\w*\s*\)|[A-Za-z_]\w*\s*->\s*[A-Za-z_]\w*)\s*\("
)
_LINE_PREFIX_RE = re.compile(r"^\s*(\d+)\s*\|\s?(.*)$")

_CONTRACT_EVENT_KINDS = {
    "allocator": ("resource_lifecycle", "resource_transition"),
    "calloc": ("resource_lifecycle", "resource_transition"),
    "reallocator": ("resource_lifecycle", "resource_transition"),
    "deallocator": ("resource_lifecycle", "resource_transition"),
    "io_acquire": ("resource_lifecycle", "resource_transition"),
    "io_release": ("resource_lifecycle", "resource_transition"),
    "ownership_transfer": ("resource_lifecycle", "ownership_transfer"),
    "reference_retention": ("resource_lifecycle", "resource_transition"),
    "lock": ("callback_concurrency", "lock_order"),
    "unlock": ("callback_concurrency", "lock_order"),
    "callback_register": ("callback_concurrency", "callback_lifetime"),
    "lock_init": ("callback_concurrency", "state_transition"),
    "lock_destroy": ("callback_concurrency", "state_transition"),
    "lock_state": ("callback_concurrency", "state_transition"),
    "lock_wait": ("callback_concurrency", "state_transition"),
    "condition_init": ("callback_concurrency", "state_transition"),
    "condition_destroy": ("callback_concurrency", "state_transition"),
    "condition_signal": ("callback_concurrency", "state_transition"),
    "thread_create": ("callback_concurrency", "callback_lifetime"),
    "thread_release": ("callback_concurrency", "callback_lifetime"),
    "standard_operation": ("resource_lifecycle", "resource_transition"),
    "copy": ("memory_bounds", "bounds_contract"),
    "recv_source": ("input_boundary", "input_origin"),
    "send_sink": ("sensitive_sink", "sensitive_sink"),
    "format_sink": ("sensitive_sink", "sensitive_sink"),
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _digest(value: Any, *, length: int = 24) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:length]


def _strict_mapping(
    raw: Mapping[str, Any],
    *,
    required: Iterable[str],
    allowed: Iterable[str],
    label: str,
) -> Dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{label} must be an object")
    required_set = set(required)
    allowed_set = set(allowed)
    missing = sorted(required_set - set(raw))
    extra = sorted(set(raw) - allowed_set)
    if missing:
        raise ValueError(f"{label} missing required field(s): {', '.join(missing)}")
    if extra:
        raise ValueError(f"{label} has unknown field(s): {', '.join(extra)}")
    return dict(raw)


def _string_list(value: Any, label: str, *, nonempty: bool = False) -> Tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    result = tuple(str(item).strip() for item in value if str(item).strip())
    if len(result) != len(value):
        raise ValueError(f"{label} must contain non-empty strings")
    if nonempty and not result:
        raise ValueError(f"{label} must not be empty")
    return result


def _json_object(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    # Round-trip now so non-JSON extension objects never reach the sidecar.
    try:
        parsed = json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be JSON serializable") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must remain an object after JSON round-trip")
    return parsed


@dataclass(frozen=True)
class SemanticClaim:
    claim_id: str
    subject_uid: str
    kind: str
    value: Dict[str, Any]
    locations: Tuple[Dict[str, Any], ...]
    evidence_refs: Tuple[str, ...]
    origin: str
    confidence: float
    status: str
    schema_version: str = SEMANTIC_CLAIM_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SEMANTIC_CLAIM_SCHEMA_VERSION:
            raise ValueError("unsupported SemanticClaim schema_version")
        if not self.claim_id or not self.subject_uid:
            raise ValueError("SemanticClaim identity fields must not be empty")
        if self.kind not in SEMANTIC_CLAIM_KINDS:
            raise ValueError(f"unsupported SemanticClaim kind: {self.kind}")
        if self.origin not in SEMANTIC_CLAIM_ORIGINS:
            raise ValueError(f"unsupported SemanticClaim origin: {self.origin}")
        if self.status not in SEMANTIC_CLAIM_STATUSES:
            raise ValueError(f"unsupported SemanticClaim status: {self.status}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("SemanticClaim confidence must be between 0 and 1")
        if not self.evidence_refs:
            raise ValueError("SemanticClaim requires at least one evidence_ref")
        for location in self.locations:
            _strict_mapping(
                location,
                required=(),
                allowed=("file", "line", "end_line", "function"),
                label="SemanticClaim.location",
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "subject_uid": self.subject_uid,
            "kind": self.kind,
            "value": dict(self.value),
            "locations": [dict(item) for item in self.locations],
            "evidence_refs": list(self.evidence_refs),
            "origin": self.origin,
            "confidence": float(self.confidence),
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SemanticClaim":
        data = _strict_mapping(
            raw,
            required=(
                "schema_version",
                "claim_id",
                "subject_uid",
                "kind",
                "value",
                "locations",
                "evidence_refs",
                "origin",
                "confidence",
                "status",
            ),
            allowed=(
                "schema_version",
                "claim_id",
                "subject_uid",
                "kind",
                "value",
                "locations",
                "evidence_refs",
                "origin",
                "confidence",
                "status",
            ),
            label="SemanticClaim",
        )
        if not isinstance(data["locations"], list) or any(
            not isinstance(item, dict) for item in data["locations"]
        ):
            raise ValueError("SemanticClaim.locations must be an array of objects")
        return cls(
            schema_version=str(data["schema_version"]),
            claim_id=str(data["claim_id"]),
            subject_uid=str(data["subject_uid"]),
            kind=str(data["kind"]),
            value=_json_object(data["value"], "SemanticClaim.value"),
            locations=tuple(dict(item) for item in data["locations"]),
            evidence_refs=_string_list(
                data["evidence_refs"], "SemanticClaim.evidence_refs", nonempty=True
            ),
            origin=str(data["origin"]),
            confidence=float(data["confidence"]),
            status=str(data["status"]),
        )


@dataclass(frozen=True)
class CoverageKey:
    """Program observation identity, never a claim that an obligation is proved."""

    family: str
    function_uid: str
    object_ref: Optional[str]
    operation_site: str
    build_context: Optional[str]
    scope_discriminator: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(v, str) and v for v in (self.family, self.function_uid, self.operation_site)
        ):
            raise ValueError("CoverageKey requires family, function and operation site")
        for value in (self.object_ref, self.build_context):
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError("CoverageKey optional identities must be nonempty or null")
        if self.build_context is not None and not re.fullmatch(r"[0-9a-f]{64}", self.build_context):
            raise ValueError("CoverageKey build_context must be a verified context digest or null")
        if not isinstance(self.scope_discriminator, str) or (
            self.build_context is None and not self.scope_discriminator
        ):
            raise ValueError("CoverageKey unknown build requires stable scope discriminator")

    def to_dict(self) -> Dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    def identity(self) -> str:
        value = self.to_dict()
        if self.build_context is not None:
            value["scope_discriminator"] = ""
        return "COVER_" + _digest(value, length=64)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CoverageKey":
        fields = tuple(cls.__dataclass_fields__)
        return cls(**_strict_mapping(raw, required=fields, allowed=fields, label="CoverageKey"))


@dataclass(frozen=True)
class AuditOccurrence:
    entry_identity: str
    entry_path: Tuple[str, ...]
    event_refs: Tuple[str, ...]
    reachability: str = "call_path"

    def __post_init__(self) -> None:
        if (
            not self.entry_identity
            or not self.entry_path
            or self.reachability not in {"call_path", "callback_registration", "legacy_unknown"}
        ):
            raise ValueError("invalid AuditOccurrence")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_identity": self.entry_identity,
            "entry_path": list(self.entry_path),
            "event_refs": list(self.event_refs),
            "reachability": self.reachability,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AuditOccurrence":
        fields = ("entry_identity", "entry_path", "event_refs", "reachability")
        data = _strict_mapping(raw, required=fields, allowed=fields, label="AuditOccurrence")
        return cls(
            str(data["entry_identity"]),
            _string_list(data["entry_path"], "AuditOccurrence.entry_path", nonempty=True),
            _string_list(data["event_refs"], "AuditOccurrence.event_refs"),
            str(data["reachability"]),
        )


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    family: str
    kind: str
    function_uid: str
    file: str
    line: int
    expression: str
    evidence_ref: str
    object_ref: Optional[str] = None
    operation_site: str = ""
    build_context: Optional[str] = None
    callback_target: Optional[str] = None

    def __post_init__(self) -> None:
        if self.build_context is not None and (
            not isinstance(self.build_context, str)
            or not re.fullmatch(r"[0-9a-f]{64}", self.build_context)
        ):
            raise ValueError("SecurityEvent build_context must be a context digest or null")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "family": self.family,
            "kind": self.kind,
            "function_uid": self.function_uid,
            "file": self.file,
            "line": self.line,
            "expression": self.expression,
            "evidence_ref": self.evidence_ref,
            "object_ref": self.object_ref,
            "operation_site": self.operation_site,
            "build_context": self.build_context,
            "callback_target": self.callback_target,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SecurityEvent":
        fields = (
            "event_id",
            "family",
            "kind",
            "function_uid",
            "file",
            "line",
            "expression",
            "evidence_ref",
        )
        extras = ("object_ref", "operation_site", "build_context", "callback_target")
        data = _strict_mapping(
            raw, required=fields, allowed=(*fields, *extras), label="SecurityEvent"
        )
        for name in ("object_ref", "build_context", "callback_target"):
            if data.get(name) is not None and (not isinstance(data[name], str) or not data[name]):
                raise ValueError(f"SecurityEvent.{name} must be nonempty or null")
        result = cls(
            event_id=str(data["event_id"]),
            family=str(data["family"]),
            kind=str(data["kind"]),
            function_uid=str(data["function_uid"]),
            file=str(data["file"]),
            line=int(data["line"]),
            expression=str(data["expression"]),
            evidence_ref=str(data["evidence_ref"]),
            object_ref=data.get("object_ref"),
            operation_site=str(data.get("operation_site") or ""),
            build_context=data.get("build_context"),
            callback_target=data.get("callback_target"),
        )
        if not all(
            (result.event_id, result.family, result.kind, result.function_uid, result.evidence_ref)
        ):
            raise ValueError("SecurityEvent identity fields must not be empty")
        return result


@dataclass(frozen=True)
class SemanticUnknown:
    unknown_id: str
    subject_uid: str
    kind: str
    reason: str
    evidence_refs: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "unknown_id": self.unknown_id,
            "subject_uid": self.subject_uid,
            "kind": self.kind,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SemanticUnknown":
        fields = ("unknown_id", "subject_uid", "kind", "reason", "evidence_refs")
        data = _strict_mapping(raw, required=fields, allowed=fields, label="SemanticUnknown")
        result = cls(
            unknown_id=str(data["unknown_id"]),
            subject_uid=str(data["subject_uid"]),
            kind=str(data["kind"]),
            reason=str(data["reason"]),
            evidence_refs=_string_list(
                data["evidence_refs"], "SemanticUnknown.evidence_refs", nonempty=True
            ),
        )
        if not result.unknown_id or not result.subject_uid or not result.kind:
            raise ValueError("SemanticUnknown identity fields must not be empty")
        return result


@dataclass(frozen=True)
class FunctionSecurityRecord:
    function_uid: str
    index_name: str
    function_name: str
    file_path: str
    start_line: int
    end_line: int
    signature: str
    code_hash: str
    entry_identities: Tuple[str, ...]
    entry_paths: Tuple[Tuple[str, ...], ...]
    callees: Tuple[str, ...]
    unresolved_callees: Tuple[str, ...]
    events: Tuple[SecurityEvent, ...]
    backend_coverage: Dict[str, Any]
    diff_focus: Dict[str, Any] = field(default_factory=dict)
    entry_occurrences: Tuple[AuditOccurrence, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "function_uid": self.function_uid,
            "index_name": self.index_name,
            "function_name": self.function_name,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "signature": self.signature,
            "code_hash": self.code_hash,
            "entry_identities": list(self.entry_identities),
            "entry_paths": [list(path) for path in self.entry_paths],
            "callees": list(self.callees),
            "unresolved_callees": list(self.unresolved_callees),
            "events": [item.to_dict() for item in self.events],
            "backend_coverage": dict(self.backend_coverage),
            "diff_focus": dict(self.diff_focus),
            "entry_occurrences": [item.to_dict() for item in self.entry_occurrences],
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "FunctionSecurityRecord":
        fields = (
            "function_uid",
            "index_name",
            "function_name",
            "file_path",
            "start_line",
            "end_line",
            "signature",
            "code_hash",
            "entry_identities",
            "entry_paths",
            "callees",
            "unresolved_callees",
            "events",
            "backend_coverage",
            "diff_focus",
        )
        data = _strict_mapping(
            raw,
            required=fields,
            allowed=(*fields, "entry_occurrences"),
            label="FunctionSecurityRecord",
        )
        if not isinstance(data.get("entry_occurrences", []), list):
            raise ValueError("FunctionSecurityRecord.entry_occurrences must be an array")
        if not isinstance(data["entry_paths"], list) or any(
            not isinstance(path, list) for path in data["entry_paths"]
        ):
            raise ValueError("FunctionSecurityRecord.entry_paths must be an array of arrays")
        if not isinstance(data["events"], list):
            raise ValueError("FunctionSecurityRecord.events must be an array")
        return cls(
            function_uid=str(data["function_uid"]),
            index_name=str(data["index_name"]),
            function_name=str(data["function_name"]),
            file_path=str(data["file_path"]),
            start_line=int(data["start_line"]),
            end_line=int(data["end_line"]),
            signature=str(data["signature"]),
            code_hash=str(data["code_hash"]),
            entry_identities=_string_list(
                data["entry_identities"], "FunctionSecurityRecord.entry_identities"
            ),
            entry_paths=tuple(
                _string_list(path, "FunctionSecurityRecord.entry_paths.item", nonempty=True)
                for path in data["entry_paths"]
            ),
            callees=_string_list(data["callees"], "FunctionSecurityRecord.callees"),
            unresolved_callees=_string_list(
                data["unresolved_callees"], "FunctionSecurityRecord.unresolved_callees"
            ),
            events=tuple(SecurityEvent.from_dict(item) for item in data["events"]),
            backend_coverage=_json_object(
                data["backend_coverage"], "FunctionSecurityRecord.backend_coverage"
            ),
            diff_focus=_json_object(data["diff_focus"], "FunctionSecurityRecord.diff_focus"),
            entry_occurrences=tuple(
                AuditOccurrence.from_dict(item) for item in data.get("entry_occurrences", [])
            ),
        )


def event_coverage_key(
    semantic_map: "SecuritySemanticMap", record: FunctionSecurityRecord, event: SecurityEvent
) -> CoverageKey:
    return CoverageKey(
        event.family,
        record.function_uid,
        event.object_ref,
        event.operation_site or f"{event.file}:{event.line}:{event.event_id}",
        event.build_context,
        _digest(
            (
                semantic_map.project_id,
                semantic_map.revision,
                record.function_uid,
                record.index_name,
                record.file_path,
                record.start_line,
                record.end_line,
                record.signature,
                record.code_hash,
            ),
            length=64,
        ),
    )


@dataclass(frozen=True)
class AuditUnit:
    unit_id: str
    unit_kind: str
    fingerprint: str
    risk_score: int
    risk_reasons: Tuple[str, ...]
    root_entries: Tuple[str, ...]
    member_functions: Tuple[str, ...]
    event_refs: Tuple[str, ...]
    claim_refs: Tuple[str, ...]
    unknown_refs: Tuple[str, ...]
    skill_families: Tuple[str, ...]
    backend_coverage: Dict[str, Any]
    candidate_desert: bool
    schema_version: str = AUDIT_UNIT_SCHEMA_VERSION
    coverage_keys: Tuple[CoverageKey, ...] = ()
    occurrences: Tuple[AuditOccurrence, ...] = ()
    migration_status: str = "current"

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_UNIT_SCHEMA_VERSION:
            raise ValueError("unsupported AuditUnit schema_version")
        if self.unit_kind not in AUDIT_UNIT_KINDS:
            raise ValueError(f"unsupported AuditUnit unit_kind: {self.unit_kind}")
        if not self.unit_id or not self.fingerprint or not self.member_functions:
            raise ValueError("AuditUnit identity and members must not be empty")
        if not 0 <= int(self.risk_score) <= 100:
            raise ValueError("AuditUnit risk_score must be between 0 and 100")
        if self.migration_status not in {"current", "legacy_unverifiable"}:
            raise ValueError("invalid AuditUnit migration_status")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "unit_id": self.unit_id,
            "unit_kind": self.unit_kind,
            "fingerprint": self.fingerprint,
            "risk_score": int(self.risk_score),
            "risk_reasons": list(self.risk_reasons),
            "root_entries": list(self.root_entries),
            "member_functions": list(self.member_functions),
            "event_refs": list(self.event_refs),
            "claim_refs": list(self.claim_refs),
            "unknown_refs": list(self.unknown_refs),
            "skill_families": list(self.skill_families),
            "backend_coverage": dict(self.backend_coverage),
            "candidate_desert": bool(self.candidate_desert),
            "coverage_keys": [item.to_dict() for item in self.coverage_keys],
            "occurrences": [item.to_dict() for item in self.occurrences],
            "migration_status": self.migration_status,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AuditUnit":
        fields = (
            "schema_version",
            "unit_id",
            "unit_kind",
            "fingerprint",
            "risk_score",
            "risk_reasons",
            "root_entries",
            "member_functions",
            "event_refs",
            "claim_refs",
            "unknown_refs",
            "skill_families",
            "backend_coverage",
            "candidate_desert",
        )
        legacy = raw.get("schema_version") == "zscope.audit_unit.v1"
        extra = ("coverage_keys", "occurrences", "migration_status")
        data = _strict_mapping(
            raw,
            required=fields if legacy else (*fields, *extra),
            allowed=fields if legacy else (*fields, *extra),
            label="AuditUnit",
        )
        if legacy:
            old_fingerprint = str(data["fingerprint"])
            data["fingerprint"] = _digest(
                (AUDIT_UNIT_SCHEMA_VERSION, "legacy_unverifiable", old_fingerprint), length=64
            )
            data["unit_id"] = f"AUDIT_{data['fingerprint'][:20]}"
            data["schema_version"] = AUDIT_UNIT_SCHEMA_VERSION
            data["coverage_keys"] = [
                CoverageKey(
                    "unknown", str(uid), None, f"legacy:{old_fingerprint}", None, old_fingerprint
                ).to_dict()
                for uid in data["member_functions"]
            ]
            data["occurrences"] = [
                AuditOccurrence(
                    str(entry), (str(entry),), tuple(data["event_refs"]), "legacy_unknown"
                ).to_dict()
                for entry in data["root_entries"]
            ]
            data["migration_status"] = "legacy_unverifiable"
        if any(not isinstance(data[name], list) for name in ("coverage_keys", "occurrences")):
            raise ValueError("AuditUnit coverage keys and occurrences must be arrays")
        if not isinstance(data["candidate_desert"], bool):
            raise ValueError("AuditUnit.candidate_desert must be boolean")
        return cls(
            schema_version=str(data["schema_version"]),
            coverage_keys=tuple(CoverageKey.from_dict(item) for item in data["coverage_keys"]),
            occurrences=tuple(AuditOccurrence.from_dict(item) for item in data["occurrences"]),
            migration_status=str(data["migration_status"]),
            unit_id=str(data["unit_id"]),
            unit_kind=str(data["unit_kind"]),
            fingerprint=str(data["fingerprint"]),
            risk_score=int(data["risk_score"]),
            risk_reasons=_string_list(data["risk_reasons"], "AuditUnit.risk_reasons"),
            root_entries=_string_list(data["root_entries"], "AuditUnit.root_entries"),
            member_functions=_string_list(
                data["member_functions"], "AuditUnit.member_functions", nonempty=True
            ),
            event_refs=_string_list(data["event_refs"], "AuditUnit.event_refs"),
            claim_refs=_string_list(data["claim_refs"], "AuditUnit.claim_refs"),
            unknown_refs=_string_list(data["unknown_refs"], "AuditUnit.unknown_refs"),
            skill_families=_string_list(
                data["skill_families"], "AuditUnit.skill_families", nonempty=True
            ),
            backend_coverage=_json_object(data["backend_coverage"], "AuditUnit.backend_coverage"),
            candidate_desert=bool(data["candidate_desert"]),
        )


@dataclass(frozen=True)
class DiscoveryHypothesis:
    hypothesis_id: str
    defect_class: str
    impact_level: str
    confidence: float
    function: str
    location: str
    source: str
    sink: str
    resource: str
    entry_paths: Tuple[Tuple[str, ...], ...]
    path_conditions: Tuple[str, ...]
    positive_evidence_refs: Tuple[str, ...]
    negative_evidence_refs: Tuple[str, ...]
    missing_fact_kinds: Tuple[str, ...]
    description: str
    reasoning: str
    root_cause: str
    cwes: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not self.hypothesis_id
            or not self.defect_class
            or not self.function
            or not self.location
        ):
            raise ValueError("DiscoveryHypothesis requires identity, class, function, and location")
        if self.impact_level not in IMPACT_LEVELS:
            raise ValueError(f"unsupported impact_level: {self.impact_level}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("DiscoveryHypothesis confidence must be between 0 and 1")
        if not self.positive_evidence_refs:
            raise ValueError("DiscoveryHypothesis requires positive_evidence_refs")
        source = str(self.source or "").strip()
        sink = str(self.sink or "").strip()
        resource = str(self.resource or "").strip()
        if not resource and not (source and sink):
            raise ValueError("DiscoveryHypothesis requires source and sink or a resource")
        for label in self.cwes:
            if not re.fullmatch(r"CWE-[1-9][0-9]*", str(label)):
                raise ValueError(f"unsupported DiscoveryHypothesis cwe label: {label!r}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "defect_class": self.defect_class,
            "impact_level": self.impact_level,
            "confidence": float(self.confidence),
            "function": self.function,
            "location": self.location,
            "source": self.source,
            "sink": self.sink,
            "resource": self.resource,
            "entry_paths": [list(path) for path in self.entry_paths],
            "path_conditions": list(self.path_conditions),
            "positive_evidence_refs": list(self.positive_evidence_refs),
            "negative_evidence_refs": list(self.negative_evidence_refs),
            "missing_fact_kinds": list(self.missing_fact_kinds),
            "description": self.description,
            "reasoning": self.reasoning,
            "root_cause": self.root_cause,
            "cwes": list(self.cwes),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "DiscoveryHypothesis":
        fields = (
            "hypothesis_id",
            "defect_class",
            "impact_level",
            "confidence",
            "function",
            "location",
            "source",
            "sink",
            "resource",
            "entry_paths",
            "path_conditions",
            "positive_evidence_refs",
            "negative_evidence_refs",
            "missing_fact_kinds",
            "description",
            "reasoning",
            "root_cause",
        )
        data = _strict_mapping(
            raw, required=fields, allowed=fields + ("cwes",), label="DiscoveryHypothesis"
        )
        if not isinstance(data["entry_paths"], list) or any(
            not isinstance(path, list) for path in data["entry_paths"]
        ):
            raise ValueError("DiscoveryHypothesis.entry_paths must be an array of arrays")
        return cls(
            hypothesis_id=str(data["hypothesis_id"]),
            defect_class=str(data["defect_class"]),
            impact_level=str(data["impact_level"]),
            confidence=float(data["confidence"]),
            function=str(data["function"]),
            location=str(data["location"]),
            source=str(data["source"]),
            sink=str(data["sink"]),
            resource=str(data["resource"]),
            entry_paths=tuple(
                _string_list(path, "DiscoveryHypothesis.entry_paths.item", nonempty=True)
                for path in data["entry_paths"]
            ),
            path_conditions=_string_list(
                data["path_conditions"], "DiscoveryHypothesis.path_conditions"
            ),
            positive_evidence_refs=_string_list(
                data["positive_evidence_refs"],
                "DiscoveryHypothesis.positive_evidence_refs",
                nonempty=True,
            ),
            negative_evidence_refs=_string_list(
                data["negative_evidence_refs"], "DiscoveryHypothesis.negative_evidence_refs"
            ),
            missing_fact_kinds=_string_list(
                data["missing_fact_kinds"], "DiscoveryHypothesis.missing_fact_kinds"
            ),
            description=str(data["description"]),
            reasoning=str(data["reasoning"]),
            root_cause=str(data["root_cause"]),
            cwes=tuple(_string_list(data.get("cwes") or [], "DiscoveryHypothesis.cwes")),
        )


@dataclass(frozen=True)
class DiscoveryReport:
    unit_id: str
    unit_fingerprint: str
    coverage_status: str
    reviewed_function_uids: Tuple[str, ...]
    reviewed_claim_ids: Tuple[str, ...]
    tool_evidence_refs: Tuple[str, ...]
    hypotheses: Tuple[DiscoveryHypothesis, ...]
    unresolved_facts: Tuple[str, ...]
    schema_version: str = DISCOVERY_REPORT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != DISCOVERY_REPORT_SCHEMA_VERSION:
            raise ValueError("unsupported DiscoveryReport schema_version")
        if not self.unit_id or not self.unit_fingerprint:
            raise ValueError("DiscoveryReport unit identity must not be empty")
        if self.coverage_status not in DISCOVERY_COVERAGE_STATUSES:
            raise ValueError(f"unsupported discovery coverage_status: {self.coverage_status}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "unit_id": self.unit_id,
            "unit_fingerprint": self.unit_fingerprint,
            "coverage_status": self.coverage_status,
            "reviewed_function_uids": list(self.reviewed_function_uids),
            "reviewed_claim_ids": list(self.reviewed_claim_ids),
            "tool_evidence_refs": list(self.tool_evidence_refs),
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "unresolved_facts": list(self.unresolved_facts),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "DiscoveryReport":
        fields = (
            "schema_version",
            "unit_id",
            "unit_fingerprint",
            "coverage_status",
            "reviewed_function_uids",
            "reviewed_claim_ids",
            "tool_evidence_refs",
            "hypotheses",
            "unresolved_facts",
        )
        data = _strict_mapping(raw, required=fields, allowed=fields, label="DiscoveryReport")
        if not isinstance(data["hypotheses"], list):
            raise ValueError("DiscoveryReport.hypotheses must be an array")
        return cls(
            schema_version=str(data["schema_version"]),
            unit_id=str(data["unit_id"]),
            unit_fingerprint=str(data["unit_fingerprint"]),
            coverage_status=str(data["coverage_status"]),
            reviewed_function_uids=_string_list(
                data["reviewed_function_uids"], "DiscoveryReport.reviewed_function_uids"
            ),
            reviewed_claim_ids=_string_list(
                data["reviewed_claim_ids"], "DiscoveryReport.reviewed_claim_ids"
            ),
            tool_evidence_refs=_string_list(
                data["tool_evidence_refs"], "DiscoveryReport.tool_evidence_refs"
            ),
            hypotheses=tuple(DiscoveryHypothesis.from_dict(item) for item in data["hypotheses"]),
            unresolved_facts=_string_list(
                data["unresolved_facts"], "DiscoveryReport.unresolved_facts"
            ),
        )


@dataclass(frozen=True)
class SemanticClaimDelta:
    """Strict LLM semantic delta for one immutable audit-unit fingerprint."""

    unit_id: str
    unit_fingerprint: str
    claims: Tuple[SemanticClaim, ...]
    unknowns: Tuple[SemanticUnknown, ...]
    unresolved_facts: Tuple[str, ...]
    schema_version: str = SEMANTIC_CLAIM_DELTA_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SEMANTIC_CLAIM_DELTA_SCHEMA_VERSION:
            raise ValueError("unsupported SemanticClaimDelta schema_version")
        if not self.unit_id or not self.unit_fingerprint:
            raise ValueError("SemanticClaimDelta unit identity must not be empty")
        if any(claim.origin != "llm" for claim in self.claims):
            raise ValueError("SemanticClaimDelta claims must use origin=llm")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "unit_id": self.unit_id,
            "unit_fingerprint": self.unit_fingerprint,
            "claims": [claim.to_dict() for claim in self.claims],
            "unknowns": [unknown.to_dict() for unknown in self.unknowns],
            "unresolved_facts": list(self.unresolved_facts),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SemanticClaimDelta":
        fields = (
            "schema_version",
            "unit_id",
            "unit_fingerprint",
            "claims",
            "unknowns",
            "unresolved_facts",
        )
        data = _strict_mapping(raw, required=fields, allowed=fields, label="SemanticClaimDelta")
        if not isinstance(data["claims"], list):
            raise ValueError("SemanticClaimDelta.claims must be an array")
        if not isinstance(data["unknowns"], list):
            raise ValueError("SemanticClaimDelta.unknowns must be an array")
        return cls(
            schema_version=str(data["schema_version"]),
            unit_id=str(data["unit_id"]),
            unit_fingerprint=str(data["unit_fingerprint"]),
            claims=tuple(SemanticClaim.from_dict(item) for item in data["claims"]),
            unknowns=tuple(SemanticUnknown.from_dict(item) for item in data["unknowns"]),
            unresolved_facts=_string_list(
                data["unresolved_facts"], "SemanticClaimDelta.unresolved_facts"
            ),
        )


@dataclass(frozen=True)
class SecuritySemanticMap:
    project_id: str
    revision: str
    profile: str
    functions: Tuple[FunctionSecurityRecord, ...]
    claims: Tuple[SemanticClaim, ...]
    unknowns: Tuple[SemanticUnknown, ...]
    audit_units: Tuple[AuditUnit, ...]
    coverage: Dict[str, Any]
    fingerprints: Dict[str, Any]
    generated_at: str = field(default_factory=_utc_now)
    schema_version: str = SECURITY_MAP_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SECURITY_MAP_SCHEMA_VERSION:
            raise ValueError("unsupported SecuritySemanticMap schema_version")
        if not self.project_id:
            raise ValueError("SecuritySemanticMap.project_id must not be empty")
        for label, values in (
            ("function_uid", [item.function_uid for item in self.functions]),
            ("claim_id", [item.claim_id for item in self.claims]),
            ("unknown_id", [item.unknown_id for item in self.unknowns]),
            ("unit_id", [item.unit_id for item in self.audit_units]),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"SecuritySemanticMap has duplicate {label}")

    @property
    def migration_status(self) -> str:
        return (
            "legacy_unverifiable"
            if self.fingerprints.get("coverage_schema") == "legacy_unverifiable"
            or self.coverage.get("migration_status") == "legacy_unverifiable"
            else "current"
        )

    @property
    def map_fingerprint(self) -> str:
        return _digest(
            {
                "schema_version": self.schema_version,
                "project_id": self.project_id,
                "revision": self.revision,
                "profile": self.profile,
                "functions": [item.to_dict() for item in self.functions],
                "claims": [item.to_dict() for item in self.claims],
                "unknowns": [item.to_dict() for item in self.unknowns],
                "fingerprints": self.fingerprints,
            },
            length=64,
        )

    def with_audit_units(self, units: Sequence[AuditUnit]) -> "SecuritySemanticMap":
        return replace(self, audit_units=tuple(units))

    def with_semantic_deltas(self, deltas: Sequence[SemanticClaimDelta]) -> "SecuritySemanticMap":
        claims = {claim.claim_id: claim for claim in self.claims}
        unknowns = {unknown.unknown_id: unknown for unknown in self.unknowns}
        for delta in deltas:
            for claim in delta.claims:
                existing = claims.get(claim.claim_id)
                if existing is not None and existing != claim:
                    raise ValueError(f"conflicting semantic claim_id: {claim.claim_id}")
                claims[claim.claim_id] = claim
            for unknown in delta.unknowns:
                existing_unknown = unknowns.get(unknown.unknown_id)
                if existing_unknown is not None and existing_unknown != unknown:
                    raise ValueError(f"conflicting semantic unknown_id: {unknown.unknown_id}")
                unknowns[unknown.unknown_id] = unknown
        coverage = dict(self.coverage)
        coverage["llm_semantic_delta_count"] = len(deltas)
        coverage["llm_semantic_claim_count"] = sum(len(delta.claims) for delta in deltas)
        coverage["llm_semantic_unknown_count"] = sum(len(delta.unknowns) for delta in deltas)
        return replace(
            self,
            claims=tuple(sorted(claims.values(), key=lambda item: item.claim_id)),
            unknowns=tuple(sorted(unknowns.values(), key=lambda item: item.unknown_id)),
            coverage=coverage,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "revision": self.revision,
            "profile": self.profile,
            "generated_at": self.generated_at,
            "map_fingerprint": self.map_fingerprint,
            "functions": [item.to_dict() for item in self.functions],
            "claims": [item.to_dict() for item in self.claims],
            "unknowns": [item.to_dict() for item in self.unknowns],
            "audit_units": [item.to_dict() for item in self.audit_units],
            "coverage": dict(self.coverage),
            "fingerprints": dict(self.fingerprints),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SecuritySemanticMap":
        fields = (
            "schema_version",
            "project_id",
            "revision",
            "profile",
            "generated_at",
            "map_fingerprint",
            "functions",
            "claims",
            "unknowns",
            "audit_units",
            "coverage",
            "fingerprints",
        )
        data = _strict_mapping(raw, required=fields, allowed=fields, label="SecuritySemanticMap")
        for key in ("functions", "claims", "unknowns", "audit_units"):
            if not isinstance(data[key], list):
                raise ValueError(f"SecuritySemanticMap.{key} must be an array")
        legacy = data["schema_version"] == "zscope.security_semantic_map.v1"
        for unit in data["audit_units"]:
            expected = "zscope.audit_unit.v1" if legacy else AUDIT_UNIT_SCHEMA_VERSION
            if not isinstance(unit, Mapping) or unit.get("schema_version") != expected:
                raise ValueError("SecuritySemanticMap mixed audit unit schema versions")
        for record in data["functions"]:
            if not isinstance(record, Mapping):
                raise ValueError("SecuritySemanticMap function must be an object")
            if legacy and "entry_occurrences" in record:
                raise ValueError("legacy map contains v2 occurrence metadata")
            if not legacy and "entry_occurrences" not in record:
                raise ValueError("v2 map missing occurrence metadata")
            if not isinstance(record.get("events"), list):
                raise ValueError("SecuritySemanticMap events must be an array")
            for event in record["events"]:
                if not isinstance(event, Mapping):
                    raise ValueError("SecuritySemanticMap event must be an object")
                extra = {"object_ref", "operation_site", "build_context", "callback_target"}
                if legacy and any(name in event for name in extra):
                    raise ValueError("legacy map contains v2 event metadata")
                if not legacy and not extra <= set(event):
                    raise ValueError("v2 map missing event metadata")
        if legacy:
            # Validate the old byte-independent identity before migration.
            original = {
                key: data[key]
                for key in (
                    "schema_version",
                    "project_id",
                    "revision",
                    "profile",
                    "functions",
                    "claims",
                    "unknowns",
                    "fingerprints",
                )
            }
            if str(data["map_fingerprint"]) != _digest(original, length=64):
                raise ValueError("SecuritySemanticMap map_fingerprint mismatch")
            data["schema_version"] = SECURITY_MAP_SCHEMA_VERSION
            data["coverage"] = {**data["coverage"], "migration_status": "legacy_unverifiable"}
            data["fingerprints"] = {
                **data["fingerprints"],
                "coverage_schema": "legacy_unverifiable",
            }
        result = cls(
            schema_version=str(data["schema_version"]),
            project_id=str(data["project_id"]),
            revision=str(data["revision"]),
            profile=str(data["profile"]),
            generated_at=str(data["generated_at"]),
            functions=tuple(FunctionSecurityRecord.from_dict(item) for item in data["functions"]),
            claims=tuple(SemanticClaim.from_dict(item) for item in data["claims"]),
            unknowns=tuple(SemanticUnknown.from_dict(item) for item in data["unknowns"]),
            audit_units=tuple(AuditUnit.from_dict(item) for item in data["audit_units"]),
            coverage=_json_object(data["coverage"], "SecuritySemanticMap.coverage"),
            fingerprints=_json_object(data["fingerprints"], "SecuritySemanticMap.fingerprints"),
        )
        if not legacy and str(data["map_fingerprint"]) != result.map_fingerprint:
            raise ValueError("SecuritySemanticMap map_fingerprint mismatch")
        if (
            result.fingerprints.get("coverage_schema") == "legacy_unverifiable"
            and result.coverage.get("migration_status") != "legacy_unverifiable"
        ):
            raise ValueError("SecuritySemanticMap legacy migration marker mismatch")
        return result


SEMANTIC_CLAIM_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "claim_id",
        "subject_uid",
        "kind",
        "value",
        "locations",
        "evidence_refs",
        "origin",
        "confidence",
        "status",
    ],
    "properties": {
        "schema_version": {"const": SEMANTIC_CLAIM_SCHEMA_VERSION},
        "claim_id": {"type": "string"},
        "subject_uid": {"type": "string"},
        "kind": {"enum": sorted(SEMANTIC_CLAIM_KINDS)},
        "value": {"type": "object"},
        "locations": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                    "function": {"type": "string"},
                },
            },
        },
        "evidence_refs": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "origin": {"enum": sorted(SEMANTIC_CLAIM_ORIGINS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "status": {"enum": sorted(SEMANTIC_CLAIM_STATUSES)},
    },
}

COVERAGE_KEY_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "family",
        "function_uid",
        "object_ref",
        "operation_site",
        "build_context",
        "scope_discriminator",
    ],
    "properties": {
        "family": {"type": "string", "minLength": 1},
        "function_uid": {"type": "string", "minLength": 1},
        "object_ref": {"type": ["string", "null"], "minLength": 1},
        "operation_site": {"type": "string", "minLength": 1},
        "build_context": {"type": ["string", "null"], "pattern": "^[0-9a-f]{64}$"},
        "scope_discriminator": {"type": "string"},
    },
}
AUDIT_OCCURRENCE_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["entry_identity", "entry_path", "event_refs", "reachability"],
    "properties": {
        "entry_identity": {"type": "string", "minLength": 1},
        "entry_path": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "event_refs": {"type": "array", "items": {"type": "string"}},
        "reachability": {"enum": ["call_path", "callback_registration", "legacy_unknown"]},
    },
}

AUDIT_UNIT_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "unit_id",
        "unit_kind",
        "fingerprint",
        "risk_score",
        "risk_reasons",
        "root_entries",
        "member_functions",
        "event_refs",
        "claim_refs",
        "unknown_refs",
        "skill_families",
        "backend_coverage",
        "candidate_desert",
        "coverage_keys",
        "occurrences",
        "migration_status",
    ],
    "properties": {
        "schema_version": {"const": AUDIT_UNIT_SCHEMA_VERSION},
        "unit_id": {"type": "string"},
        "unit_kind": {"enum": sorted(AUDIT_UNIT_KINDS)},
        "fingerprint": {"type": "string"},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "risk_reasons": {"type": "array", "items": {"type": "string"}},
        "root_entries": {"type": "array", "items": {"type": "string"}},
        "member_functions": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "event_refs": {"type": "array", "items": {"type": "string"}},
        "claim_refs": {"type": "array", "items": {"type": "string"}},
        "unknown_refs": {"type": "array", "items": {"type": "string"}},
        "skill_families": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        "backend_coverage": {"type": "object"},
        "candidate_desert": {"type": "boolean"},
        "coverage_keys": {"type": "array", "items": COVERAGE_KEY_JSON_SCHEMA},
        "occurrences": {"type": "array", "items": AUDIT_OCCURRENCE_JSON_SCHEMA},
        "migration_status": {"enum": ["current", "legacy_unverifiable"]},
    },
}

DISCOVERY_HYPOTHESIS_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "anyOf": [
        {
            "properties": {"resource": {"type": "string", "minLength": 1}},
            "required": ["resource"],
        },
        {
            "properties": {
                "source": {"type": "string", "minLength": 1},
                "sink": {"type": "string", "minLength": 1},
            },
            "required": ["source", "sink"],
        },
    ],
    "required": [
        "hypothesis_id",
        "defect_class",
        "impact_level",
        "confidence",
        "function",
        "location",
        "source",
        "sink",
        "resource",
        "entry_paths",
        "path_conditions",
        "positive_evidence_refs",
        "negative_evidence_refs",
        "missing_fact_kinds",
        "description",
        "reasoning",
        "root_cause",
    ],
    "properties": {
        "hypothesis_id": {"type": "string"},
        "defect_class": {"type": "string"},
        "impact_level": {"enum": sorted(IMPACT_LEVELS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "function": {"type": "string"},
        "location": {"type": "string"},
        "source": {"type": "string"},
        "sink": {"type": "string"},
        "resource": {"type": "string"},
        "entry_paths": {
            "type": "array",
            "items": {"type": "array", "minItems": 1, "items": {"type": "string"}},
        },
        "path_conditions": {"type": "array", "items": {"type": "string"}},
        "positive_evidence_refs": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string"},
        },
        "negative_evidence_refs": {"type": "array", "items": {"type": "string"}},
        "missing_fact_kinds": {"type": "array", "items": {"type": "string"}},
        "description": {"type": "string"},
        "reasoning": {"type": "string"},
        "root_cause": {"type": "string"},
        "cwes": {
            "type": "array",
            "items": {"type": "string", "pattern": r"^CWE-[1-9][0-9]*$"},
        },
    },
}

DISCOVERY_REPORT_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "unit_id",
        "unit_fingerprint",
        "coverage_status",
        "reviewed_function_uids",
        "reviewed_claim_ids",
        "tool_evidence_refs",
        "hypotheses",
        "unresolved_facts",
    ],
    "properties": {
        "schema_version": {"const": DISCOVERY_REPORT_SCHEMA_VERSION},
        "unit_id": {"type": "string"},
        "unit_fingerprint": {"type": "string"},
        "coverage_status": {"enum": sorted(DISCOVERY_COVERAGE_STATUSES)},
        "reviewed_function_uids": {"type": "array", "items": {"type": "string"}},
        "reviewed_claim_ids": {"type": "array", "items": {"type": "string"}},
        "tool_evidence_refs": {"type": "array", "items": {"type": "string"}},
        "hypotheses": {"type": "array", "items": DISCOVERY_HYPOTHESIS_JSON_SCHEMA},
        "unresolved_facts": {"type": "array", "items": {"type": "string"}},
    },
}

SEMANTIC_UNKNOWN_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["unknown_id", "subject_uid", "kind", "reason", "evidence_refs"],
    "properties": {
        "unknown_id": {"type": "string"},
        "subject_uid": {"type": "string"},
        "kind": {"type": "string"},
        "reason": {"type": "string"},
        "evidence_refs": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string"},
        },
    },
}

SEMANTIC_CLAIM_DELTA_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "schema_version",
        "unit_id",
        "unit_fingerprint",
        "claims",
        "unknowns",
        "unresolved_facts",
    ],
    "properties": {
        "schema_version": {"const": SEMANTIC_CLAIM_DELTA_SCHEMA_VERSION},
        "unit_id": {"type": "string"},
        "unit_fingerprint": {"type": "string"},
        "claims": {
            "type": "array",
            "items": SEMANTIC_CLAIM_JSON_SCHEMA,
        },
        "unknowns": {
            "type": "array",
            "items": SEMANTIC_UNKNOWN_JSON_SCHEMA,
        },
        "unresolved_facts": {"type": "array", "items": {"type": "string"}},
    },
}


class SecurityMapStore(ABC):
    @abstractmethod
    def save_map(self, semantic_map: SecuritySemanticMap) -> None:
        raise NotImplementedError

    @abstractmethod
    def load_map(self, project_id: str, revision: str) -> Optional[SecuritySemanticMap]:
        raise NotImplementedError

    @abstractmethod
    def save_discovery_report(self, report: DiscoveryReport) -> None:
        raise NotImplementedError

    def save_semantic_delta(self, cache_key: str, delta: SemanticClaimDelta) -> None:
        raise NotImplementedError

    def load_semantic_delta(self, cache_key: str) -> Optional[SemanticClaimDelta]:
        return None

    @abstractmethod
    def export_json(
        self,
        semantic_map: SecuritySemanticMap,
        output_path: Path,
        reports: Sequence[DiscoveryReport] = (),
    ) -> Path:
        raise NotImplementedError


class SQLiteSecurityMapStore(SecurityMapStore):
    """SQLite sidecar for maps and discovery reports with deterministic JSON export."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _initialize(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_maps (
                        project_id TEXT NOT NULL,
                        revision TEXT NOT NULL,
                        map_fingerprint TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY(project_id, revision)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS discovery_reports (
                        unit_id TEXT NOT NULL,
                        unit_fingerprint TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY(unit_id, unit_fingerprint)
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS semantic_claim_deltas (
                        cache_key TEXT NOT NULL PRIMARY KEY,
                        unit_id TEXT NOT NULL,
                        unit_fingerprint TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def save_map(self, semantic_map: SecuritySemanticMap) -> None:
        payload = json.dumps(semantic_map.to_dict(), ensure_ascii=False, sort_keys=True)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO security_maps(
                        project_id, revision, map_fingerprint, payload_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        semantic_map.project_id,
                        semantic_map.revision,
                        semantic_map.map_fingerprint,
                        payload,
                        _utc_now(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def load_map(self, project_id: str, revision: str) -> Optional[SecuritySemanticMap]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT payload_json FROM security_maps WHERE project_id = ? AND revision = ?",
                    (str(project_id), str(revision)),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        return SecuritySemanticMap.from_dict(json.loads(str(row[0])))

    def load_latest_map(
        self,
        *,
        project_id: str = "",
        revision: str = "",
    ) -> Optional[SecuritySemanticMap]:
        clauses: List[str] = []
        values: List[str] = []
        if project_id:
            clauses.append("project_id = ?")
            values.append(str(project_id))
        if revision:
            clauses.append("revision = ?")
            values.append(str(revision))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT payload_json FROM security_maps"
                    + where
                    + " ORDER BY updated_at DESC LIMIT 1",
                    tuple(values),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        return SecuritySemanticMap.from_dict(json.loads(str(row[0])))

    def save_discovery_report(self, report: DiscoveryReport) -> None:
        payload = json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO discovery_reports(
                        unit_id, unit_fingerprint, payload_json, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (report.unit_id, report.unit_fingerprint, payload, _utc_now()),
                )
                conn.commit()
            finally:
                conn.close()

    def load_discovery_report(
        self, unit_id: str, unit_fingerprint: str
    ) -> Optional[DiscoveryReport]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT payload_json FROM discovery_reports
                    WHERE unit_id = ? AND unit_fingerprint = ?
                    """,
                    (str(unit_id), str(unit_fingerprint)),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        return DiscoveryReport.from_dict(json.loads(str(row[0])))

    def save_semantic_delta(self, cache_key: str, delta: SemanticClaimDelta) -> None:
        payload = json.dumps(delta.to_dict(), ensure_ascii=False, sort_keys=True)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO semantic_claim_deltas(
                        cache_key, unit_id, unit_fingerprint, payload_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(cache_key),
                        delta.unit_id,
                        delta.unit_fingerprint,
                        payload,
                        _utc_now(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def load_semantic_delta(self, cache_key: str) -> Optional[SemanticClaimDelta]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT payload_json FROM semantic_claim_deltas WHERE cache_key = ?",
                    (str(cache_key),),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        return SemanticClaimDelta.from_dict(json.loads(str(row[0])))

    def export_json(
        self,
        semantic_map: SecuritySemanticMap,
        output_path: Path,
        reports: Sequence[DiscoveryReport] = (),
    ) -> Path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = semantic_map.to_dict()
        payload["discovery_reports"] = [report.to_dict() for report in reports]
        temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
        temp_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temp_path.replace(output_path)
        return output_path


class ZeroLLMSecurityMapBuilder:
    """Build a bounded evidence skeleton without invoking an LLM."""

    def __init__(
        self,
        code_index: Any,
        *,
        project_id: str,
        revision: str,
        profile: str,
        semantic_overlay: Optional[Mapping[str, Any]] = None,
        project_root: Optional[Path] = None,
        max_functions: int = 5000,
        callee_limit: int = 1000,
    ) -> None:
        self.code_index = code_index
        self.project_id = str(project_id or "project")
        self.revision = str(revision or "")
        self.profile = str(profile or "fast")
        self.semantic_overlay = dict(semantic_overlay or {})
        self.project_root = Path(project_root).resolve() if project_root else None
        self.max_functions = max(1, int(max_functions))
        self.callee_limit = max(1, int(callee_limit))
        semantics = LocalPatternSemantics()
        semantics.merge_overlay(self.semantic_overlay)
        self._contracts = semantics.contracts
        self._contract_names = {c.symbol.name for c in self._contracts.contracts}
        self._contract_event_values: Dict[str, CallSemanticMatch] = {}

    def build(self, entries: Sequence[FunctionEntry]) -> SecuritySemanticMap:
        mutable: Dict[str, Dict[str, Any]] = {}
        claims: Dict[str, SemanticClaim] = {}
        unknowns: Dict[str, SemanticUnknown] = {}
        pending: List[Tuple[str, str, str, Tuple[str, ...], Dict[str, Any], str]] = []
        entry_exposures = {entry.identity_key(self.project_root): entry.exposure for entry in entries}
        for entry in sorted(entries, key=lambda item: item.identity_key(self.project_root)):
            identity = entry.identity_key(self.project_root)
            pending.append(
                (
                    entry.lookup_query(),
                    str(entry.file_path or ""),
                    identity,
                    (entry.function_name,),
                    dict(entry.diff_focus or {}),
                    "call_path",
                )
            )
        seen_routes: set[Tuple[str, str, str, str]] = set()
        truncated = False

        while pending:
            query, file_hint, entry_identity, path, diff_focus, reachability = pending.pop(0)
            route_key = (entry_identity, query, file_hint, reachability)
            expand_route = route_key not in seen_routes
            seen_routes.add(route_key)
            impl = self._get_impl(query, file_hint)
            if not impl:
                unknown = self._unknown(
                    subject_uid=path[-1] if path else query,
                    kind="unresolved_function",
                    reason=f"No implementation resolved for {query}",
                    evidence_refs=(f"entry:{entry_identity}",),
                )
                unknowns.setdefault(unknown.unknown_id, unknown)
                continue

            function_name = str(
                impl.get("func_name")
                or impl.get("qualified_name")
                or impl.get("function_name")
                or impl.get("name")
                or query
            )
            file_path = str(impl.get("file") or impl.get("file_path") or file_hint or "")
            start_line = int(impl.get("start_line") or 0)
            end_line = int(impl.get("end_line") or start_line or 0)
            signature = str(impl.get("signature") or "")
            index_name = str(
                impl.get("index_name")
                or impl.get("qualified_name")
                or f"{function_name}@{file_path}:{start_line}-{end_line}"
            )
            code = str(impl.get("code") or "")
            program_facts = self._program_facts(function_name, file_path, code)
            scope = str(program_facts.get("build_context_id") or "")
            function_identity = {"project": self.project_id, "index": index_name}
            if scope:
                function_identity["build_context_id"] = scope
            function_uid = f"FUNC_{_digest(function_identity)}"
            if function_uid not in mutable and len(mutable) >= self.max_functions:
                truncated = True
                unknown = self._unknown(
                    subject_uid=function_uid,
                    kind="function_budget_deferred",
                    reason="Function traversal budget exhausted",
                    evidence_refs=(f"entry:{entry_identity}",),
                )
                unknowns.setdefault(unknown.unknown_id, unknown)
                continue
            events = self._events(
                function_uid, function_name, file_path, start_line, code, program_facts
            )
            callees = self._get_callees(index_name, function_name)
            callee_names = tuple(
                self._callee_name(item) for item in callees if self._callee_name(item)
            )
            existing = mutable.get(function_uid)
            if existing is None:
                existing = {
                    "function_uid": function_uid,
                    "index_name": index_name,
                    "function_name": function_name,
                    "file_path": file_path,
                    "start_line": start_line,
                    "end_line": end_line,
                    "signature": signature,
                    "code_hash": hashlib.sha256(code.encode("utf-8")).hexdigest(),
                    "entry_identities": set(),
                    "entry_paths": set(),
                    "entry_occurrences": set(),
                    "callees": set(callee_names),
                    "unresolved_callees": set(),
                    "events": {event.event_id: event for event in events},
                    "backend_coverage": {
                        **self._backend_coverage(impl, callees, file_path=file_path),
                        "build_context_id": scope,
                        "program_facts_complete": bool(program_facts.get("complete")),
                        "program_facts_status": str(
                            program_facts.get("reason") or ("current" if scope else "unknown")
                        ),
                    },
                    "diff_focus": dict(diff_focus),
                }
                mutable[function_uid] = existing
            existing["entry_identities"].add(entry_identity)
            existing["entry_paths"].add(tuple(path))
            existing["entry_occurrences"].add(
                AuditOccurrence(
                    entry_identity,
                    tuple(path),
                    tuple(sorted(event.event_id for event in events)),
                    reachability,
                )
            )
            existing["callees"].update(callee_names)
            if diff_focus and not existing["diff_focus"]:
                existing["diff_focus"] = dict(diff_focus)

            if len(path) == 1:
                self._entry_claims(
                    claims,
                    function_uid=function_uid,
                    function_name=function_name,
                    file_path=file_path,
                    line=start_line,
                    entry_identity=entry_identity,
                    impl=impl,
                    entry_exposure=entry_exposures.get(entry_identity),
                )
            self._event_claims(claims, events)
            self._framework_claims(claims, function_uid, function_name, impl)

            if _INDIRECT_CALL_RE.search(code):
                unknown = self._unknown(
                    subject_uid=function_uid,
                    kind="indirect_call_target",
                    reason="Indirect call target requires backend or runtime resolution",
                    evidence_refs=(f"source:{file_path}:{start_line}",),
                )
                unknowns.setdefault(unknown.unknown_id, unknown)

            for event in events:
                if event.family in FINE_COVERAGE_FAMILIES and event.object_ref is None:
                    unknown = self._unknown(
                        subject_uid=function_uid,
                        kind="object_alias_unknown",
                        reason="Operation site has no unambiguous lexical object binding",
                        evidence_refs=(event.evidence_ref,),
                    )
                    unknowns.setdefault(unknown.unknown_id, unknown)
                if event.callback_target:
                    unknown = self._unknown(
                        subject_uid=function_uid,
                        kind="callback_dispatch_unproven",
                        reason="Registration supplies a reachability hint, not proof of invocation",
                        evidence_refs=(event.evidence_ref,),
                    )
                    unknowns.setdefault(unknown.unknown_id, unknown)
                    if expand_route and event.callback_target not in path:
                        pending.append(
                            (
                                event.callback_target,
                                file_path,
                                entry_identity,
                                (*path, event.callback_target),
                                diff_focus,
                                "callback_registration",
                            )
                        )

            if len(callees) >= self.callee_limit:
                truncated = True
                unknown = self._unknown(
                    subject_uid=function_uid,
                    kind="callee_budget_partial",
                    reason="Callee page reaches configured limit; remaining targets unknown",
                    evidence_refs=(f"source:{file_path}:{start_line}",),
                )
                unknowns.setdefault(unknown.unknown_id, unknown)

            for callee in callees:
                if not expand_route:
                    break
                name = self._callee_name(callee)
                if not name or name in path:
                    continue
                callee_file = (
                    str(callee.get("file") or callee.get("file_path") or "")
                    if isinstance(callee, Mapping)
                    else ""
                )
                pending.append(
                    (name, callee_file, entry_identity, (*path, name), diff_focus, reachability)
                )

        records = tuple(
            FunctionSecurityRecord(
                function_uid=str(item["function_uid"]),
                index_name=str(item["index_name"]),
                function_name=str(item["function_name"]),
                file_path=str(item["file_path"]),
                start_line=int(item["start_line"]),
                end_line=int(item["end_line"]),
                signature=str(item["signature"]),
                code_hash=str(item["code_hash"]),
                entry_identities=tuple(sorted(item["entry_identities"])),
                entry_paths=tuple(sorted(item["entry_paths"])),
                callees=tuple(sorted(item["callees"])),
                unresolved_callees=tuple(sorted(item["unresolved_callees"])),
                events=tuple(sorted(item["events"].values(), key=lambda event: event.event_id)),
                backend_coverage=dict(item["backend_coverage"]),
                diff_focus=dict(item["diff_focus"]),
                entry_occurrences=tuple(
                    sorted(
                        item["entry_occurrences"],
                        key=lambda value: (
                            value.entry_identity,
                            value.entry_path,
                            value.reachability,
                            value.event_refs,
                        ),
                    )
                ),
            )
            for item in sorted(mutable.values(), key=lambda row: str(row["function_uid"]))
        )
        self._overlay_claims(claims, records)
        records = self._attach_dependency_fingerprints(records, tuple(claims.values()))
        backend_name = str(getattr(self.code_index, "backend_name", "") or "unknown")
        return SecuritySemanticMap(
            project_id=self.project_id,
            revision=self.revision,
            profile=self.profile,
            functions=records,
            claims=tuple(sorted(claims.values(), key=lambda item: item.claim_id)),
            unknowns=tuple(sorted(unknowns.values(), key=lambda item: item.unknown_id)),
            audit_units=(),
            coverage={
                "entry_count": len(entries),
                "reachable_function_count": len(records),
                "claim_count": len(claims),
                "unknown_count": len(unknowns),
                "truncated": truncated,
                "llm_calls": 0,
            },
            fingerprints={
                "backend": backend_name,
                "builder": "zero_llm_security_map_v5",
                "semantic_overlay": _digest(self.semantic_overlay, length=64),
                "contract_version": self._contracts.version,
            },
        )

    @staticmethod
    def _attach_dependency_fingerprints(
        records: Sequence[FunctionSecurityRecord],
        claims: Sequence[SemanticClaim],
    ) -> Tuple[FunctionSecurityRecord, ...]:
        """Annotate records with SCC-atomic, reverse-dependency fingerprints.

        The identity deliberately excludes the deterministic rule catalog.  A
        local code/contract change invalidates its whole SCC and then only the
        callers that consume that SCC; unrelated components keep their cache
        identity.  This gives the semantic-delta cache precise invalidation
        without coupling the read-only map to rule revisions.
        """

        if not records:
            return ()

        by_uid = {record.function_uid: record for record in records}
        aliases: Dict[str, set[str]] = {}

        def alias(value: Any) -> str:
            return re.sub(r"\s+", "", str(value or "")).lower()

        for record in records:
            for value in (
                record.function_uid,
                record.function_name,
                record.index_name,
                record.index_name.split("@", 1)[0],
            ):
                key = alias(value)
                if key:
                    aliases.setdefault(key, set()).add(record.function_uid)

        edges: Dict[str, set[str]] = {uid: set() for uid in by_uid}
        for record in records:
            for callee in record.callees:
                candidates = aliases.get(alias(callee), set())
                if len(candidates) == 1:
                    edges[record.function_uid].update(candidates)

        index = 0
        indices: Dict[str, int] = {}
        lowlinks: Dict[str, int] = {}
        stack: List[str] = []
        on_stack: set[str] = set()
        components: List[Tuple[str, ...]] = []

        def visit(uid: str) -> None:
            nonlocal index
            indices[uid] = index
            lowlinks[uid] = index
            index += 1
            stack.append(uid)
            on_stack.add(uid)
            for target in sorted(edges[uid]):
                if target not in indices:
                    visit(target)
                    lowlinks[uid] = min(lowlinks[uid], lowlinks[target])
                elif target in on_stack:
                    lowlinks[uid] = min(lowlinks[uid], indices[target])
            if lowlinks[uid] != indices[uid]:
                return
            members: List[str] = []
            while stack:
                member = stack.pop()
                on_stack.remove(member)
                members.append(member)
                if member == uid:
                    break
            components.append(tuple(sorted(members)))

        for uid in sorted(by_uid):
            if uid not in indices:
                visit(uid)

        component_for: Dict[str, int] = {}
        for component_index, members in enumerate(components):
            for uid in members:
                component_for[uid] = component_index

        claims_by_subject: Dict[str, List[SemanticClaim]] = {}
        for claim in claims:
            claims_by_subject.setdefault(claim.subject_uid, []).append(claim)

        local_fingerprints: Dict[int, str] = {}
        component_edges: Dict[int, set[int]] = {
            component_index: set() for component_index in range(len(components))
        }
        component_ids: Dict[int, str] = {}
        for component_index, members in enumerate(components):
            component_ids[component_index] = "SCC_" + _digest(members)
            local_fingerprints[component_index] = hashlib.sha256(
                _stable_json(
                    {
                        "members": [
                            {
                                "uid": uid,
                                "code_hash": by_uid[uid].code_hash,
                                "signature": by_uid[uid].signature,
                                "callees": sorted(by_uid[uid].callees),
                                "claims": [
                                    {
                                        "kind": claim.kind,
                                        "value": claim.value,
                                        "origin": claim.origin,
                                        "status": claim.status,
                                    }
                                    for claim in sorted(
                                        claims_by_subject.get(uid, ()),
                                        key=lambda item: item.claim_id,
                                    )
                                ],
                            }
                            for uid in members
                        ]
                    }
                ).encode("utf-8")
            ).hexdigest()
            for uid in members:
                for target in edges[uid]:
                    target_component = component_for[target]
                    if target_component != component_index:
                        component_edges[component_index].add(target_component)

        dependency_fingerprints: Dict[int, str] = {}

        def dependency_fingerprint(component_index: int) -> str:
            cached = dependency_fingerprints.get(component_index)
            if cached is not None:
                return cached
            value = hashlib.sha256(
                _stable_json(
                    {
                        "local": local_fingerprints[component_index],
                        "callees": [
                            dependency_fingerprint(target)
                            for target in sorted(component_edges[component_index])
                        ],
                    }
                ).encode("utf-8")
            ).hexdigest()
            dependency_fingerprints[component_index] = value
            return value

        annotated: List[FunctionSecurityRecord] = []
        for record in records:
            component_index = component_for[record.function_uid]
            coverage = dict(record.backend_coverage)
            coverage.update(
                {
                    "scc_id": component_ids[component_index],
                    "scc_size": len(components[component_index]),
                    "semantic_contract_fingerprint": local_fingerprints[component_index],
                    "dependency_fingerprint": dependency_fingerprint(component_index),
                }
            )
            annotated.append(replace(record, backend_coverage=coverage))
        return tuple(annotated)

    def _get_impl(self, query: str, file_hint: str) -> Optional[Dict[str, Any]]:
        try:
            value = self.code_index.get_function_impl(
                query,
                max_lines=None,
                warn_missing=False,
                include_context=False,
                file_path=file_hint,
            )
        except TypeError:
            try:
                value = self.code_index.get_function_impl(
                    query, max_lines=None, warn_missing=False, file_path=file_hint
                )
            except TypeError:
                value = self.code_index.get_function_impl(query)
        except Exception:
            return None
        return dict(value) if isinstance(value, Mapping) else None

    def _get_callees(self, index_name: str, function_name: str) -> List[Any]:
        try:
            values = self.code_index.get_callees(index_name, limit=self.callee_limit)
            if not values and index_name != function_name:
                values = self.code_index.get_callees(function_name, limit=self.callee_limit)
        except TypeError:
            try:
                values = self.code_index.get_callees(function_name)
            except Exception:
                return []
        except Exception:
            return []
        return list(values or [])[: self.callee_limit]

    @staticmethod
    def _callee_name(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if not isinstance(value, Mapping):
            return ""
        return str(
            value.get("name")
            or value.get("func_name")
            or value.get("function")
            or value.get("callee")
            or value.get("qualified_name")
            or ""
        ).strip()

    @staticmethod
    def _source_line(raw: str, offset: int, start_line: int) -> Tuple[int, str]:
        match = _LINE_PREFIX_RE.match(raw)
        if match:
            return int(match.group(1)), match.group(2)
        return max(1, start_line + offset), raw

    def _program_facts(self, function_name: str, file_path: str, code: str) -> Dict[str, Any]:
        from ..common.cancellation import CancellationError
        from .build_scope import source_scope_problem

        getter = getattr(self.code_index, "get_function_program_facts", None)
        if not callable(getter):
            return {}
        try:
            facts = getter(function_name, file_path)
        except CancellationError:
            raise
        except Exception as exc:
            return {"reason": "program_facts_unavailable:" + type(exc).__name__}
        if not isinstance(facts, dict):
            return {"reason": "invalid_program_facts"}
        problem = source_scope_problem({"code": code, "program_facts": facts})
        if problem or not facts.get("complete"):
            return {"reason": problem or "incomplete_program_facts"}
        return facts

    def _events(
        self,
        function_uid: str,
        function_name: str,
        file_path: str,
        start_line: int,
        code: str,
        program_facts: Mapping[str, Any],
    ) -> Tuple[SecurityEvent, ...]:
        result: Dict[str, SecurityEvent] = {}
        # Program-facts expressions (macro-expanded by the batch indexer) are
        # scanned alongside the raw source so wrapper macros such as LOCK()
        # still yield events; each fact line carries its true line number.
        scanned: List[str] = list(code.splitlines())
        for body in program_facts.get("functions") or []:
            for ev in body.get("events") or []:
                loc = ev.get("location") or {}
                ln = int(loc.get("line") or ev.get("line") or 0)
                expr = str(ev.get("expression") or "").strip()
                if ln and expr:
                    scanned.append(f"{ln} | {expr}")
        from .call_context import bind_call_context

        with bind_call_context(
            {
                "func_name": function_name,
                "file_path": file_path,
                "code": code,
                "program_facts": program_facts,
            },
            self._contracts,
        ):
            for offset, raw_line in enumerate(scanned):
                line, expression = self._source_line(raw_line, offset, start_line)
                operations = list(self._contract_calls(expression))
                lexical = self._lexical_coverage_sites(expression)
                operation_families = {
                    _CONTRACT_EVENT_KINDS[operation.role][0] for _, operation in operations
                }
                for family, kind, pattern in _EVENT_PATTERNS:
                    if not pattern.search(expression):
                        continue
                    if family in FINE_COVERAGE_FAMILIES and family in operation_families:
                        continue
                    sites = [item for item in lexical if item[1] == family]
                    if sites:
                        for ordinal, _, obj in sites:
                            evidence_ref = f"source:{file_path}:{line}"
                            event_id = f"EVT_{_digest((function_uid, family, line, ordinal, expression.strip()))}"
                            result.setdefault(
                                event_id,
                                SecurityEvent(
                                    event_id,
                                    family,
                                    kind,
                                    function_uid,
                                    file_path,
                                    line,
                                    expression.strip()[:400],
                                    evidence_ref,
                                    obj,
                                    f"{file_path}:{line}:token-{ordinal}",
                                    None,
                                    (
                                        self._callback_target(expression, ordinal)
                                        if family == "callback_concurrency"
                                        else None
                                    ),
                                ),
                            )
                        continue
                    evidence_ref = f"source:{file_path}:{line}"
                    event_id = (
                        f"EVT_{_digest((function_uid, family, kind, line, expression.strip()))}"
                    )
                    result.setdefault(
                        event_id,
                        SecurityEvent(
                            event_id=event_id,
                            family=family,
                            kind=kind,
                            function_uid=function_uid,
                            file=file_path,
                            line=line,
                            expression=expression.strip()[:400],
                            evidence_ref=evidence_ref,
                            operation_site=f"{file_path}:{line}:{family}",
                            callback_target=(
                                self._callback_target(expression)
                                if family == "callback_concurrency"
                                else None
                            ),
                        ),
                    )
                for ordinal, operation in operations:
                    family, kind = _CONTRACT_EVENT_KINDS[operation.role]
                    evidence_ref = f"source:{file_path}:{line}"
                    event_id = f"EVT_{_digest((function_uid, line, expression.strip(), ordinal, operation.to_dict()))}"
                    self._contract_event_values[event_id] = operation
                    result.setdefault(
                        event_id,
                        SecurityEvent(
                            event_id=event_id,
                            family=family,
                            kind=kind,
                            function_uid=function_uid,
                            file=file_path,
                            line=line,
                            expression=expression.strip()[:400],
                            evidence_ref=evidence_ref,
                            object_ref=next(
                                (
                                    obj
                                    for pos, fam, obj in lexical
                                    if pos == ordinal and fam == family
                                ),
                                self._coverage_object(operation),
                            ),
                            operation_site=f"{file_path}:{line}:token-{ordinal}",
                            callback_target=(
                                self._callback_target(expression, ordinal)
                                if family == "callback_concurrency"
                                else None
                            ),
                        ),
                    )
        return tuple(result.values())

    @staticmethod
    def _lexical_coverage_sites(expression: str) -> List[Tuple[int, str, Optional[str]]]:
        """Bind explicit standard call syntax without asserting its effects."""
        from .contract_compiler import closing, split_tokens

        allocators = {"malloc", "calloc", "realloc", "strdup", "open", "fopen", "socket", "mmap"}
        releasers = {"free", "close", "fclose", "munmap"}
        callback_calls = {
            "register_callback",
            "pthread_create",
            "pthread_mutex_lock",
            "pthread_mutex_unlock",
        }
        tokens = code_tokens(expression)
        result = []
        for position, name in enumerate(tokens):
            if name not in allocators | releasers | callback_calls or tokens[
                position + 1 : position + 2
            ] != ["("]:
                continue
            end = closing(tokens, position + 1)
            if end >= len(tokens) or tokens[end] != ")" or tokens[end + 1 : end + 2] == ["{"]:
                continue
            args = ["".join(item) for item in split_tokens(tokens[position + 2 : end])]
            obj = ""
            if name in allocators and position >= 2 and tokens[position - 1] == "=":
                prefix = tokens[: position - 1]
                for separator in (";", "{", "}"):
                    if separator in prefix:
                        prefix = prefix[len(prefix) - prefix[::-1].index(separator) :]
                if (
                    prefix
                    and prefix[0] != "*"
                    and all(re.fullmatch(r"[A-Za-z_]\w*|\*", part) for part in prefix)
                ):
                    obj = prefix[-1]
            elif name in releasers | callback_calls and args:
                obj = args[0].removeprefix("&")
            # Member access/array expressions can alias: first release uses
            # operation-site identity, never a guessed object equivalence.
            if not re.fullmatch(r"[A-Za-z_]\w*", obj):
                obj = ""
            result.append(
                (
                    position,
                    "callback_concurrency" if name in callback_calls else "resource_lifecycle",
                    obj or None,
                )
            )
        return result

    @staticmethod
    def _coverage_object(operation: CallSemanticMatch) -> Optional[str]:
        # A lexical variable/member is a scheduling hint, not alias proof.
        # Complex dereferences/calls and untrusted contract bindings stay at site granularity.
        if not operation.effects_trusted:
            return None
        value = operation.object.removeprefix("&")
        if not re.fullmatch(r"[A-Za-z_]\w*(?:(?:\.|->)[A-Za-z_]\w*)*", value):
            return None
        if operation.resource_domain:
            if not re.fullmatch(r"[A-Za-z_]\w*", operation.resource_domain):
                return None
            value = operation.resource_domain + "::" + value
        return value

    def _callback_target(self, expression: str, ordinal: Optional[int] = None) -> Optional[str]:
        from .contract_compiler import closing, split_tokens

        tokens = code_tokens(expression)
        arguments: Optional[List[str]]
        for name, position in (("pthread_create", 2), ("register_callback", 0)):
            if ordinal is not None:
                if tokens[ordinal] != name:
                    continue
                end = closing(tokens, ordinal + 1)
                arguments = ["".join(item) for item in split_tokens(tokens[ordinal + 2 : end])]
            else:
                arguments = self._contracts.call_arguments(name, expression)
            if arguments is not None and len(arguments) > position:
                target = arguments[position].strip().removeprefix("&")
                if re.fullmatch(r"[A-Za-z_]\w*", target):
                    return target
        return None

    def _contract_calls(self, expression: str) -> Iterable[Tuple[int, CallSemanticMatch]]:
        """Resolve all explicit calls; prose and summary names cannot assign a role.

        These observations do not prove reachability. The map supplies evidence
        to discovery; path-sensitive lifecycle reasoning stays in the engines.
        """
        from .contract_compiler import closing, split_tokens

        tokens = code_tokens(expression)
        for offset, name in enumerate(tokens):
            if name not in self._contract_names:
                continue
            if offset and tokens[offset - 1] in {".", "->", "::"}:
                continue
            arguments: List[str] = []
            if tokens[offset + 1 : offset + 2] == ["("]:
                end = closing(tokens, offset + 1)
                if tokens[end] != ")":
                    continue
                # A source declaration is not an invocation.
                if tokens[end + 1 : end + 2] == ["{"]:
                    continue
                arguments = ["".join(p) for p in split_tokens(tokens[offset + 2 : end]) if p]
            elif not any(c.symbol.symbol_type == "macro" for c in self._contracts.find(name)):
                continue
            returned = ""
            if offset >= 2 and tokens[offset - 1] == "=":
                prefix = tokens[: offset - 1]
                for separator in (";", "{", "}"):
                    if separator in prefix:
                        prefix = prefix[len(prefix) - prefix[::-1].index(separator) :]
                if (
                    prefix
                    and prefix[0] != "*"
                    and all(re.fullmatch(r"[A-Za-z_]\w*|\*", t) for t in prefix)
                    and re.fullmatch(r"[A-Za-z_]\w*", prefix[-1])
                ):
                    returned = prefix[-1]
            for operation in self._contracts.match_call(name, "", arguments, returned):
                yield offset, operation

    def _entry_claims(
        self,
        claims: Dict[str, SemanticClaim],
        *,
        function_uid: str,
        function_name: str,
        file_path: str,
        line: int,
        entry_identity: str,
        impl: Mapping[str, Any],
        entry_exposure: Optional[str] = None,
    ) -> None:
        framework = impl.get("framework_semantics") or impl.get("framework_runtime_ir") or {}
        explicit_exposure = set(str(entry_exposure or "").lower().split("+"))
        has_external = bool(
            explicit_exposure & {"api", "communication", "other_user_input"}
            or impl.get("entry_exposure")
            or impl.get("exposure")
            or (isinstance(framework, Mapping) and framework.get("has_external_input"))
        )
        for kind, value in (
            ("input_origin", {"origin": "external" if has_external else "entry_unknown"}),
            (
                "trust_boundary",
                {"entry_identity": entry_identity, "externally_exposed": has_external},
            ),
        ):
            evidence_ref = f"entry:{entry_identity}"
            claim_id = f"CLAIM_{_digest((function_uid, kind, value, evidence_ref))}"
            claims.setdefault(
                claim_id,
                SemanticClaim(
                    claim_id=claim_id,
                    subject_uid=function_uid,
                    kind=kind,
                    value=value,
                    locations=(
                        {
                            "file": file_path,
                            "line": line,
                            "function": function_name,
                        },
                    ),
                    evidence_refs=(evidence_ref,),
                    origin="program",
                    confidence=1.0 if has_external else 0.6,
                    status="known" if has_external else "unknown",
                ),
            )

    def _event_claims(
        self, claims: Dict[str, SemanticClaim], events: Sequence[SecurityEvent]
    ) -> None:
        claim_kind_by_family = {
            "resource_lifecycle": "resource_transition",
            "memory_bounds": "bounds_contract",
            "callback_concurrency": "callback_lifetime",
            "state_protocol": "state_transition",
            "auth_boundary": "authorization_guard",
            "sensitive_sink": "sensitive_sink",
            "input_boundary": "input_origin",
        }
        for event in events:
            kind = claim_kind_by_family[event.family]
            value: Dict[str, Any] = {"event_kind": event.kind, "expression": event.expression}
            origin, confidence, status = "program", 0.9, "known"
            operation = self._contract_event_values.get(event.event_id)
            if operation is not None:
                kind = _CONTRACT_EVENT_KINDS[operation.role][1]
                value["call_semantics"] = operation.to_dict()
                value["observation"] = "call_site; reachability requires separate evidence"
                origin = self._contract_origin(operation.source, operation.effects_trusted)
                status = (
                    "known"
                    if operation.effects_trusted
                    and operation.applicability != "unknown"
                    and operation.object
                    else "unknown"
                )
                confidence = 0.9 if status == "known" else 0.5
            claim_id = f"CLAIM_{_digest((event.function_uid, kind, value, event.evidence_ref))}"
            claims.setdefault(
                claim_id,
                SemanticClaim(
                    claim_id=claim_id,
                    subject_uid=event.function_uid,
                    kind=kind,
                    value=value,
                    locations=(
                        {
                            "file": event.file,
                            "line": event.line,
                        },
                    ),
                    evidence_refs=(event.evidence_ref,),
                    origin=origin,
                    confidence=confidence,
                    status=status,
                ),
            )

    @staticmethod
    def _framework_claims(
        claims: Dict[str, SemanticClaim],
        function_uid: str,
        function_name: str,
        impl: Mapping[str, Any],
    ) -> None:
        framework = impl.get("framework_semantics") or impl.get("framework_runtime_ir")
        if not isinstance(framework, Mapping):
            return
        for collection, claim_kind in (
            ("sources", "input_origin"),
            ("guards", "authorization_guard"),
            ("sinks", "sensitive_sink"),
        ):
            rows = framework.get(collection) or []
            if not isinstance(rows, list):
                continue
            for index, raw in enumerate(rows[:64]):
                value = dict(raw) if isinstance(raw, Mapping) else {"value": str(raw)}
                evidence_ref = f"framework:{function_name}:{collection}:{index}"
                claim_id = f"CLAIM_{_digest((function_uid, claim_kind, value, evidence_ref))}"
                claims.setdefault(
                    claim_id,
                    SemanticClaim(
                        claim_id=claim_id,
                        subject_uid=function_uid,
                        kind=claim_kind,
                        value=value,
                        locations=(),
                        evidence_refs=(evidence_ref,),
                        origin="program",
                        confidence=0.9,
                        status="known",
                    ),
                )

    def _overlay_claims(
        self,
        claims: Dict[str, SemanticClaim],
        functions: Sequence[FunctionSecurityRecord],
    ) -> None:
        for contract in self._contracts.contracts:
            records = [
                record
                for record in functions
                if record.function_name == contract.symbol.name
                and (not contract.symbol.file_path or contract.symbol.file_path == record.file_path)
                and (not contract.symbol.signature or contract.symbol.signature == record.signature)
                and (not contract.symbol.build_context_id or contract.symbol.build_context_id == record.backend_coverage.get("build_context_id"))
            ]
            if len(records) != 1:
                continue
            record = records[0]
            kind = _CONTRACT_EVENT_KINDS[contract.role][1]
            value = {
                "api_contract": contract.to_dict(),
                "contract_version": self._contracts.version,
            }
            evidence_ref = f"contract:{self._contracts.version}:{contract.symbol.key}"
            claim_id = f"CLAIM_{_digest((record.function_uid, kind, value, evidence_ref))}"
            claims.setdefault(
                claim_id,
                SemanticClaim(
                    claim_id=claim_id,
                    subject_uid=record.function_uid,
                    kind=kind,
                    value=value,
                    locations=(),
                    evidence_refs=(evidence_ref,),
                    origin=self._contract_origin(contract.source, contract.effects_trusted),
                    confidence=contract.confidence,
                    status="known" if contract.effects_trusted else "unknown",
                ),
            )
        by_name: Dict[str, List[FunctionSecurityRecord]] = {}
        for record in functions:
            by_name.setdefault(record.function_name, []).append(record)
        for collection, claim_kind in (
            ("resource_models", "resource_transition"),
            ("lock_models", "lock_order"),
            ("function_intent_models", "trust_boundary"),
        ):
            if collection != "function_intent_models" and "api_contracts" in self.semantic_overlay:
                continue
            rows = self.semantic_overlay.get(collection) or []
            if not isinstance(rows, list):
                continue
            for index, raw in enumerate(rows):
                if not isinstance(raw, Mapping):
                    continue
                name = str(raw.get("name") or raw.get("func_name") or "")
                records = by_name.get(name, [])
                if len(records) != 1:
                    continue
                record = records[0]
                value = dict(raw)
                inferred = str(raw.get("source") or "").startswith("inferred")
                evidence_ref = f"overlay:{collection}:{index}:{name}"
                claim_id = (
                    f"CLAIM_{_digest((record.function_uid, claim_kind, value, evidence_ref))}"
                )
                claims.setdefault(
                    claim_id,
                    SemanticClaim(
                        claim_id=claim_id,
                        subject_uid=record.function_uid,
                        kind=claim_kind,
                        value=value,
                        locations=(),
                        evidence_refs=(evidence_ref,),
                        origin="llm" if inferred else "user",
                        confidence=0.5 if inferred else 1.0,
                        status="unknown" if inferred else "known",
                    ),
                )

    @staticmethod
    def _contract_origin(source: str, trusted: bool) -> str:
        if source.startswith("inferred"):
            return "program" if trusted else "llm"
        return "program" if source == "builtin_defaults" else "user"

    @staticmethod
    def _unknown(
        *, subject_uid: str, kind: str, reason: str, evidence_refs: Tuple[str, ...]
    ) -> SemanticUnknown:
        return SemanticUnknown(
            unknown_id=f"UNKNOWN_{_digest((subject_uid, kind, reason, evidence_refs))}",
            subject_uid=subject_uid,
            kind=kind,
            reason=reason,
            evidence_refs=evidence_refs,
        )

    def _backend_coverage(
        self,
        impl: Mapping[str, Any],
        callees: Sequence[Any],
        *,
        file_path: str,
    ) -> Dict[str, Any]:
        project_relative_path = str(file_path or "").replace("\\", "/")
        if self.project_root and project_relative_path:
            try:
                candidate_path = Path(file_path)
                if not candidate_path.is_absolute():
                    candidate_path = self.project_root / candidate_path
                project_relative_path = str(
                    candidate_path.resolve().relative_to(self.project_root)
                ).replace("\\", "/")
            except (OSError, ValueError):
                pass
        return {
            "backend": str(getattr(self.code_index, "backend_name", "") or "unknown"),
            "structure_precision": str(
                impl.get("structure_precision") or impl.get("precision") or "unknown"
            ),
            "call_graph_observed": bool(callees),
            "framework_ir_observed": bool(
                impl.get("framework_semantics") or impl.get("framework_runtime_ir")
            ),
            # The planner uses the project-relative path for default
            # generated/vendor/test-only isolation.  Keeping it alongside
            # backend coverage avoids changing source locations or evidence
            # identities used elsewhere in the pipeline.
            "project_relative_path": project_relative_path,
            "is_generated": bool(impl.get("is_generated") or impl.get("generated")),
            "is_vendor": bool(
                impl.get("is_vendor") or impl.get("vendor") or impl.get("is_third_party")
            ),
            "is_test_only": bool(
                impl.get("is_test_only") or impl.get("test_only") or impl.get("is_test")
            ),
        }
