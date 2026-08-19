"""Content-addressed, per-cluster decision traces.

The trace is an audit sidecar, never a decision authority.  Product stages
append structured events while the existing Candidate Ledger, proof pipeline,
and report views remain authoritative.  This separation lets a trace failure
degrade observability without silently changing a security disposition.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, cast


DECISION_TRACE_SCHEMA_VERSION = "zscope.issue-decision-trace.v3"
DECISION_EVENT_SCHEMA_VERSION = "zscope.issue-decision-event.v3"
DECISION_TRACE_MANIFEST_VERSION = "zscope.decision-trace-manifest.v3"
COVERAGE_TRACE_SCHEMA_VERSION = "zscope.coverage-trace.v1"
EVIDENCE_OBJECT_SCHEMA_VERSION = "zscope.evidence-object.v1"
MODEL_EVENT_SCHEMA_VERSION = "zscope.model-event.v1"


DISCOVERY_REASON_CODES = frozenset(
    {
        "AUDIT_UNIT_CREATED",
        "AUDIT_UNIT_EXCLUDED_GENERATED_VENDOR_TEST",
        "AUDIT_UNIT_SUPPRESSED_LOCAL_COVERAGE",
        "BACKEND_UNAVAILABLE_OR_DEGRADED",
        "PRODUCER_NO_SIGNAL",
        "SIGNAL_REGISTRATION_REJECTED",
        "CANDIDATE_REGISTERED",
        "LEDGER_ALIAS_MERGED",
        "LEDGER_FROZEN",
    }
)
VALIDATION_REASON_CODES = frozenset(
    {
        "V0_UNRESOLVED",
        "POSITIVE_PROOF_COMPLETE",
        "NEGATIVE_PROOF_COMPLETE",
        "PROOF_CONFLICT",
        "PROOF_INVALID_SCOPE_OR_DEPENDENCY",
        "FACT_VERIFIED_TRUE",
        "FACT_VERIFIED_FALSE",
        "FACT_UNKNOWN",
        "FACT_CONFLICTING",
        "PROVIDER_NO_MATCH",
        "PROVIDER_TIMEOUT",
        "PROVIDER_ERROR",
        "V1_COMPLETED",
        "V2_COMPLETED",
        "V2_SKIPPED_NO_DELTA",
        "V3_NOT_ELIGIBLE_RISK",
        "V3_NOT_ELIGIBLE_NO_EXECUTABLE_GAP",
        "V3_ENTERED",
        "V3_STOP_NO_PROGRESS",
        "V3_STOP_NO_REMAINING_ACTION",
        "V3_STOP_MAX_ITERATIONS",
        "LLM_USAGE_BOUND",
    }
)
TERMINAL_REASON_CODES = frozenset(
    {
        "CONFIRMED_DETERMINISTIC_PROOF",
        "CONFIRMED_VERIFIED_CLOSURE",
        "REJECTED_DETERMINISTIC_COUNTERPROOF",
        "NEEDS_REVIEW_OPEN_CLAUSES",
        "NEEDS_REVIEW_EVIDENCE_CONFLICT",
        "NEEDS_REVIEW_MODEL_REJECT_NO_PROOF",
        "NEEDS_REVIEW_VERIFIED_BUT_PROMOTION_BLOCKED",
        "NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",
        "ROOT_PRIMARY",
        "ROOT_ALIAS",
        "VIEW_DEFAULT",
        "VIEW_WITH_NEEDS_REVIEW",
        "VIEW_EXCLUDED",
    }
)
DECISION_REASON_CODES = DISCOVERY_REASON_CODES | VALIDATION_REASON_CODES | TERMINAL_REASON_CODES

_SENSITIVE_KEYS = frozenset(
    {
        "apikey",
        "authorization",
        "bearertoken",
        "chainofthought",
        "password",
        "reasoningcontent",
        "secret",
        "secretkey",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def _sanitize(value: Any) -> Any:
    """Return deterministic JSON data while removing secret/reasoning bodies."""

    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for raw_key, nested in value.items():
            key = str(raw_key)
            if _normalized_key(key) in _SENSITIVE_KEYS:
                continue
            result[key] = _sanitize(nested)
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_sanitize(item) for item in value]
        return sorted(normalized, key=lambda item: _canonical_json(item))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _sanitize(to_dict())
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _sanitize(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                _sanitize(value),
                handle,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        try:
            if temporary.exists():
                temporary.unlink()
        except OSError:
            pass


def _artifact_name(identity: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(identity or "unknown")).strip("._")
    digest = hashlib.sha256(str(identity or "unknown").encode("utf-8")).hexdigest()[:12]
    prefix = normalized[:96] or "unknown"
    return f"{prefix}-{digest}.json"


def _disposition(issue: Mapping[str, Any]) -> str:
    return (
        str(
            issue.get("candidate_disposition")
            or issue.get("terminal_disposition")
            or issue.get("policy_disposition")
            or issue.get("validation_status")
            or issue.get("status")
            or "needs_review"
        )
        .strip()
        .lower()
    )


def terminal_reason_codes(issue: Mapping[str, Any]) -> tuple[str, ...]:
    """Project only the P5 TerminalAuthorityDecision v3 explanation."""

    disposition = _disposition(issue)
    authority = issue.get("terminal_authority_decision")
    authority = authority if isinstance(authority, Mapping) else {}
    valid_authority = bool(
        authority.get("schema_version") == "zscope.terminal-authority-decision.v3"
        and authority.get("terminal") is True
        and str(authority.get("disposition") or "") == disposition
        and str(authority.get("authority") or "")
        in {"zscope.proof-checker", "zscope.proof-checker-conflict-resolver"}
    )
    if disposition in {"confirmed", "validated"}:
        if not valid_authority:
            return ("NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",)
        return (str(authority.get("reason_code") or "CONFIRMED_VERIFIED_CLOSURE"),)
    if disposition in {"rejected", "rejected_with_proof"}:
        if not valid_authority:
            return ("NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",)
        return (str(authority.get("reason_code") or "REJECTED_DETERMINISTIC_COUNTERPROOF"),)
    if disposition == "deduplicated_alias":
        return ("ROOT_ALIAS", "VIEW_EXCLUDED")
    if disposition in {"engine_failed", "interrupted"}:
        return ("NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE", "VIEW_EXCLUDED")
    if disposition in {"shadow", "shadow_observation"}:
        return ("VIEW_EXCLUDED",)
    if valid_authority:
        reason = str(authority.get("reason_code") or "")
        if reason in TERMINAL_REASON_CODES:
            return (reason,)
    return ("NEEDS_REVIEW_PROTOCOL_OR_ENGINE_FAILURE",)


class DecisionTraceError(ValueError):
    """Raised when a frozen trace or content-addressed object is invalid."""


class DecisionTraceStore:
    """Thread-safe sidecar store shared by one scan configuration."""

    def __init__(
        self,
        root: Path,
        *,
        scan_uid: str = "",
        identity: Optional[Mapping[str, Any]] = None,
        usage_ledger: Any = None,
    ) -> None:
        self.root = Path(root)
        self.scan_uid = str(scan_uid or f"scan-{uuid.uuid4().hex}")
        self.identity: Dict[str, Any] = _sanitize(identity or {})
        self.usage_ledger = usage_ledger
        self._lock = threading.RLock()
        self._traces: Dict[str, Dict[str, Any]] = {}
        self._coverage: Dict[str, Dict[str, Any]] = {}
        self._trace_paths: Dict[str, str] = {}
        self._coverage_paths: Dict[str, str] = {}
        self._evidence_refs: set[str] = set()
        self._model_event_refs: set[str] = set()
        self._errors: list[str] = []

    @property
    def trace_dir(self) -> Path:
        return self.root / "decision_traces"

    @property
    def coverage_dir(self) -> Path:
        return self.root / "coverage_traces"

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence_objects"

    @property
    def model_event_dir(self) -> Path:
        return self.root / "model_events"

    @property
    def manifest_path(self) -> Path:
        return self.root / "decision_trace_manifest.json"

    def update_identity(self, values: Mapping[str, Any]) -> None:
        with self._lock:
            self.identity.update(_sanitize(values))
            for cluster_uid, trace in self._traces.items():
                trace["identity"] = deepcopy(self.identity)
                self._persist_trace(cluster_uid)

    def bind_usage_ledger(self, usage_ledger: Any) -> None:
        with self._lock:
            self.usage_ledger = usage_ledger

    def put_evidence(
        self,
        *,
        kind: str,
        payload: Any,
        producer: str,
        dependency_hashes: Sequence[str] = (),
        locations: Sequence[Mapping[str, Any]] = (),
    ) -> str:
        body = {
            "schema_version": EVIDENCE_OBJECT_SCHEMA_VERSION,
            "kind": str(kind),
            "producer": str(producer),
            "dependency_hashes": sorted({str(item) for item in dependency_hashes if str(item)}),
            "locations": [_sanitize(item) for item in locations],
            "payload": _sanitize(payload),
        }
        digest = _sha256(body)
        record = {**body, "sha256": digest}
        path = self.evidence_dir / f"{digest}.json"
        with self._lock:
            if not path.exists():
                self._write(path, record)
            self._evidence_refs.add(digest)
        return f"evidence_objects/{digest}.json"

    def put_model_event(
        self,
        *,
        call_identity: str,
        stage: str,
        validation_cluster_uid: str,
        structured_input: Any,
        structured_output: Any,
        call_ids: Sequence[str] = (),
        tool_call_ids: Sequence[str] = (),
        prompt_revision: str = "",
        prompt_hash: str = "",
    ) -> str:
        body = {
            "schema_version": MODEL_EVENT_SCHEMA_VERSION,
            "call_identity": str(call_identity),
            "stage": str(stage),
            "validation_cluster_uid": str(validation_cluster_uid),
            "structured_input": _sanitize(structured_input),
            "structured_output": _sanitize(structured_output),
            "call_ids": sorted({str(item) for item in call_ids if str(item)}),
            "tool_call_ids": sorted({str(item) for item in tool_call_ids if str(item)}),
            "prompt_revision": str(prompt_revision),
            "prompt_hash": str(prompt_hash),
        }
        digest = _sha256(body)
        path = self.model_event_dir / f"{digest}.json"
        with self._lock:
            if not path.exists():
                self._write(path, {**body, "sha256": digest})
            self._model_event_refs.add(digest)
        return f"model_events/{digest}.json"

    def append_event(
        self,
        validation_cluster_uid: str,
        *,
        stage: str,
        actor: str,
        reason_code: str,
        before_state: Optional[Mapping[str, Any]] = None,
        after_state: Optional[Mapping[str, Any]] = None,
        input_refs: Sequence[str] = (),
        output_refs: Sequence[str] = (),
        disposition_before: str = "",
        disposition_after: str = "",
        call_ids: Sequence[str] = (),
        tool_call_ids: Sequence[str] = (),
        token_delta: int = 0,
        closed_clause_ids: Sequence[str] = (),
        open_clause_ids: Sequence[str] = (),
        parent_event_uids: Sequence[str] = (),
        details: Optional[Mapping[str, Any]] = None,
        dedupe_key: str = "",
    ) -> Dict[str, Any]:
        cluster_uid = str(validation_cluster_uid or "").strip()
        if not cluster_uid:
            raise DecisionTraceError("validation_cluster_uid is required for a decision event")
        code = str(reason_code or "").strip().upper()
        if code not in DECISION_REASON_CODES:
            raise DecisionTraceError(f"unknown decision trace reason_code: {reason_code}")
        with self._lock:
            trace = self._trace(cluster_uid)
            events = cast(list[Dict[str, Any]], trace["events"])
            if dedupe_key:
                for existing in events:
                    if existing.get("dedupe_key") == dedupe_key:
                        return deepcopy(existing)
            prior = events[-1] if events else None
            sequence = len(events) + 1
            parents = [str(value) for value in parent_event_uids if str(value)]
            if not parents and prior is not None:
                parents = [str(prior["event_uid"])]
            payload: Dict[str, Any] = {
                "schema_version": DECISION_EVENT_SCHEMA_VERSION,
                "sequence": sequence,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "stage": str(stage),
                "actor": str(actor),
                "reason_code": code,
                "parent_event_uids": parents,
                "previous_event_hash": str(prior.get("event_hash") or "") if prior else "",
                "input_state_hash": _sha256(before_state or {}),
                "output_state_hash": _sha256(after_state or {}),
                "input_refs": sorted({str(item) for item in input_refs if str(item)}),
                "output_refs": sorted({str(item) for item in output_refs if str(item)}),
                "disposition_before": str(disposition_before),
                "disposition_after": str(disposition_after),
                "call_ids": sorted({str(item) for item in call_ids if str(item)}),
                "tool_call_ids": sorted({str(item) for item in tool_call_ids if str(item)}),
                "token_delta": max(0, int(token_delta or 0)),
                "closed_clause_ids": sorted({str(item) for item in closed_clause_ids if str(item)}),
                "open_clause_ids": sorted({str(item) for item in open_clause_ids if str(item)}),
                "details": _sanitize(details or {}),
                "dedupe_key": str(dedupe_key),
            }
            event_hash = _sha256(payload)
            event = {
                **payload,
                "event_uid": f"EVENT_{event_hash[:32]}",
                "event_hash": event_hash,
            }
            events.append(event)
            trace["trace_root_sha256"] = event_hash
            trace["updated_at"] = payload["recorded_at"]
            self._persist_trace(cluster_uid)
            return deepcopy(event)

    def record_coverage_event(
        self,
        audit_unit_uid: str,
        *,
        reason_code: str,
        producer: str,
        details: Optional[Mapping[str, Any]] = None,
        evidence_refs: Sequence[str] = (),
        call_ids: Sequence[str] = (),
        token_delta: int = 0,
    ) -> Dict[str, Any]:
        unit_uid = str(audit_unit_uid or "").strip()
        if not unit_uid:
            raise DecisionTraceError("audit_unit_uid is required for a coverage event")
        code = str(reason_code or "").strip().upper()
        if code not in DISCOVERY_REASON_CODES:
            raise DecisionTraceError(f"invalid coverage reason_code: {reason_code}")
        with self._lock:
            trace = self._coverage.setdefault(
                unit_uid,
                {
                    "schema_version": COVERAGE_TRACE_SCHEMA_VERSION,
                    "scan_uid": self.scan_uid,
                    "audit_unit_uid": unit_uid,
                    "events": [],
                    "trace_root_sha256": "",
                },
            )
            events = cast(list[Dict[str, Any]], trace["events"])
            prior_hash = str(events[-1].get("event_hash") or "") if events else ""
            body = {
                "sequence": len(events) + 1,
                "reason_code": code,
                "producer": str(producer),
                "previous_event_hash": prior_hash,
                "evidence_refs": sorted({str(item) for item in evidence_refs if str(item)}),
                "call_ids": sorted({str(item) for item in call_ids if str(item)}),
                "token_delta": max(0, int(token_delta or 0)),
                "details": _sanitize(details or {}),
            }
            event_hash = _sha256(body)
            event = {**body, "event_uid": f"COVERAGE_{event_hash[:32]}", "event_hash": event_hash}
            events.append(event)
            trace["trace_root_sha256"] = event_hash
            coverage_body = dict(trace)
            coverage_body.pop("document_sha256", None)
            trace["document_sha256"] = _sha256(coverage_body)
            path = self.coverage_dir / _artifact_name(unit_uid)
            self._coverage_paths[unit_uid] = path.relative_to(self.root).as_posix()
            self._write(path, trace)
            return deepcopy(event)

    def finalize_issue(
        self,
        issue: Dict[str, Any],
        *,
        view_memberships: Sequence[str],
    ) -> Dict[str, Any]:
        cluster_uid = str(issue.get("validation_cluster_uid") or "").strip()
        if not cluster_uid:
            return issue
        disposition = _disposition(issue)
        terminal_authority = issue.get("terminal_authority_decision")
        terminal_authority = terminal_authority if isinstance(terminal_authority, Mapping) else {}
        security_terminal = disposition in {
            "confirmed",
            "validated",
            "rejected",
            "rejected_with_proof",
            "needs_review",
        }
        operational = str(issue.get("record_role") or "") == "operational_obligation"
        if security_terminal and not operational:
            if not (
                terminal_authority.get("schema_version") == "zscope.terminal-authority-decision.v3"
                and terminal_authority.get("terminal") is True
                and str(terminal_authority.get("disposition") or "")
                in {disposition, "confirmed" if disposition == "validated" else disposition}
                and str(terminal_authority.get("authority") or "")
                in {"zscope.proof-checker", "zscope.proof-checker-conflict-resolver"}
            ):
                raise DecisionTraceError(
                    "security terminal requires TerminalAuthorityDecision v3 from Proof Engine"
                )
        explicit_reasons = issue.get("terminal_reason_codes")
        reasons = (
            tuple(str(value) for value in explicit_reasons if str(value) in TERMINAL_REASON_CODES)
            if isinstance(explicit_reasons, list) and _disposition(issue) != "deduplicated_alias"
            else ()
        ) or terminal_reason_codes(issue)
        terminal_reason = next(
            (value for value in reasons if value not in {"ROOT_ALIAS", "VIEW_EXCLUDED"}),
            reasons[0],
        )
        security_spec_mode = str(
            issue.get("security_spec_mode")
            or self.identity.get("security_spec_mode")
            or "authoritative"
        )
        security_spec_artifact_refs = _sanitize(
            issue.get("security_spec_artifact_refs")
            or self.identity.get("security_spec_artifact_refs")
            or []
        )
        security_spec_decision = _sanitize(
            issue.get("security_spec_decision")
            or self.identity.get("security_spec_decision")
            or {
                "active_product_effect": "semantic_input",
                "reason_code": "security_spec_manifest_unavailable",
            }
        )
        hypothesis_hunter_mode = str(
            issue.get("hypothesis_hunter_mode")
            or self.identity.get("hypothesis_hunter_mode")
            or "active"
        )
        hypothesis_hunter_artifact_refs = _sanitize(
            issue.get("hypothesis_hunter_artifact_refs")
            or self.identity.get("hypothesis_hunter_artifact_refs")
            or []
        )
        hypothesis_hunter_decision = _sanitize(
            issue.get("hypothesis_hunter_decision")
            or self.identity.get("hypothesis_hunter_decision")
            or {
                "active_product_effect": "candidate_registration_only",
                "reason_code": "hypothesis_hunter_manifest_unavailable",
            }
        )
        policy_ref = self.put_evidence(
            kind="terminal_policy_input",
            payload={
                "issue": self._state_projection(issue),
                "terminal_authority_decision": _sanitize(
                    issue.get("terminal_authority_decision") or {}
                ),
                "proof_kernel_mode": str(issue.get("proof_kernel_mode") or "authoritative"),
                "proof_kernel_artifact_refs": _sanitize(
                    issue.get("proof_kernel_artifact_refs") or []
                ),
                "proof_kernel_checker_results": _sanitize(
                    issue.get("proof_kernel_checker_results") or []
                ),
                "proof_kernel_checker_result_refs": _sanitize(
                    issue.get("proof_kernel_checker_result_refs") or []
                ),
                "proof_kernel_root_manifest_sha256": str(
                    issue.get("proof_kernel_root_manifest_sha256") or ""
                ),
                "proof_kernel_decision": _sanitize(
                    issue.get("proof_kernel_decision")
                    or issue.get("proof_kernel_terminal_authority_decision")
                    or {}
                ),
                "proof_kernel_terminal_authority_decision": _sanitize(
                    issue.get("proof_kernel_terminal_authority_decision") or {}
                ),
                "security_spec_mode": security_spec_mode,
                "security_spec_artifact_refs": security_spec_artifact_refs,
                "security_spec_decision": security_spec_decision,
                "hypothesis_hunter_mode": hypothesis_hunter_mode,
                "hypothesis_hunter_artifact_refs": hypothesis_hunter_artifact_refs,
                "hypothesis_hunter_decision": hypothesis_hunter_decision,
            },
            producer="terminal_authority_evaluator",
        )
        with self._lock:
            existing_terminal = next(
                (
                    deepcopy(event)
                    for event in reversed(self._trace(cluster_uid)["events"])
                    if event.get("stage") == "policy"
                    and event.get("reason_code") == terminal_reason
                    and str(event.get("disposition_after") or "") == _disposition(issue)
                ),
                None,
            )
        with self._lock:
            prior_terminal_events = [
                deepcopy(event)
                for event in self._trace(cluster_uid)["events"]
                if event.get("stage") == "policy"
                and str(event.get("reason_code") or "") in TERMINAL_REASON_CODES
            ]
        if prior_terminal_events and existing_terminal is None:
            raise DecisionTraceError("cluster already has a different terminal event")
        terminal = existing_terminal or self.append_event(
            cluster_uid,
            stage="policy",
            actor="terminal_authority_evaluator",
            reason_code=terminal_reason,
            after_state=self._state_projection(issue),
            input_refs=(policy_ref,),
            disposition_after=_disposition(issue),
            open_clause_ids=self._open_clause_ids(issue),
            details={
                "security_spec_mode": security_spec_mode,
                "security_spec_artifact_refs": security_spec_artifact_refs,
                "security_spec_decision": security_spec_decision,
                "hypothesis_hunter_mode": hypothesis_hunter_mode,
                "hypothesis_hunter_artifact_refs": hypothesis_hunter_artifact_refs,
                "hypothesis_hunter_decision": hypothesis_hunter_decision,
            },
            dedupe_key=f"terminal:{terminal_reason}:{_disposition(issue)}",
        )
        root_uid = str(issue.get("finding_root_uid") or "")
        if root_uid:
            is_alias = _disposition(issue) == "deduplicated_alias"
            self.append_event(
                cluster_uid,
                stage="report",
                actor="finding_root_v2",
                reason_code="ROOT_ALIAS" if is_alias else "ROOT_PRIMARY",
                after_state={
                    "finding_root_uid": root_uid,
                    "merge_contract": issue.get("finding_root_merge_contract"),
                },
                disposition_before=_disposition(issue),
                disposition_after=_disposition(issue),
                details={
                    "primary_validation_cluster_uid": issue.get(
                        "finding_root_primary_validation_cluster_uid"
                    ),
                    "member_validation_cluster_uids": issue.get("member_validation_cluster_uids"),
                },
                dedupe_key=f"root:{root_uid}:{'alias' if is_alias else 'primary'}",
            )
        for view in sorted({str(value) for value in view_memberships if str(value)}):
            reason = {
                "default": "VIEW_DEFAULT",
                "with_needs_review": "VIEW_WITH_NEEDS_REVIEW",
            }.get(view, "VIEW_EXCLUDED")
            self.append_event(
                cluster_uid,
                stage="report",
                actor="report_views",
                reason_code=reason,
                after_state={"view": view},
                disposition_after=_disposition(issue),
                dedupe_key=f"view:{view}",
            )
        with self._lock:
            trace = self._trace(cluster_uid)
            trace["terminal_disposition"] = _disposition(issue)
            trace["terminal_event_uid"] = terminal["event_uid"]
            trace["terminal_authority"] = str(terminal_reason)
            trace["terminal_reason_codes"] = list(reasons)
            trace["view_memberships"] = sorted(
                {str(value) for value in view_memberships if str(value)}
            )
            trace["finding_root"] = {
                "finding_root_uid": root_uid,
                "role": "alias" if _disposition(issue) == "deduplicated_alias" else "primary",
                "primary_validation_cluster_uid": str(
                    issue.get("finding_root_primary_validation_cluster_uid") or cluster_uid
                ),
            }
            self._persist_trace(cluster_uid)
            path = self._trace_paths[cluster_uid]
            trace_hash = str(trace.get("document_sha256") or "")
        issue["decision_trace_ref"] = path
        issue["decision_trace_sha256"] = trace_hash
        issue["terminal_event_uid"] = terminal["event_uid"]
        issue["terminal_authority"] = terminal_reason
        issue["terminal_reason_codes"] = list(reasons)
        issue["open_clause_ids"] = self._open_clause_ids(issue)
        return issue

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            self._bind_usage_events()
            traces = {
                cluster: {
                    "path": self._trace_paths.get(cluster, ""),
                    "trace_root_sha256": str(trace.get("trace_root_sha256") or ""),
                    "document_sha256": str(trace.get("document_sha256") or ""),
                    "event_count": len(trace.get("events") or []),
                    "terminal_disposition": str(trace.get("terminal_disposition") or ""),
                }
                for cluster, trace in sorted(self._traces.items())
            }
            coverage = {
                unit: {
                    "path": self._coverage_paths.get(unit, ""),
                    "trace_root_sha256": str(trace.get("trace_root_sha256") or ""),
                    "document_sha256": str(trace.get("document_sha256") or ""),
                    "event_count": len(trace.get("events") or []),
                }
                for unit, trace in sorted(self._coverage.items())
            }
            manifest: Dict[str, Any] = {
                "schema_version": DECISION_TRACE_MANIFEST_VERSION,
                "scan_uid": self.scan_uid,
                "identity": deepcopy(self.identity),
                "trace_count": len(traces),
                "coverage_trace_count": len(coverage),
                "evidence_object_count": len(self._evidence_refs),
                "model_event_count": len(self._model_event_refs),
                "traces": traces,
                "coverage_traces": coverage,
                "evidence_object_sha256": sorted(self._evidence_refs),
                "model_event_sha256": sorted(self._model_event_refs),
                "errors": list(self._errors),
            }
            usage = self._usage_binding()
            manifest["llm_usage_events"] = usage
            manifest["complete"] = not self._errors and bool(usage.get("conservation_valid", True))
            manifest["manifest_sha256"] = _sha256(manifest)
            self._write(self.manifest_path, manifest)
            manifest["manifest_path"] = str(self.manifest_path)
            return manifest

    def _bind_usage_events(self) -> None:
        snapshot = getattr(self.usage_ledger, "snapshot", None)
        if not callable(snapshot):
            return
        raw = snapshot(include_events=True)
        already_bound = {
            str(call_id)
            for trace in (*self._traces.values(), *self._coverage.values())
            for event in trace.get("events") or []
            if isinstance(event, Mapping)
            for call_id in event.get("call_ids") or []
            if str(call_id)
        }
        for event in raw.get("events") or []:
            if not isinstance(event, Mapping):
                continue
            call_id = str(event.get("call_id") or "")
            attribution = event.get("attribution")
            attribution = attribution if isinstance(attribution, Mapping) else {}
            cluster_uid = str(
                event.get("validation_cluster_uid")
                or attribution.get("validation_cluster_uid")
                or ""
            )
            audit_unit_uid = str(
                event.get("audit_unit_uid") or attribution.get("audit_unit_uid") or ""
            )
            if not call_id or call_id in already_bound:
                continue
            details = {
                "event_kind": "llm_usage_binding",
                "agent": str(event.get("agent") or attribution.get("agent") or ""),
                "stage": str(event.get("stage") or attribution.get("stage") or ""),
                "call_kind": str(event.get("call_kind") or attribution.get("call_kind") or ""),
            }
            if cluster_uid:
                self.append_event(
                    cluster_uid,
                    stage=str(event.get("stage") or attribution.get("stage") or "verifier"),
                    actor="llm_usage_ledger_binding",
                    reason_code="LLM_USAGE_BOUND",
                    call_ids=(call_id,),
                    token_delta=int(event.get("total_tokens") or 0),
                    details=details,
                    dedupe_key=f"usage:{call_id}",
                )
                already_bound.add(call_id)
                continue
            if not audit_unit_uid:
                continue
            self.record_coverage_event(
                audit_unit_uid,
                reason_code="AUDIT_UNIT_CREATED",
                producer="llm_usage_ledger_binding",
                call_ids=(call_id,),
                token_delta=int(event.get("total_tokens") or 0),
                details=details,
            )
            already_bound.add(call_id)

    def _usage_binding(self) -> Dict[str, Any]:
        snapshot = getattr(self.usage_ledger, "snapshot", None)
        if not callable(snapshot):
            return {
                "available": False,
                "event_count": 0,
                "referenced_call_count": 0,
                "conservation_valid": True,
            }
        raw = snapshot(include_events=True)
        events = [value for value in raw.get("events") or [] if isinstance(value, Mapping)]
        by_call = {
            str(value.get("call_id") or ""): int(value.get("total_tokens") or 0)
            for value in events
            if str(value.get("call_id") or "")
        }
        referenced: list[str] = [
            str(call_id)
            for trace in self._traces.values()
            for event in trace.get("events") or []
            if isinstance(event, Mapping)
            for call_id in event.get("call_ids") or []
            if str(call_id)
        ]
        referenced.extend(
            str(call_id)
            for trace in self._coverage.values()
            for event in trace.get("events") or []
            if isinstance(event, Mapping)
            for call_id in event.get("call_ids") or []
            if str(call_id)
        )
        referenced_unique = sorted(set(referenced))
        missing = sorted(set(referenced_unique) - set(by_call))
        duplicates = sorted(
            {call_id for call_id in referenced_unique if referenced.count(call_id) > 1}
        )
        trace_tokens = sum(
            int(event.get("token_delta") or 0)
            for trace in self._traces.values()
            for event in trace.get("events") or []
            if isinstance(event, Mapping) and event.get("call_ids")
        )
        trace_tokens += sum(
            int(event.get("token_delta") or 0)
            for trace in self._coverage.values()
            for event in trace.get("events") or []
            if isinstance(event, Mapping) and event.get("call_ids")
        )
        usage_tokens = sum(by_call.get(call_id, 0) for call_id in referenced_unique)
        unreferenced = sorted(set(by_call) - set(referenced_unique))
        raw_path = str(raw.get("usage_events_path") or "")
        file_sha = ""
        relative_path = ""
        if raw_path:
            path = Path(raw_path)
            try:
                resolved = path.resolve()
                root = self.root.resolve()
                if resolved == root or root in resolved.parents:
                    relative_path = resolved.relative_to(root).as_posix()
                    if resolved.is_file():
                        file_sha = hashlib.sha256(resolved.read_bytes()).hexdigest()
                    elif events:
                        missing.append("usage_sidecar_unreadable:FileNotFoundError")
                else:
                    missing.append("usage_sidecar_outside_trace_root")
            except OSError as exc:
                missing.append(f"usage_sidecar_unreadable:{type(exc).__name__}")
        conservation_valid = (
            not missing
            and not duplicates
            and not unreferenced
            and trace_tokens == usage_tokens
            and len(referenced_unique) == len(by_call)
        )
        return {
            "available": bool(events or raw_path),
            "schema_version": str(raw.get("schema_version") or ""),
            "path": relative_path,
            "file_sha256": file_sha,
            "event_count": len(events),
            "referenced_call_count": len(referenced_unique),
            "referenced_call_ids": referenced_unique,
            "trace_token_total": trace_tokens,
            "usage_token_total": usage_tokens,
            "missing_call_ids": missing,
            "unreferenced_call_ids": unreferenced,
            "duplicate_call_ids": duplicates,
            "provider_usage_coverage": (
                (raw.get("usage_attribution") or {}).get("provider_usage_coverage")
                if isinstance(raw.get("usage_attribution"), Mapping)
                else None
            ),
            "conservation_valid": conservation_valid,
        }

    def trace(self, validation_cluster_uid: str) -> Dict[str, Any]:
        with self._lock:
            return deepcopy(self._trace(validation_cluster_uid))

    def _trace(self, cluster_uid: str) -> Dict[str, Any]:
        return self._traces.setdefault(
            cluster_uid,
            {
                "schema_version": DECISION_TRACE_SCHEMA_VERSION,
                "scan_uid": self.scan_uid,
                "validation_cluster_uid": cluster_uid,
                "candidate_uids": [],
                "occurrence_uids": [],
                "identity": deepcopy(self.identity),
                "events": [],
                "terminal_disposition": "",
                "terminal_event_uid": "",
                "terminal_authority": "",
                "terminal_reason_codes": [],
                "view_memberships": [],
                "finding_root": {},
                "trace_root_sha256": "",
            },
        )

    def bind_candidate(
        self,
        validation_cluster_uid: str,
        *,
        candidate_uids: Iterable[str] = (),
        occurrence_uids: Iterable[str] = (),
    ) -> None:
        with self._lock:
            trace = self._trace(validation_cluster_uid)
            trace["candidate_uids"] = sorted(
                {
                    *[str(item) for item in trace.get("candidate_uids") or [] if str(item)],
                    *[str(item) for item in candidate_uids if str(item)],
                }
            )
            trace["occurrence_uids"] = sorted(
                {
                    *[str(item) for item in trace.get("occurrence_uids") or [] if str(item)],
                    *[str(item) for item in occurrence_uids if str(item)],
                }
            )
            self._persist_trace(validation_cluster_uid)

    def _persist_trace(self, cluster_uid: str) -> None:
        trace = self._trace(cluster_uid)
        document_body = dict(trace)
        document_body.pop("document_sha256", None)
        trace["document_sha256"] = _sha256(document_body)
        path = self.trace_dir / _artifact_name(cluster_uid)
        self._trace_paths[cluster_uid] = path.relative_to(self.root).as_posix()
        self._write(path, trace)

    def _write(self, path: Path, value: Mapping[str, Any]) -> None:
        try:
            _atomic_write_json(path, value)
        except OSError as exc:
            message = f"{type(exc).__name__}: {exc}"
            if message not in self._errors:
                self._errors.append(message)

    @staticmethod
    def _open_clause_ids(issue: Mapping[str, Any]) -> list[str]:
        raw = issue.get("open_clause_ids") or issue.get("missing_fact_kinds") or []
        return sorted({str(value) for value in raw if str(value)}) if isinstance(raw, list) else []

    @staticmethod
    def _state_projection(issue: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            key: _sanitize(issue.get(key))
            for key in (
                "candidate_uid",
                "obligation_uid",
                "validation_cluster_uid",
                "subject_uid",
                "resource_identity",
                "resource_signature",
                "source_identity",
                "decision_region_uid",
                "dependency_code_hash",
                "code_snapshot_hash",
                "candidate_disposition",
                "validation_status",
                "model_verdict",
                "policy_disposition",
                "proof_coverage",
                "evidence_conflict",
                "decision_fact_coverage",
                "missing_fact_kinds",
                "v3_evidence_closure",
                "finding_root_uid",
            )
            if issue.get(key) not in (None, "", [], {})
        }


_CONFIG_TRACE_LOCK = threading.Lock()


def ensure_decision_trace_store(config: Any) -> DecisionTraceStore:
    existing = getattr(config, "decision_trace_store", None)
    if isinstance(existing, DecisionTraceStore):
        existing.bind_usage_ledger(getattr(config, "scan_token_usage_ledger", None))
        return existing
    with _CONFIG_TRACE_LOCK:
        existing = getattr(config, "decision_trace_store", None)
        if isinstance(existing, DecisionTraceStore):
            existing.bind_usage_ledger(getattr(config, "scan_token_usage_ledger", None))
            return existing
        analysis = getattr(config, "analysis", None)
        snapshot_dir = Path(getattr(analysis, "snapshot_dir", ".zscope_snapshots"))
        project = getattr(config, "project", None)
        scan = getattr(config, "scan", None)
        identity = {
            "project_id": str(
                getattr(project, "project_id", "")
                or getattr(getattr(project, "project_root", None), "name", "")
            ),
            "project_root": str(getattr(project, "project_root", "") or ""),
            "scan_depth": str(getattr(scan, "depth", "fast") or "fast"),
            "effective_rules_sha256": str(
                getattr(getattr(config, "rule_catalog_provenance", None), "effective_sha256", "")
                or ""
            ),
        }
        store = DecisionTraceStore(
            snapshot_dir,
            identity=identity,
            usage_ledger=getattr(config, "scan_token_usage_ledger", None),
        )
        setattr(config, "decision_trace_store", store)
        return store


def verify_decision_trace(trace: Mapping[str, Any]) -> tuple[bool, str]:
    if str(trace.get("schema_version") or "") != DECISION_TRACE_SCHEMA_VERSION:
        return False, "unsupported trace schema"
    events = trace.get("events")
    if not isinstance(events, list):
        return False, "events must be a list"
    previous_hash = ""
    previous_uid = ""
    for index, raw in enumerate(events, start=1):
        if not isinstance(raw, Mapping):
            return False, f"event {index} is not an object"
        event = dict(raw)
        event_hash = str(event.pop("event_hash", ""))
        event_uid = str(event.pop("event_uid", ""))
        if int(event.get("sequence") or 0) != index:
            return False, f"event {index} has invalid sequence"
        if str(event.get("previous_event_hash") or "") != previous_hash:
            return False, f"event {index} breaks previous hash chain"
        parents = event.get("parent_event_uids") or []
        if index > 1 and previous_uid not in parents:
            return False, f"event {index} does not reference its causal predecessor"
        actual = _sha256(event)
        if actual != event_hash or event_uid != f"EVENT_{actual[:32]}":
            return False, f"event {index} hash mismatch"
        previous_hash = event_hash
        previous_uid = event_uid
    if str(trace.get("trace_root_sha256") or "") != previous_hash:
        return False, "trace root hash mismatch"
    document = dict(trace)
    supplied_document_hash = str(document.pop("document_sha256", ""))
    if supplied_document_hash != _sha256(document):
        return False, "trace document hash mismatch"
    return True, "ok"


def verify_coverage_trace(trace: Mapping[str, Any]) -> tuple[bool, str]:
    if str(trace.get("schema_version") or "") != COVERAGE_TRACE_SCHEMA_VERSION:
        return False, "unsupported coverage trace schema"
    events = trace.get("events")
    if not isinstance(events, list):
        return False, "coverage events must be a list"
    previous_hash = ""
    for index, raw in enumerate(events, start=1):
        if not isinstance(raw, Mapping):
            return False, f"coverage event {index} is not an object"
        event = dict(raw)
        event_hash = str(event.pop("event_hash", ""))
        event_uid = str(event.pop("event_uid", ""))
        if int(event.get("sequence") or 0) != index:
            return False, f"coverage event {index} has invalid sequence"
        if str(event.get("previous_event_hash") or "") != previous_hash:
            return False, f"coverage event {index} breaks previous hash chain"
        actual = _sha256(event)
        if actual != event_hash or event_uid != f"COVERAGE_{actual[:32]}":
            return False, f"coverage event {index} hash mismatch"
        previous_hash = event_hash
    if str(trace.get("trace_root_sha256") or "") != previous_hash:
        return False, "coverage trace root hash mismatch"
    document = dict(trace)
    supplied_document_hash = str(document.pop("document_sha256", ""))
    if supplied_document_hash != _sha256(document):
        return False, "coverage trace document hash mismatch"
    return True, "ok"


def load_decision_trace(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DecisionTraceError(f"cannot load decision trace: {exc}") from exc
    if not isinstance(value, dict):
        raise DecisionTraceError("decision trace must be a JSON object")
    valid, reason = verify_decision_trace(value)
    if not valid:
        raise DecisionTraceError(reason)
    return cast(Dict[str, Any], value)


def verify_evidence_object(path: Path) -> tuple[bool, str]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, str(exc)
    if not isinstance(value, dict):
        return False, "evidence object must be an object"
    digest = str(value.pop("sha256", ""))
    if not _SHA256_RE.fullmatch(digest):
        return False, "invalid evidence sha256"
    return (_sha256(value) == digest, "ok" if _sha256(value) == digest else "hash mismatch")


def verify_model_event(path: Path) -> tuple[bool, str]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, str(exc)
    if not isinstance(value, dict):
        return False, "model event must be an object"
    digest = str(value.pop("sha256", ""))
    if not _SHA256_RE.fullmatch(digest):
        return False, "invalid model-event sha256"
    valid = _sha256(value) == digest
    return valid, "ok" if valid else "hash mismatch"
