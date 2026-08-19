"""Scan-wide, attribution-safe LLM usage telemetry.

The ledger is intentionally independent of any one Agent or LLM profile.  It
accounts for every physical provider attempt, but it never admits, rejects, or
truncates work based on a scan-wide token target.  Cost targets belong to the
benchmark policy and are evaluated after a scan has completed.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Union


USAGE_EVENT_SCHEMA_VERSION = "zscope.llm-usage-event.v1"
USAGE_ATTRIBUTION_SCHEMA_VERSION = "zscope.llm-usage-attribution.v1"
TOKEN_USAGE_SCHEMA_VERSION = "zscope.scan-token-usage.v1"
TOKEN_USAGE_STAGES = (
    "semantic_modeling",
    "active_discovery",
    "validation",
    "reserve",
)
_VALIDATOR_V3_CALL_KINDS = frozenset(
    {"length_retry", "json_repair", "investigation_synthesis", "targeted_investigation"}
)

_INHERITED_USAGE_ATTRIBUTION: ContextVar[Mapping[str, Any]] = ContextVar(
    "zscope_inherited_llm_usage_attribution",
    default={},
)


def current_llm_usage_attribution() -> Dict[str, Any]:
    """Return the current synchronous/nested LLM attribution scope.

    Context variables are thread/task local, so one Validator worker cannot
    leak its cluster identity into another concurrent worker.  Explicit call
    attribution remains authoritative over inherited values.
    """

    return dict(_INHERITED_USAGE_ATTRIBUTION.get() or {})


@contextmanager
def llm_usage_attribution_scope(**values: Any) -> Any:
    inherited = current_llm_usage_attribution()
    inherited.update({str(key): value for key, value in values.items() if value not in (None, "")})
    token = _INHERITED_USAGE_ATTRIBUTION.set(inherited)
    try:
        yield
    finally:
        _INHERITED_USAGE_ATTRIBUTION.reset(token)


def canonical_usage_stage(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "semantic": "semantic_modeling",
        "modeling": "semantic_modeling",
        "security_spec_miner": "semantic_modeling",
        "discovery": "active_discovery",
        "active_analysis": "active_discovery",
        "mining": "active_discovery",
        "investigation": "active_discovery",
        "proof_engine": "validation",
        "repair": "reserve",
        "v3": "reserve",
    }
    normalized = aliases.get(normalized, normalized)
    # Unknown legacy/direct callers use the validation pool.  This preserves
    # fast-mode compatibility while telemetry still labels them unattributed.
    return normalized if normalized in TOKEN_USAGE_STAGES else "validation"


def _token_count(value: Any, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("token count must be numeric")
    parsed = int(value)
    if parsed < minimum:
        qualifier = "positive" if minimum > 0 else "non-negative"
        raise ValueError(f"token count must be {qualifier}")
    return parsed


def _clean(value: Any, *, limit: int = 240) -> str:
    text = " ".join(str(value or "").strip().split())
    return text[:limit]


@dataclass(frozen=True)
class LLMUsageAttribution:
    """Stable, non-secret dimensions linking one LLM call to scan work."""

    stage: str = ""
    agent: str = ""
    skill: str = ""
    entry_identity: str = ""
    audit_unit_uid: str = ""
    candidate_uid: str = ""
    finding_uid: str = ""
    validation_cluster_uid: str = ""
    llm_ref: str = ""
    call_kind: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "schema_version": USAGE_ATTRIBUTION_SCHEMA_VERSION,
            "stage": _clean(self.stage),
            "agent": _clean(self.agent),
            "skill": _clean(self.skill),
            "entry_identity": _clean(self.entry_identity),
            "audit_unit_uid": _clean(self.audit_unit_uid),
            "candidate_uid": _clean(self.candidate_uid),
            "finding_uid": _clean(self.finding_uid),
            "validation_cluster_uid": _clean(self.validation_cluster_uid),
            "llm_ref": _clean(self.llm_ref),
            "call_kind": _clean(self.call_kind),
        }

    @classmethod
    def from_mapping(cls, value: Optional[Mapping[str, Any]]) -> "LLMUsageAttribution":
        data = value or {}
        return cls(
            stage=_clean(data.get("stage")),
            agent=_clean(data.get("agent")),
            skill=_clean(data.get("skill")),
            entry_identity=_clean(data.get("entry_identity") or data.get("entry")),
            audit_unit_uid=_clean(data.get("audit_unit_uid") or data.get("unit")),
            candidate_uid=_clean(data.get("candidate_uid") or data.get("candidate")),
            finding_uid=_clean(data.get("finding_uid") or data.get("finding")),
            validation_cluster_uid=_clean(
                data.get("validation_cluster_uid") or data.get("validation_cluster")
            ),
            llm_ref=_clean(data.get("llm_ref")),
            call_kind=_clean(data.get("call_kind")),
        )

    @classmethod
    def from_trace(
        cls,
        *,
        trace_agent: Optional[str],
        trace_label: Optional[str],
        llm_ref: str = "",
        explicit: Optional[Mapping[str, Any]] = None,
    ) -> "LLMUsageAttribution":
        data: Dict[str, Any] = dict(explicit or {})
        agent = _clean(data.get("agent") or trace_agent)
        label = str(trace_label or "")

        def capture(*names: str) -> str:
            for name in names:
                match = re.search(
                    rf"(?:^|[;\s]){re.escape(name)}\s*=\s*([^;]+)",
                    label,
                    flags=re.IGNORECASE,
                )
                if match:
                    return _clean(match.group(1))
            return ""

        call_kind = _clean(data.get("call_kind") or capture("call_kind"))
        stage = _clean(data.get("stage"))
        if not stage:
            normalized_agent = agent.lower()
            normalized_label = label.lower()
            if "repair" in normalized_label or "json_retry" in normalized_label:
                stage = "reserve"
            elif call_kind in _VALIDATOR_V3_CALL_KINDS:
                stage = "reserve"
            elif "proof_engine" in normalized_agent:
                stage = "validation"
            elif (
                "security_spec_miner" in normalized_agent
                or "history_maintenance_agent" in normalized_agent
            ):
                stage = "semantic_modeling"
            elif "hypothesis_hunter" in normalized_agent:
                stage = "active_discovery"
            else:
                stage = _clean(data.get("call_kind") or "unattributed")
        return cls(
            stage=stage,
            agent=agent,
            skill=_clean(data.get("skill") or capture("skill")),
            entry_identity=_clean(
                data.get("entry_identity") or data.get("entry") or capture("entry")
            ),
            audit_unit_uid=_clean(
                data.get("audit_unit_uid") or data.get("unit") or capture("audit_unit_uid", "unit")
            ),
            candidate_uid=_clean(
                data.get("candidate_uid") or data.get("candidate") or capture("candidate")
            ),
            finding_uid=_clean(
                data.get("finding_uid") or data.get("finding") or capture("finding")
            ),
            validation_cluster_uid=_clean(
                data.get("validation_cluster_uid")
                or data.get("validation_cluster")
                or capture("validation_cluster_uid", "validation_cluster")
            ),
            llm_ref=_clean(data.get("llm_ref") or llm_ref),
            call_kind=call_kind,
        )


@dataclass(frozen=True)
class TokenUsageReservation:
    reservation_id: str
    estimated_prompt_tokens: int
    reserved_prompt_tokens: int
    completion_token_limit: int
    reserved_total_tokens: int
    attribution: LLMUsageAttribution
    budget_stage: str = "validation"
    model: str = ""
    local_scope: str = ""
    local_limit_tokens: int = 0
    created_monotonic: float = field(default_factory=time.monotonic)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "estimated_prompt_tokens": self.estimated_prompt_tokens,
            "reserved_prompt_tokens": self.reserved_prompt_tokens,
            "completion_token_limit": self.completion_token_limit,
            "reserved_total_tokens": self.reserved_total_tokens,
            "attribution": self.attribution.to_dict(),
            "budget_stage": self.budget_stage,
            "model": _clean(self.model),
            "local_scope": self.local_scope,
            "local_limit_tokens": self.local_limit_tokens,
        }


@dataclass(frozen=True)
class LLMUsageEvent:
    sequence: int
    reservation_id: str
    outcome: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    reserved_total_tokens: int
    provider_reported: bool
    conservative_charge: bool
    budget_violation: bool
    attribution: LLMUsageAttribution
    budget_stage: str = "validation"
    model: str = ""
    reason: str = ""
    finish_reason: str = ""
    cached_prompt_tokens: int = 0
    reasoning_tokens: int = 0
    retry: bool = False
    repair: bool = False
    tool_call_count: int = 0
    new_fact_count: int = 0
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        attribution = self.attribution.to_dict()
        return {
            "schema_version": USAGE_EVENT_SCHEMA_VERSION,
            "sequence": self.sequence,
            # Public telemetry and benchmark contracts call this identity
            # ``call_id``.  Keep reservation_id as a compatibility alias.
            # A denied request has no reservation, so its monotonic sequence
            # provides a stable per-scan identity.
            "call_id": self.reservation_id or f"denied:{self.sequence}",
            "reservation_id": self.reservation_id,
            "agent": attribution["agent"],
            "stage": self.budget_stage,
            "candidate_uid": attribution["candidate_uid"],
            "audit_unit_uid": attribution["audit_unit_uid"],
            "validation_cluster_uid": attribution["validation_cluster_uid"],
            "llm_ref": attribution["llm_ref"],
            "call_kind": attribution["call_kind"],
            "outcome": self.outcome,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "reserved_total_tokens": self.reserved_total_tokens,
            "provider_reported": self.provider_reported,
            "conservative_charge": self.conservative_charge,
            "budget_violation": self.budget_violation,
            "attribution": attribution,
            "budget_stage": self.budget_stage,
            "model": _clean(self.model),
            "reason": _clean(self.reason, limit=500),
            "finish_reason": _clean(self.finish_reason),
            # cached_prompt_tokens is a subset of prompt_tokens and
            # reasoning_tokens is a subset of completion_tokens.  Consumers
            # must not add either field to total_tokens.
            "cached_prompt_tokens": self.cached_prompt_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "retry": self.retry,
            "repair": self.repair,
            "tool_call_count": self.tool_call_count,
            "new_fact_count": self.new_fact_count,
            "duration_ms": self.duration_ms,
        }


def _empty_usage_row() -> Dict[str, int]:
    return {
        "request_count": 0,
        "successful_calls": 0,
        "denied_requests": 0,
        "failed_or_unknown_calls": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "provider_reported_calls": 0,
        "estimated_or_conservative_calls": 0,
        "budget_violation_count": 0,
        "cached_prompt_tokens": 0,
        "reasoning_tokens": 0,
        "retry_count": 0,
        "repair_count": 0,
        "tool_call_count": 0,
        "new_fact_count": 0,
        "duration_ms": 0,
    }


class LLMUsageEventAggregator:
    """Incrementally aggregate serializable usage events by audit dimension."""

    _DIMENSIONS = {
        "by_stage": lambda event: event.budget_stage,
        "by_agent": lambda event: event.attribution.agent,
        "by_skill": lambda event: event.attribution.skill,
        "by_entry": lambda event: event.attribution.entry_identity,
        "by_audit_unit": lambda event: event.attribution.audit_unit_uid,
        "by_candidate": lambda event: event.attribution.candidate_uid,
        "by_finding": lambda event: event.attribution.finding_uid,
        "by_validation_cluster": lambda event: event.attribution.validation_cluster_uid,
        "by_llm_ref": lambda event: event.attribution.llm_ref,
        # Validator V1/V2/V3 calls share the validation agent and may share the
        # same coarse stage.  Preserve the physical call kind so benchmark
        # reports can attribute their token cost without inspecting prompts.
        "by_call_kind": lambda event: event.attribution.call_kind,
        "by_model": lambda event: event.model,
        "by_finish_reason": lambda event: event.finish_reason or "unknown",
        "by_agent_stage": lambda event: "|".join(
            (
                event.attribution.agent or "unattributed",
                event.budget_stage,
            )
        ),
    }

    def __init__(self) -> None:
        self._totals = _empty_usage_row()
        self._dimensions: Dict[str, Dict[str, Dict[str, int]]] = {
            name: {} for name in self._DIMENSIONS
        }

    @staticmethod
    def _add(row: Dict[str, int], event: LLMUsageEvent) -> None:
        row["request_count"] += 1
        if event.outcome == "success":
            row["successful_calls"] += 1
        elif event.outcome == "denied":
            row["denied_requests"] += 1
        else:
            row["failed_or_unknown_calls"] += 1
        row["prompt_tokens"] += event.prompt_tokens
        row["completion_tokens"] += event.completion_tokens
        row["total_tokens"] += event.total_tokens
        if event.provider_reported:
            row["provider_reported_calls"] += 1
        else:
            row["estimated_or_conservative_calls"] += 1
        if event.budget_violation:
            row["budget_violation_count"] += 1
        row["cached_prompt_tokens"] += event.cached_prompt_tokens
        row["reasoning_tokens"] += event.reasoning_tokens
        row["retry_count"] += int(event.retry)
        row["repair_count"] += int(event.repair)
        row["tool_call_count"] += event.tool_call_count
        row["new_fact_count"] += event.new_fact_count
        row["duration_ms"] += event.duration_ms

    def record(self, event: LLMUsageEvent) -> None:
        self._add(self._totals, event)
        for dimension, selector in self._DIMENSIONS.items():
            key = _clean(selector(event)) or "unattributed"
            row = self._dimensions[dimension].setdefault(key, _empty_usage_row())
            self._add(row, event)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "totals": dict(self._totals),
            **{
                name: {key: dict(value) for key, value in sorted(rows.items())}
                for name, rows in self._dimensions.items()
            },
        }


class ScanTokenUsageLedger:
    """Thread-safe usage ledger shared by a whole scan.

    ``reserve`` records the expected size of an in-flight provider attempt so
    unknown-usage failures can be charged conservatively.  It never reduces a
    provider output allowance and never refuses an attempt.
    """

    def __init__(self, *, depth: str = "fast", event_sink_path: Optional[Path] = None) -> None:
        self.depth = str(depth or "fast").strip().lower()
        self._lock = threading.Lock()
        self._consumed_tokens = 0
        self._reserved_tokens = 0
        self._sequence = 0
        self._reservation_sequence = 0
        self._reservations: Dict[str, TokenUsageReservation] = {}
        self._stage_consumed_tokens = {stage: 0 for stage in TOKEN_USAGE_STAGES}
        self._stage_reserved_tokens = {stage: 0 for stage in TOKEN_USAGE_STAGES}
        self._events: list[LLMUsageEvent] = []
        self._event_sink_path = Path(event_sink_path) if event_sink_path else None
        self._persisted_event_count = 0
        self._event_sink_error = ""
        self._aggregator = LLMUsageEventAggregator()

    def reserve(
        self,
        estimated_prompt_tokens: int,
        max_completion_tokens: int,
        *,
        attribution: Optional[LLMUsageAttribution] = None,
        model: str = "",
    ) -> TokenUsageReservation:
        estimated = _token_count(estimated_prompt_tokens)
        requested_completion = _token_count(max_completion_tokens, minimum=1)
        normalized_attribution = attribution or LLMUsageAttribution()
        usage_stage = canonical_usage_stage(normalized_attribution.stage)
        with self._lock:
            self._reservation_sequence += 1
            reservation = TokenUsageReservation(
                reservation_id=f"llm-reservation-{self._reservation_sequence}",
                estimated_prompt_tokens=estimated,
                reserved_prompt_tokens=estimated,
                completion_token_limit=requested_completion,
                reserved_total_tokens=estimated + requested_completion,
                attribution=normalized_attribution,
                budget_stage=usage_stage,
                model=_clean(model),
            )
            self._reservations[reservation.reservation_id] = reservation
            self._reserved_tokens += reservation.reserved_total_tokens
            self._stage_reserved_tokens[usage_stage] += reservation.reserved_total_tokens
            return reservation

    def settle(
        self,
        reservation: TokenUsageReservation,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: Optional[int] = None,
        provider_reported: bool = False,
        outcome: str = "success",
        reason: str = "",
        conservative_charge: bool = False,
        finish_reason: str = "",
        cached_prompt_tokens: int = 0,
        reasoning_tokens: int = 0,
        retry: bool = False,
        repair: bool = False,
        tool_call_count: int = 0,
        new_fact_count: int = 0,
        duration_ms: int = 0,
    ) -> LLMUsageEvent:
        prompt = _token_count(prompt_tokens)
        completion = _token_count(completion_tokens)
        combined = prompt + completion
        total = combined if total_tokens is None else max(combined, _token_count(total_tokens))
        with self._lock:
            active = self._reservations.pop(reservation.reservation_id, None)
            if active is None:
                raise ValueError(
                    f"unknown or already settled reservation {reservation.reservation_id}"
                )
            self._reserved_tokens -= active.reserved_total_tokens
            self._stage_reserved_tokens[active.budget_stage] -= active.reserved_total_tokens
            self._consumed_tokens += total
            self._stage_consumed_tokens[active.budget_stage] += total
            return self._new_event_locked(
                reservation_id=active.reservation_id,
                outcome=_clean(outcome) or "success",
                prompt_tokens=prompt,
                completion_tokens=completion,
                total_tokens=total,
                reserved_total_tokens=active.reserved_total_tokens,
                provider_reported=bool(provider_reported),
                conservative_charge=bool(conservative_charge),
                budget_violation=False,
                attribution=active.attribution,
                budget_stage=active.budget_stage,
                model=active.model,
                reason=reason,
                finish_reason=_clean(finish_reason),
                cached_prompt_tokens=min(prompt, _token_count(cached_prompt_tokens)),
                reasoning_tokens=min(completion, _token_count(reasoning_tokens)),
                retry=bool(retry),
                repair=bool(repair),
                tool_call_count=_token_count(tool_call_count),
                new_fact_count=_token_count(new_fact_count),
                duration_ms=_token_count(duration_ms),
            )

    def forfeit(
        self,
        reservation: TokenUsageReservation,
        *,
        reason: str,
        retry: bool = False,
        repair: bool = False,
        duration_ms: int = 0,
    ) -> LLMUsageEvent:
        """Conservatively charge a dispatched request with unknown usage."""

        return self.settle(
            reservation,
            prompt_tokens=reservation.reserved_prompt_tokens,
            completion_tokens=reservation.completion_token_limit,
            total_tokens=reservation.reserved_total_tokens,
            provider_reported=False,
            outcome="failed_unknown_usage",
            reason=reason,
            conservative_charge=True,
            retry=retry,
            repair=repair,
            duration_ms=duration_ms,
        )

    def snapshot(self, *, include_events: bool = False) -> Dict[str, Any]:
        with self._lock:
            return self._snapshot_locked(include_events=include_events)

    def events_jsonl(self) -> str:
        """Serialize audit-safe usage events without prompts or model responses."""

        with self._lock:
            rows = [event.to_dict() for event in self._events]
        return "".join(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in rows
        )

    def events_for_cluster(self, validation_cluster_uid: str) -> list[Dict[str, Any]]:
        """Return audit-safe physical call events for one validation cluster."""

        cluster_uid = _clean(validation_cluster_uid)
        if not cluster_uid:
            return []
        with self._lock:
            return [
                event.to_dict()
                for event in self._events
                if event.attribution.validation_cluster_uid == cluster_uid
            ]

    def attribute_accepted_facts(
        self,
        *,
        validation_cluster_uid: str,
        new_fact_count: int,
    ) -> bool:
        """Attach accepted V3 facts to the physical call that finalized them.

        Tool-produced facts are validated only after the terminal Validator
        result is parsed.  At that point the last V3 call is the first call for
        which ``new_fact_count`` is authoritative.  Updating under the ledger
        lock keeps the raw JSONL sidecar and every aggregate dimension in
        conservation without relying on a model self-report.
        """

        cluster_uid = _clean(validation_cluster_uid)
        count = _token_count(new_fact_count)
        if not cluster_uid or count <= 0:
            return False
        with self._lock:
            target_index = -1
            for index in range(len(self._events) - 1, -1, -1):
                event = self._events[index]
                if event.attribution.validation_cluster_uid != cluster_uid:
                    continue
                if event.attribution.call_kind not in {
                    "targeted_investigation",
                    "investigation_synthesis",
                }:
                    continue
                target_index = index
                break
            if target_index < 0:
                return False
            current = self._events[target_index]
            if current.new_fact_count == count:
                return True
            self._events[target_index] = replace(current, new_fact_count=count)
            self._aggregator = LLMUsageEventAggregator()
            for event in self._events:
                self._aggregator.record(event)
            if self._event_sink_path is not None:
                try:
                    self._event_sink_path.parent.mkdir(parents=True, exist_ok=True)
                    temporary = self._event_sink_path.with_name(
                        self._event_sink_path.name + ".rewrite.tmp"
                    )
                    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                        for event in self._events:
                            handle.write(
                                json.dumps(
                                    event.to_dict(),
                                    ensure_ascii=False,
                                    sort_keys=True,
                                )
                            )
                            handle.write("\n")
                    temporary.replace(self._event_sink_path)
                    self._persisted_event_count = len(self._events)
                except OSError as exc:
                    self._event_sink_error = f"{type(exc).__name__}: {exc}"
                    return False
            return True

    def export_events_jsonl(
        self,
        path: Union[Path, str],
        *,
        append: bool = False,
    ) -> Path:
        """Write the event stream as UTF-8 JSONL for offline cost attribution."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with destination.open(mode, encoding="utf-8", newline="\n") as handle:
            handle.write(self.events_jsonl())
        return destination

    def _new_event_locked(self, **values: Any) -> LLMUsageEvent:
        self._sequence += 1
        event = LLMUsageEvent(sequence=self._sequence, **values)
        self._events.append(event)
        self._aggregator.record(event)
        if self._event_sink_path is not None:
            try:
                self._event_sink_path.parent.mkdir(parents=True, exist_ok=True)
                with self._event_sink_path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True))
                    handle.write("\n")
                self._persisted_event_count += 1
            except OSError as exc:
                # Accounting remains available in memory, but a formal run can
                # now fail closed on telemetry_complete instead of silently
                # treating a missing call ledger as authoritative.
                self._event_sink_error = f"{type(exc).__name__}: {exc}"
        return event

    def _snapshot_locked(self, *, include_events: bool) -> Dict[str, Any]:
        stages: Dict[str, Dict[str, int]] = {}
        for stage in TOKEN_USAGE_STAGES:
            stages[stage] = {
                "consumed_tokens": self._stage_consumed_tokens[stage],
                "reserved_tokens": self._stage_reserved_tokens[stage],
            }
        result: Dict[str, Any] = {
            "schema_version": TOKEN_USAGE_SCHEMA_VERSION,
            "depth": self.depth,
            "consumed_tokens": self._consumed_tokens,
            "reserved_tokens": self._reserved_tokens,
            "active_reservation_count": len(self._reservations),
            "event_count": len(self._events),
            "stage_order": list(TOKEN_USAGE_STAGES),
            "stages": stages,
            "usage_attribution": self._aggregator.snapshot(),
            "usage_events_path": (
                str(self._event_sink_path) if self._event_sink_path is not None else ""
            ),
            "event_persistence_enabled": self._event_sink_path is not None,
            "persisted_event_count": self._persisted_event_count,
            "telemetry_complete": not self._event_sink_error
            and (self._event_sink_path is None or self._persisted_event_count == len(self._events)),
            "telemetry_error": self._event_sink_error,
        }
        if include_events:
            result["events"] = [event.to_dict() for event in self._events]
        return result


_CONFIG_LEDGER_LOCK = threading.Lock()


def ensure_scan_token_usage_ledger(config: Any) -> ScanTokenUsageLedger:
    """Return the one usage ledger attached to an effective scan config."""

    existing = getattr(config, "scan_token_usage_ledger", None)
    if isinstance(existing, ScanTokenUsageLedger):
        return existing
    with _CONFIG_LEDGER_LOCK:
        existing = getattr(config, "scan_token_usage_ledger", None)
        if isinstance(existing, ScanTokenUsageLedger):
            return existing
        scan = getattr(config, "scan", None)
        depth = getattr(scan, "depth", "fast")
        analysis = getattr(config, "analysis", None)
        snapshot_dir = Path(getattr(analysis, "snapshot_dir", ".zscope_snapshots"))
        event_sink_path = snapshot_dir / f"llm_usage_events_{uuid.uuid4().hex}.jsonl"
        ledger = ScanTokenUsageLedger(depth=depth, event_sink_path=event_sink_path)
        setattr(config, "scan_token_usage_ledger", ledger)
        return ledger


def scan_token_usage_snapshot(config: Any, *, include_events: bool = False) -> Dict[str, Any]:
    ledger = ensure_scan_token_usage_ledger(config)
    return ledger.snapshot(include_events=include_events)
