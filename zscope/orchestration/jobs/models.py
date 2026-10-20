"""Shared model constants and envelope helpers for persistent scan jobs.

This module is part of the S08 ``zscope/orchestration/jobs/`` slice.  It only
contains schema constants and pure helpers; persistence lives in
:mod:`zscope.orchestration.jobs.store` and process handling in
:mod:`zscope.orchestration.jobs.identity` / ``owner.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

SCHEMA_VERSION = "zscope.scan-jobs.v1"
LAUNCH_SCHEMA_VERSION = "zscope.scan-job-launch.v1"
PENDING_SCHEMA_VERSION = "zscope.scan-job-pending.v1"
OWNER_HEARTBEAT_SCHEMA = "zscope.scan-job-owner.v1"

JOB_STATUSES = (
    "queued",
    "running",
    "stopping",
    "completed",
    "partial",
    "cancelled",
    "failed",
    "lost",
)
ACTIVE_STATUSES = frozenset({"queued", "running", "stopping"})
TERMINAL_STATUSES = frozenset({"completed", "partial", "cancelled", "failed", "lost"})
CANCELLABLE_STATUSES = frozenset({"queued", "running"})
RESUMABLE_STATUSES = frozenset({"cancelled", "failed", "partial", "lost"})

OWNER_STATES = ("alive", "exited", "lost", "unknown")

SCAN_DEPTH_CHOICES = frozenset({"fast", "balanced", "deep"})

MAX_EVENT_DATA_CHARS = 4000
EVENT_PAGE_SIZE = 500
MAX_REQUEST_ID_CHARS = 128

PHASE_QUEUED = "queued"
PHASE_LAUNCHING = "launching"
PHASE_SCANNING = "scanning"
PHASE_FINALIZING = "finalizing"
PHASE_STOPPING = "stopping"


class JobError(Exception):
    """Error carrying an HTTP-aligned code/status for the envelope."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = dict(details or {})


def utc_now_iso() -> str:
    """Return the current time as ISO8601 with an explicit UTC offset."""

    return datetime.now(timezone.utc).isoformat()


def epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def parse_stop_at(value: Any) -> datetime:
    """Parse an ISO8601 ``stop_at`` value that must carry a timezone offset."""

    if not isinstance(value, str) or not value.strip():
        raise JobError(
            "invalid_request",
            "stop_at must be an ISO8601 timestamp string with an explicit timezone offset",
            status_code=400,
        )
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise JobError(
            "invalid_request",
            f"stop_at is not a valid ISO8601 timestamp: {text!r}",
            status_code=400,
        ) from exc
    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        raise JobError(
            "invalid_request",
            "stop_at must include an explicit timezone offset (e.g. 2026-10-14T22:00:00+08:00)",
            status_code=400,
        )
    return parsed


def resolve_stop_time(value: Any) -> tuple[Optional[str], Optional[float]]:
    """Return ``(resolved_iso_utc, epoch_seconds)`` for an optional stop_at."""

    if value is None:
        return None, None
    parsed = parse_stop_at(value)
    epoch = parsed.timestamp()
    return epoch_to_iso(epoch), epoch


def validate_scan_depth(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str) or value.strip().lower() not in SCAN_DEPTH_CHOICES:
        allowed = ", ".join(sorted(SCAN_DEPTH_CHOICES))
        raise JobError(
            "invalid_request",
            f"scan_depth must be one of: {allowed}",
            status_code=400,
        )
    return value.strip().lower()


def validate_request_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise JobError(
            "invalid_request",
            "request_id is required and must be a non-empty string",
            status_code=400,
        )
    request_id = value.strip()
    if len(request_id) > MAX_REQUEST_ID_CHARS:
        raise JobError(
            "invalid_request",
            f"request_id must be at most {MAX_REQUEST_ID_CHARS} characters",
            status_code=400,
        )
    return request_id


def validate_base_revision(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise JobError(
            "invalid_request",
            "base_revision must be an integer",
            status_code=400,
        )
    if value < 1:
        raise JobError(
            "invalid_request",
            "base_revision must be a positive integer",
            status_code=400,
        )
    return int(value)


def validate_after_seq(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise JobError(
            "invalid_request",
            "after_seq must be a non-negative integer",
            status_code=400,
        )
    if value < 0:
        raise JobError(
            "invalid_request",
            "after_seq must be a non-negative integer",
            status_code=400,
        )
    return int(value)


def error_envelope(exc: JobError) -> Dict[str, Any]:
    envelope: Dict[str, Any] = {"error": exc.message, "code": exc.code}
    if exc.details:
        envelope["details"] = exc.details
    return envelope


def bounded_event_data(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Bound event payloads so a runaway producer cannot grow the DB row.

    The result must also be finite JSON by itself: ``append_event`` persists
    it without a ``default`` encoder, so values that only ``default=str``
    can serialize are round-tripped into plain JSON types here.
    """

    if not data:
        return {}
    import json

    try:
        encoded = json.dumps(data, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"_truncated": True, "preview": str(data)[:1000]}
    if len(encoded) <= MAX_EVENT_DATA_CHARS:
        try:
            decoded = json.loads(encoded)
        except ValueError:  # pragma: no cover - defensive
            return {"_truncated": True, "preview": encoded[: MAX_EVENT_DATA_CHARS // 2]}
        return decoded if isinstance(decoded, dict) else {"_truncated": True, "preview": encoded}
    return {"_truncated": True, "preview": encoded[: MAX_EVENT_DATA_CHARS // 2]}


def null_progress() -> Dict[str, Any]:
    """Progress is only populated from real session events; unknown stays null."""

    return {"completed": None, "total": None, "active": None, "deferred": None, "unit": None}


def null_coverage() -> Dict[str, Any]:
    return {
        "completeness": None,
        "build_coverage": None,
        "gaps": [],
        "deferred_count": None,
    }


def capability_reason(code: str, message: str) -> Dict[str, str]:
    return {"code": code, "message": message}


def job_capabilities(status: str) -> Dict[str, Any]:
    reasons: List[Dict[str, str]] = []
    can_cancel = status in CANCELLABLE_STATUSES
    can_resume = status in RESUMABLE_STATUSES
    if not can_cancel:
        if status == "stopping":
            reasons.append(
                capability_reason("cancel_in_progress", "cancellation has already been requested")
            )
        elif status in TERMINAL_STATUSES:
            reasons.append(
                capability_reason("terminal_state", f"job is already in terminal state {status!r}")
            )
        else:
            reasons.append(capability_reason("invalid_state", f"cannot cancel from {status!r}"))
    if not can_resume:
        if status in ACTIVE_STATUSES:
            reasons.append(
                capability_reason("job_active", "job is still active; cancel it or wait")
            )
        elif status == "completed":
            reasons.append(
                capability_reason(
                    "already_completed", "job completed; start a new job for another scan"
                )
            )
        else:
            reasons.append(capability_reason("invalid_state", f"cannot resume from {status!r}"))
    return {"cancel": can_cancel, "resume": can_resume, "reasons": reasons}


def build_error_field(code: Optional[str], message: Optional[str]) -> Optional[Dict[str, str]]:
    if not code:
        return None
    return {"code": code, "message": str(message or "")}


def deduce_owner_state(
    *,
    probe_result: Optional[bool],
    job_status: str,
) -> str:
    """Map an identity probe result onto the contract owner state enum.

    ``probe_result`` is True when the recorded process identity is verifiably
    alive, False when it is verifiably gone (dead or PID reused), and None
    when the platform cannot prove either.
    """

    if probe_result is True:
        return "alive"
    if probe_result is False:
        return "exited" if job_status in TERMINAL_STATUSES else "lost"
    return "unknown"


def normalize_questions(raw: Any) -> List[Dict[str, Any]]:
    """Pass through real question records; anything malformed is dropped."""

    questions: List[Dict[str, Any]] = []
    if not isinstance(raw, list):
        return questions
    for item in raw:
        if not isinstance(item, dict):
            continue
        question = item.get("question")
        if not isinstance(question, str) or not question.strip():
            continue
        questions.append(
            {
                "id": item.get("id") if isinstance(item.get("id"), str) else None,
                "question": question,
                "affected_scope": item.get("affected_scope"),
                "current_assumption": item.get("current_assumption"),
                "impact": item.get("impact"),
                "answer_revision": item.get("answer_revision"),
            }
        )
    return questions


def merge_coverage(
    report: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Extract the coverage projection from a bound report, nulls when absent."""

    coverage = null_coverage()
    if not report:
        return coverage
    completeness = report.get("completeness")
    if isinstance(completeness, str) and completeness.strip():
        coverage["completeness"] = completeness.strip()
    metadata = report.get("metadata")
    if isinstance(metadata, dict):
        build_coverage = metadata.get("build_coverage")
        if isinstance(build_coverage, dict):
            coverage["build_coverage"] = build_coverage
        gaps = metadata.get("coverage_gaps")
        if isinstance(gaps, list):
            coverage["gaps"] = [gap for gap in gaps if isinstance(gap, (dict, str))]
        deferred = metadata.get("deferred_count")
        if isinstance(deferred, int) and not isinstance(deferred, bool):
            coverage["deferred_count"] = deferred
    return coverage


def report_completeness_is_partial(report: Optional[Dict[str, Any]]) -> Optional[bool]:
    """True/False when the bound report states completeness, else None."""

    if not report:
        return None
    completeness = report.get("completeness")
    if not isinstance(completeness, str) or not completeness.strip():
        return None
    return completeness.strip().lower() != "complete"


def extract_questions(report: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not report:
        return []
    metadata = report.get("metadata")
    if not isinstance(metadata, dict):
        return []
    return normalize_questions(metadata.get("business_questions"))


def iterable_strings(value: Any) -> Iterable[str]:
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, str) and item.strip():
                yield item.strip()
