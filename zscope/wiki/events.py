"""Replay and render the program-owned Wiki audit event chain."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from .identity import digest_json
from .schema import validate_instance


AUDIT_EVENTS_MAX_BYTES = 64 * 1024 * 1024
AUDIT_EVENT_MAX_LINE_BYTES = 64 * 1024
AUDIT_EVENT_MAX_COUNT = 100_000
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class AuditReplayResult:
    events: Tuple[Dict[str, Any], ...]
    errors: Tuple[str, ...]
    active_revision_id: Optional[str]
    head_digest: Optional[str]
    failed_revision_ids: Tuple[str, ...]
    quarantined_workset_ids: Tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "passed" if self.passed else "failed",
            "event_count": len(self.events),
            "active_revision_id": self.active_revision_id,
            "head_digest": self.head_digest,
            "failed_revision_ids": list(self.failed_revision_ids),
            "quarantined_workset_ids": list(self.quarantined_workset_ids),
            "errors": list(self.errors),
        }


def replay_audit_events(path: Union[Path, str]) -> AuditReplayResult:
    audit_path = Path(path)
    if audit_path.is_symlink():
        return AuditReplayResult((), ("audit_events_symlink",), None, None, (), ())
    if not audit_path.is_file():
        return AuditReplayResult((), ("audit_events_missing",), None, None, (), ())
    try:
        if audit_path.stat().st_size > AUDIT_EVENTS_MAX_BYTES:
            return AuditReplayResult(
                (),
                ("audit_events_size_limit",),
                None,
                None,
                (),
                (),
            )
    except OSError:
        return AuditReplayResult((), ("audit_events_unavailable",), None, None, (), ())
    events = []
    errors = []
    previous_digest: Optional[str] = None
    active_revision_id: Optional[str] = None
    failed_revision_ids = []
    quarantined_workset_ids = []
    try:
        with audit_path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                if line_number > AUDIT_EVENT_MAX_COUNT:
                    errors.append("audit_event_count_limit")
                    break
                if len(raw_line) > AUDIT_EVENT_MAX_LINE_BYTES:
                    errors.append(f"audit_event_line_limit:{line_number}")
                    break
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError:
                    errors.append(f"audit_event_utf8:{line_number}")
                    continue
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    validate_instance(event, "zscope.wiki-event.v1")
                    for key, value in event.items():
                        if not isinstance(value, str):
                            continue
                        max_length = 160 if key == "project_id" else 80 if key == "occurred_at" else 500
                        if len(value) > max_length or _CONTROL_CHARS.search(value):
                            raise ValueError("unsafe event text")
                except Exception:
                    errors.append(f"audit_event_invalid:{line_number}")
                    continue
                events.append(dict(event))
                if int(event.get("event_id", 0)) != len(events):
                    errors.append(f"audit_event_id:{line_number}")
                if event.get("previous_event_digest") != previous_digest:
                    errors.append(f"audit_event_chain:{line_number}")
                expected_digest = digest_json(
                    {key: value for key, value in event.items() if key != "event_digest"}
                )
                if event.get("event_digest") != expected_digest:
                    errors.append(f"audit_event_digest:{line_number}")
                previous_digest = str(event.get("event_digest"))
                event_type = str(event.get("event_type") or "")
                status = str(event.get("status") or "")
                revision_id = str(event.get("revision_id") or "")
                if event_type == "publish" and status == "succeeded":
                    if revision_id:
                        active_revision_id = revision_id
                    else:
                        errors.append(f"audit_transition_revision:{line_number}")
                elif event_type == "rollback" and status == "rolled_back":
                    if revision_id:
                        active_revision_id = revision_id
                    else:
                        errors.append(f"audit_transition_revision:{line_number}")
                elif event_type == "publish" and status == "failed" and revision_id:
                    failed_revision_ids.append(revision_id)
                elif status == "quarantined" and event.get("workset_id"):
                    quarantined_workset_ids.append(str(event["workset_id"]))
    except OSError:
        errors.append("audit_events_unavailable")
    return AuditReplayResult(
        tuple(events),
        tuple(sorted(set(errors))),
        active_revision_id,
        previous_digest,
        tuple(dict.fromkeys(failed_revision_ids)),
        tuple(dict.fromkeys(quarantined_workset_ids)),
    )


def render_log_markdown(replay: AuditReplayResult) -> str:
    lines = ["# Wiki log", ""]
    for event in replay.events:
        details = [
            f"event={event['event_id']}",
            f"type={event['event_type']}",
            f"status={event['status']}",
        ]
        if event.get("revision_id"):
            details.append(f"revision={event['revision_id']}")
        if event.get("workset_id"):
            details.append(f"workset={event['workset_id']}")
        if event.get("fallback_reason"):
            details.append(f"fallback={event['fallback_reason']}")
        details.append(f"payload={event['payload_digest']}")
        lines.append(f"- {event['occurred_at']} " + " ".join(details))
    return "\n".join(lines) + "\n"


__all__ = [
    "AuditReplayResult",
    "render_log_markdown",
    "replay_audit_events",
    "AUDIT_EVENTS_MAX_BYTES",
    "AUDIT_EVENT_MAX_LINE_BYTES",
    "AUDIT_EVENT_MAX_COUNT",
]
