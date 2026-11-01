"""Durable, saved-config schedules. The detached coordinator never runs user argv.

Calendar policy is separate from jobs: each active window arms a normal, owner-
verified job attempt with a fresh absolute deadline. SQLite reservations and the
job service's idempotency keys make coordinator restart safe.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, time as wall_time, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from typing import Any, Iterator
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .identity import probe_process, read_process_start_ticks, system_boot_id
from .models import (
    ACTIVE_STATUSES,
    JobError,
    parse_stop_at,
    validate_request_id,
    validate_scan_depth,
)
from .service import ScanJobService, ServiceResponse, _envelope_errors

SCHEMA = "zscope.scan-schedules.v1"
LIVE = {"waiting", "running"}


def iso(epoch: float | None) -> str | None:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat() if epoch is not None else None


def daily_window_at(now: float, policy: dict[str, Any]) -> tuple[float, float]:
    """Current or next daily interval; end is exclusive, including midnight.

    DST gaps are normalized forward by UTC roundtrip. A repeated wall-clock
    boundary uses its first occurrence, so no duplicate window is invented.
    """
    zone = ZoneInfo(policy["timezone"])
    local = datetime.fromtimestamp(now, zone)
    start = wall_time.fromisoformat(policy["start"])
    end = wall_time.fromisoformat(policy["end"])
    for offset in (-1, 0, 1, 2):
        day = local.date() + timedelta(days=offset)
        left = datetime.combine(day, start, zone).timestamp()
        right = datetime.combine(day + timedelta(days=end <= start), end, zone).timestamp()
        if right > now and right > left:
            return left, right
    raise ValueError("Cannot resolve a daily execution window")


def validate_policy(payload: dict[str, Any], now: float) -> dict[str, Any]:
    allowed = {"request_id", "scan_depth", "start_at", "end_mode", "stop_at", "daily_window"}
    if not {"request_id", "scan_depth", "end_mode"} <= set(payload) <= allowed:
        raise JobError("invalid_request", "Schedule fields are invalid.", status_code=400)
    request = validate_request_id(payload["request_id"])
    depth = validate_scan_depth(payload["scan_depth"])
    if depth is None:
        raise JobError("invalid_request", "Select fast, balanced or deep.", status_code=400)
    if not isinstance(payload["end_mode"], str) or payload["end_mode"] not in {
        "complete",
        "deadline",
    }:
        raise JobError("invalid_request", "Select complete or deadline.", status_code=400)
    if payload.get("start_at") is not None and not isinstance(payload["start_at"], str):
        raise JobError(
            "invalid_request", "Start time must be an absolute timestamp.", status_code=400
        )
    start = (
        parse_stop_at(payload["start_at"]).timestamp()
        if payload.get("start_at") is not None
        else now
    )
    stop = None
    if payload["end_mode"] == "deadline":
        stop = parse_stop_at(payload.get("stop_at")).timestamp()
        if stop <= max(start, now):
            raise JobError(
                "invalid_request",
                "Deadline must follow the start and current time.",
                status_code=400,
            )
    elif payload.get("stop_at") is not None:
        raise JobError(
            "invalid_request", "Until-complete schedules cannot carry a deadline.", status_code=400
        )
    daily = payload.get("daily_window")
    if daily is not None:
        if not isinstance(daily, dict) or set(daily) != {"timezone", "start", "end"}:
            raise JobError(
                "invalid_request", "Daily window needs timezone, start and end.", status_code=400
            )
        try:
            ZoneInfo(daily["timezone"])
            for field in ("start", "end"):
                value = daily[field]
                if not isinstance(value, str) or len(value) != 5:
                    raise ValueError("Use HH:MM")
                wall_time.fromisoformat(value)
            if daily["start"] == daily["end"]:
                raise ValueError("Equal boundaries are ambiguous")
            left, right = daily_window_at(max(start, now), daily)
            if stop is not None and max(left, start) >= min(right, stop):
                raise ValueError("Deadline precedes the next window")
        except (TypeError, ValueError, ZoneInfoNotFoundError) as exc:
            raise JobError(
                "invalid_request", "Daily window or timezone is invalid.", status_code=400
            ) from exc
    return {
        "request_id": request,
        "scan_depth": depth,
        "start_epoch": start,
        "deadline_epoch": stop,
        "end_mode": payload["end_mode"],
        "daily_window": daily,
    }


class ScanScheduleService:
    def __init__(
        self,
        config_path: str | Path,
        *,
        engine: Any = None,
        spawn_daemon: bool = True,
        clock: Any = time.time,
    ):
        self.config_path = Path(config_path).resolve()
        self.engine = engine or ScanJobService(self.config_path)
        # A saved YAML is the scope: no project switch can retarget old plans.
        self.root = self.config_path.parent / ".zscope_jobs"
        self.root.mkdir(parents=True, exist_ok=True)
        suffix = hashlib.sha256(str(self.config_path).encode()).hexdigest()[:16]
        self.db_path = self.root / f"schedules-{suffix}.db"
        self.spawn_daemon = spawn_daemon
        self.clock = clock
        with self._db() as db:
            db.executescript(
                """CREATE TABLE IF NOT EXISTS schedules
                (id TEXT PRIMARY KEY, request_id TEXT UNIQUE, payload_hash TEXT, data TEXT);
                CREATE TABLE IF NOT EXISTS commands
                (request_id TEXT PRIMARY KEY, payload_hash TEXT, schedule_id TEXT);"""
            )

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _save(db: sqlite3.Connection, value: dict[str, Any]) -> None:
        db.execute(
            "UPDATE schedules SET data=? WHERE id=?", (json.dumps(value), value["schedule_id"])
        )

    @staticmethod
    def _public(value: dict[str, Any]) -> dict[str, Any]:
        return {
            key: item
            for key, item in value.items()
            if key not in {"pending_action", "input_revision"}
        }

    def ensure_coordinator(self) -> None:
        if not self.spawn_daemon:
            return
        identity_path = self.db_path.with_suffix(".owner.json")
        try:
            identity = json.loads(identity_path.read_text())
            if (
                identity.get("boot_id") == system_boot_id()
                and probe_process(
                    identity.get("pid"), expected_start_ticks=identity.get("start_ticks")
                )
                is True
            ):
                return
        except (OSError, ValueError, TypeError):
            pass
        with self.db_path.with_suffix(".log").open("ab") as log:
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "zscope.orchestration.jobs.schedule_runner",
                    "--config",
                    str(self.config_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

    @_envelope_errors
    def create(self, **payload: Any) -> ServiceResponse:
        now = self.clock()
        policy = validate_policy(payload, now)
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        # Resolve execution compatibility now and again at every actual launch.
        fingerprint = self.engine._fingerprint(scan_depth=policy["scan_depth"])
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM schedules WHERE request_id=?", (policy["request_id"],)
            ).fetchone()
            if row:
                if row["payload_hash"] != digest:
                    raise JobError(
                        "request_conflict",
                        "Request identity already has different schedule parameters.",
                        status_code=409,
                    )
                value = json.loads(row["data"])
            else:
                self.engine.require_semantics()
                value = {
                    "schedule_id": "schedule_" + uuid.uuid4().hex,
                    "revision": 1,
                    "status": "waiting",
                    "created_at": iso(now),
                    "config_path": str(self.config_path),
                    "scan_depth": policy["scan_depth"],
                    "start_at": iso(policy["start_epoch"]),
                    "end_mode": policy["end_mode"],
                    "stop_at": iso(policy["deadline_epoch"]),
                    "daily_window": policy["daily_window"],
                    "next_start_at": iso(policy["start_epoch"]),
                    "window_end_at": None,
                    "job_id": None,
                    "run_id": None,
                    "job_status": None,
                    "input_revision": fingerprint["sha256"],
                    "pending_action": None,
                    "last_window_start": None,
                    "error": None,
                    "stop_running_on_cancel": True,
                }
                if policy["daily_window"]:
                    left, _ = daily_window_at(
                        max(now, policy["start_epoch"]), policy["daily_window"]
                    )
                    value["next_start_at"] = iso(max(left, policy["start_epoch"]))
                db.execute(
                    "INSERT INTO schedules VALUES (?,?,?,?)",
                    (value["schedule_id"], policy["request_id"], digest, json.dumps(value)),
                )
        self.ensure_coordinator()
        return ServiceResponse(202, {"schema": SCHEMA, "schedule": self._public(value)})

    @_envelope_errors
    def list(self) -> ServiceResponse:
        with self._db() as db:
            values = [
                json.loads(row[0])
                for row in db.execute("SELECT data FROM schedules ORDER BY rowid DESC")
            ]
        if any(item["status"] in LIVE or item.get("cancel_pending") for item in values):
            self.ensure_coordinator()
        return ServiceResponse(
            200,
            {
                "schema": SCHEMA,
                "schedules": [self._public(item) for item in values],
                "capabilities": {"create": True, "persistent": True},
                "execution_note": "Resumes recoverable verified state; remaining-only execution is not guaranteed.",
            },
        )

    @_envelope_errors
    def cancel(
        self, schedule_id: str, *, base_revision: int, request_id: str, stop_running: bool = True
    ) -> ServiceResponse:
        validate_request_id(request_id)
        if (
            not isinstance(schedule_id, str)
            or not schedule_id
            or len(schedule_id) > 128
            or type(base_revision) is not int
            or base_revision < 1
            or type(stop_running) is not bool
        ):
            raise JobError(
                "invalid_request", "Schedule revision or stop_running is invalid.", status_code=400
            )
        digest = hashlib.sha256(
            json.dumps([schedule_id, base_revision, stop_running]).encode()
        ).hexdigest()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM commands WHERE request_id=?", (request_id,)).fetchone()
            row = db.execute("SELECT data FROM schedules WHERE id=?", (schedule_id,)).fetchone()
            if not row:
                raise JobError("not_found", "Schedule does not exist.", status_code=404)
            value = json.loads(row[0])
            if old and old["payload_hash"] != digest:
                raise JobError(
                    "request_conflict", "Cancellation request was reused.", status_code=409
                )
            if not old:
                if value["revision"] != base_revision:
                    raise JobError(
                        "revision_conflict",
                        "Schedule changed; refresh before cancellation.",
                        status_code=409,
                    )
                value.update(
                    status="cancelled",
                    revision=value["revision"] + 1,
                    next_start_at=None,
                    stop_running_on_cancel=stop_running,
                    cancel_pending=stop_running,
                )
                db.execute("INSERT INTO commands VALUES (?,?,?)", (request_id, digest, schedule_id))
                self._save(db, value)
        if stop_running:
            self.ensure_coordinator()
        return ServiceResponse(200, {"schema": SCHEMA, "schedule": self._public(value)})

    def tick(self) -> None:
        """One bounded pass; independent of HTTP requests and browser lifetime."""
        with self.db_path.with_suffix(".tick.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self._db() as db:
                values = [json.loads(row[0]) for row in db.execute("SELECT data FROM schedules")]
            for value in values:
                if value["status"] not in LIVE and not value.get("cancel_pending"):
                    continue
                try:
                    self._advance(value)
                except (JobError, OSError, ValueError, RuntimeError) as exc:
                    value.update(
                        status="cancelled" if value["status"] == "cancelled" else "blocked",
                        cancel_pending=False,
                        error={
                            "code": getattr(exc, "code", "schedule_unavailable"),
                            "message": str(exc),
                        },
                        next_start_at=None,
                    )
                with self._db() as db:
                    # A concurrent HTTP cancellation wins over an in-flight tick.
                    current = json.loads(
                        db.execute(
                            "SELECT data FROM schedules WHERE id=?", (value["schedule_id"],)
                        ).fetchone()[0]
                    )
                    previous = dict(current)
                    if current["status"] == "cancelled" and value["status"] != "cancelled":
                        for field in ("job_id", "run_id", "job_status", "pending_action"):
                            current[field] = value[field]
                        value = current
                    if value != previous:
                        value["revision"] = current["revision"] + 1
                        self._save(db, value)

    def _advance(self, value: dict[str, Any]) -> None:
        now = self.clock()
        job = None
        if value["job_id"]:
            response = self.engine.detail(value["job_id"])
            if response.status_code != 200:
                raise JobError(
                    "scheduled_job_unavailable", "The bound job cannot be read.", status_code=409
                )
            job = response.payload["job"]
            value["job_status"] = job["status"]
        if value.get("cancel_pending"):
            if not job and value.get("pending_action"):
                job = self.engine.registered_job(value["pending_action"]["request_id"])
                if job:
                    value.update(
                        job_id=job["job_id"], run_id=job["run_id"], job_status=job["status"]
                    )
            if (
                job
                and job["status"] in ACTIVE_STATUSES
                and job["run_id"] == value["run_id"]
                and job["input_revision"] == value["input_revision"]
            ):
                response = self.engine.cancel(
                    job["job_id"],
                    base_revision=job["revision"],
                    request_id=f"{value['schedule_id']}:cancel:{job['run_id']}",
                )
                if response.status_code >= 400:
                    return
                value["job_status"] = response.payload["job"]["status"]
            elif job and job["status"] in ACTIVE_STATUSES:
                value["error"] = {
                    "code": "schedule_job_changed",
                    "message": "Future windows cancelled; current run identity changed and was not stopped.",
                }
            value["cancel_pending"] = False
            return
        if (
            job
            and value["pending_action"] is None
            and (
                job["run_id"] != value["run_id"] or job["input_revision"] != value["input_revision"]
            )
        ):
            raise JobError(
                "schedule_job_changed",
                "The bound attempt or input changed outside this schedule.",
                status_code=409,
            )
        if job and (job.get("error") or {}).get("code") == "schedule_input_changed":
            raise JobError(
                "schedule_input_changed",
                "Inputs changed before scanner launch; review and create a new schedule.",
                status_code=409,
            )
        if job and job["status"] in ACTIVE_STATUSES:
            value.update(status="running", next_start_at=None)
            return
        if job and job["status"] == "completed":
            value.update(status="completed", next_start_at=None)
            return
        deadline = parse_stop_at(value["stop_at"]).timestamp() if value["stop_at"] else None
        if deadline is not None and now >= deadline:
            value.update(
                status="expired",
                next_start_at=None,
                error={
                    "code": "schedule_deadline_reached",
                    "message": "Schedule deadline reached; inspect actual job coverage.",
                },
            )
            return
        start = parse_stop_at(value["start_at"]).timestamp()
        if now < start:
            return
        if value["pending_action"] is None:
            left, right = (
                (start, deadline)
                if not value["daily_window"]
                else daily_window_at(now, value["daily_window"])
            )
            if left > now:
                value.update(status="waiting", next_start_at=iso(left))
                return
            if value["last_window_start"] == iso(left):
                if value["daily_window"]:
                    assert right is not None
                    following, _ = daily_window_at(right, value["daily_window"])
                    value.update(status="waiting", next_start_at=iso(following))
                else:
                    value.update(
                        status="blocked",
                        error={
                            "code": "scan_incomplete",
                            "message": "Scan stopped before completion; inspect and retry explicitly.",
                        },
                    )
                return
            stop = min(right, deadline) if right is not None and deadline is not None else right
            fingerprint = self.engine._fingerprint(scan_depth=value["scan_depth"])
            if fingerprint["sha256"] != value["input_revision"]:
                raise JobError(
                    "schedule_input_changed",
                    "Inputs changed since scheduling; create a new schedule.",
                    status_code=409,
                )
            action = {
                "request_id": f"{value['schedule_id']}:{hashlib.sha256(str(left).encode()).hexdigest()[:16]}",
                "expected_input_revision": value["input_revision"],
                "stop_at": iso(stop),
            }
            if job:
                if (
                    job["input_revision"] != value["input_revision"]
                    or job["run_id"] != value["run_id"]
                ):
                    raise JobError(
                        "schedule_job_changed",
                        "The job was resumed or rebound outside this schedule.",
                        status_code=409,
                    )
                action.update(job_id=job["job_id"], base_revision=job["revision"])
            else:
                action.update(scan_depth=value["scan_depth"], ignore_config_window=True)
            value.update(
                pending_action=action, window_end_at=iso(stop), last_window_start=iso(left)
            )
            with self._db() as db:
                db.execute("BEGIN IMMEDIATE")
                current = json.loads(
                    db.execute(
                        "SELECT data FROM schedules WHERE id=?", (value["schedule_id"],)
                    ).fetchone()[0]
                )
                if current["status"] == "cancelled":
                    value.update(current)
                    return
                self._save(db, value)  # durable replay reservation, before job launch
        action = value["pending_action"]
        registered = self.engine.registered_job(action["request_id"])
        if (
            registered is None
            and action["stop_at"]
            and parse_stop_at(action["stop_at"]).timestamp() <= now
        ):
            value.update(pending_action=None, status="waiting")
            return
        response = (
            ServiceResponse(202, {"job": registered})
            if registered is not None
            else (
                self.engine.resume(**action) if "job_id" in action else self.engine.start(**action)
            )
        )
        if response.status_code >= 400:
            code = response.payload.get("code", "schedule_launch_failed")
            if code == "project_scan_active":
                value.update(status="waiting")
                return
            raise JobError(
                code,
                response.payload.get("error", "Scheduled launch failed."),
                status_code=response.status_code,
            )
        job = response.payload["job"]
        value.update(
            job_id=job["job_id"],
            run_id=job["run_id"],
            job_status=job["status"],
            status="running",
            pending_action=None,
            next_start_at=None,
            error=None,
        )
