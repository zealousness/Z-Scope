"""ScanJobService: persistent job control plane matching the 2026-10-14 API contract.

Each method returns a :class:`ServiceResponse` whose ``payload`` is exactly the
contract envelope (``zscope.scan-jobs.v1``) and whose ``status_code`` the HTTP
layer forwards unchanged.  The service never executes the scan itself: it
spawns a detached owner process (``python -m zscope.orchestration.jobs``) and
reconciles the store against real process identity on every read.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
import os
import secrets
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

from ...reporting.json_io import read_report
from ..execution_profile import (
    PersistedStopWindow,
    closed_persisted_window_message,
    persisted_window_closed,
    resolve_saved_config_stop_window,
)
from .fingerprint import compute_input_fingerprint, diff_components
from .identity import probe_process, read_process_start_ticks, system_boot_id
from .models import (
    ACTIVE_STATUSES,
    EVENT_PAGE_SIZE,
    RESUMABLE_STATUSES,
    SCHEMA_VERSION,
    TERMINAL_STATUSES,
    JobError,
    build_error_field,
    deduce_owner_state,
    error_envelope,
    job_capabilities,
    null_coverage,
    null_progress,
    resolve_stop_time,
    utc_now_iso,
    validate_after_seq,
    validate_base_revision,
    validate_request_id,
    validate_scan_depth,
)
from .runner import ScanCommandBuilder, build_cli_command, write_launch_file
from .store import JobStore

logger = logging.getLogger(__name__)

STORE_DIR_NAME = ".zscope_jobs"
STORE_DB_NAME = "jobs.db"
_REPORT_CANDIDATE_NAMES = ("zscope_batch_report.json", "report.json")


@dataclass
class ServiceResponse:
    """HTTP-ready response: forward ``status_code`` and serialize ``payload``."""

    status_code: int
    payload: Dict[str, Any]


def _envelope_errors(func: Any) -> Any:
    """Map JobError onto its contract envelope; unexpected errors stay generic."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> ServiceResponse:
        try:
            return cast(ServiceResponse, func(*args, **kwargs))
        except JobError as exc:
            return ServiceResponse(exc.status_code, error_envelope(exc))
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("scan job service failure in %s", func.__name__)
            return ServiceResponse(
                500,
                {
                    "error": f"internal job service error ({type(exc).__name__})",
                    "code": "internal_error",
                },
            )

    return wrapper


class ScanJobService:
    """Control plane for persistent scan jobs of one saved config."""

    def __init__(
        self,
        config_path: str | Path,
        *,
        python_executable: Optional[str] = None,
        scan_command_builder: Optional[ScanCommandBuilder] = None,
        store_root: Optional[str | Path] = None,
        terminate_grace: float = 10.0,
        spawn_owner: bool = True,
    ) -> None:
        self.config_path = Path(config_path)
        self.python_executable = python_executable or sys.executable
        self.scan_command_builder = scan_command_builder or build_cli_command
        self.store_root_override = Path(store_root) if store_root is not None else None
        self.terminate_grace = max(0.5, float(terminate_grace))
        self.spawn_owner = spawn_owner
        self._locate_cache: Optional[Dict[str, Any]] = None
        self._locate_cache_key: Optional[Tuple[int, int]] = None

    # ------------------------------------------------------------------ config

    def _config_signature(self) -> Tuple[int, int]:
        try:
            stat = self.config_path.stat()
        except OSError as exc:
            raise JobError(
                "config_unavailable",
                f"saved config does not exist: {self.config_path}",
                status_code=503,
            ) from exc
        return (stat.st_mtime_ns, stat.st_size)

    def _fingerprint(self, *, scan_depth: Optional[str]) -> Dict[str, Any]:
        """Fresh input-binding fingerprint; never served from any cache.

        Every start/resume must re-verify the real source, header, build and
        tool inputs of this moment.  Only locating the project's store may use
        a cache keyed on the config file stat (see :meth:`_locate_fingerprint`);
        a config-stat hit never authorizes binding a new attempt to stale
        inputs.
        """

        return compute_input_fingerprint(self.config_path, scan_depth=scan_depth)

    def _locate_fingerprint(self) -> Dict[str, Any]:
        """Cacheable fingerprint used only to locate the project's store.

        The project root cannot move while the config bytes are unchanged, so
        the store location is safe to cache; the returned fingerprint must
        never be used as an attempt's input binding.
        """

        key = self._config_signature()
        if self._locate_cache is not None and key == self._locate_cache_key:
            return self._locate_cache
        fingerprint = compute_input_fingerprint(self.config_path, scan_depth=None)
        self._locate_cache = fingerprint
        self._locate_cache_key = self._config_signature()
        return fingerprint

    def _store(self, fingerprint: Optional[Dict[str, Any]] = None) -> JobStore:
        if self.store_root_override is not None:
            root = self.store_root_override
        else:
            fp = fingerprint or self._locate_fingerprint()
            root = Path(fp["project_root"]) / STORE_DIR_NAME
        return JobStore(root / STORE_DB_NAME)

    def _store_and_fingerprint(
        self, *, scan_depth: Optional[str] = None
    ) -> Tuple[JobStore, Dict[str, Any]]:
        fingerprint = self._fingerprint(scan_depth=scan_depth)
        return self._store(fingerprint), fingerprint

    def _config_stop_window(self) -> Optional[PersistedStopWindow]:
        """Resolve the saved config's stop window once for this start.

        The fingerprint above already loaded the saved config; this single
        additional read resolves the boundary whose instant this start
        persists (v3 documents with ``execution.stop_at`` only — v2 and
        window-less documents return ``None`` and keep the current
        behaviour).  The window is resolved once per job creation; the owner
        and request replays only ever read the persisted row.

        A boundary whose instant already passed is refused here: the job
        would be accepted (202) and then stop before any work, which is the
        same silent, useless run the CLI refuses for the same config.  An
        explicit request window is untouched — it is the caller's own
        statement, not the saved config's default.
        """

        try:
            window = resolve_saved_config_stop_window(self.config_path)
        except ValueError as exc:
            raise JobError(
                "stop_window_unresolvable",
                "the saved config's execution.stop_at boundary cannot be "
                f"resolved for this start: {exc}",
                status_code=400,
            ) from exc
        if window is not None and persisted_window_closed(window):
            raise JobError(
                "stop_window_closed",
                closed_persisted_window_message(window),
                status_code=400,
                details={
                    "requested_stop_at": window.requested_stop_at,
                    "resolved_stop_time_local": window.resolved_local,
                    "stop_at_epoch": window.stop_at_epoch,
                },
            )
        return window

    def _locate_store(self) -> JobStore:
        """Store handle for read paths; store *locating* may reuse the cache."""

        return self._store(self._locate_fingerprint())

    # ------------------------------------------------------------------ serialize

    @staticmethod
    def _owner_state(job: Dict[str, Any]) -> Dict[str, Any]:
        pid = job.get("owner_pid")
        probe = probe_process(
            int(pid) if isinstance(pid, int) else None,
            expected_start_ticks=job.get("owner_start_ticks"),
        )
        state = deduce_owner_state(probe_result=probe, job_status=str(job.get("status") or ""))
        return {"state": state, "process_id": pid if isinstance(pid, int) else None}

    def _serialize_job(self, job: Dict[str, Any]) -> Dict[str, Any]:
        report = dict(job.get("report_json") or {})
        artifacts: List[Dict[str, Any]] = []
        for artifact in job.get("artifacts_json") or []:
            if not isinstance(artifact, dict):
                continue
            path = artifact.get("path")
            status = artifact.get("status")
            if isinstance(path, str) and path:
                status = "available" if Path(path).is_file() else "missing"
            artifacts.append(
                {
                    "kind": artifact.get("kind"),
                    "path": path,
                    "status": status or "missing",
                }
            )
        progress = dict(null_progress())
        stored_progress = job.get("progress_json") or {}
        for key in progress:
            if key in stored_progress:
                progress[key] = stored_progress[key]
        coverage = dict(null_coverage())
        stored_coverage = job.get("coverage_json") or {}
        for key in coverage:
            if key in stored_coverage and stored_coverage[key] is not None:
                coverage[key] = stored_coverage[key]
        return {
            "job_id": job["job_id"],
            "run_id": job["run_id"],
            "revision": int(job["revision"]),
            "input_revision": job.get("input_revision"),
            "status": job["status"],
            "phase": job.get("phase"),
            "created_at": job.get("created_at"),
            "started_at": job.get("started_at"),
            "updated_at": job.get("updated_at"),
            "resolved_stop_time": job.get("resolved_stop_time"),
            "owner": self._owner_state(job),
            "progress": progress,
            "coverage": coverage,
            "pending_count": job.get("pending_count"),
            "questions": list(job.get("questions_json") or []),
            "report": {
                "available": bool(report.get("available")),
                "report_id": report.get("report_id"),
                "path": report.get("path"),
            },
            "artifacts": artifacts,
            "capabilities": job_capabilities(str(job["status"])),
            "error": build_error_field(job.get("error_code"), job.get("error_message")),
        }

    # ------------------------------------------------------------------ reconcile

    def _reconcile(self, store: JobStore, job: Dict[str, Any]) -> Dict[str, Any]:
        """Mark owners that verifiably died mid-flight as lost; reap orphans."""

        if job["status"] not in ACTIVE_STATUSES:
            return job
        pid = job.get("owner_pid")
        probe = probe_process(
            int(pid) if isinstance(pid, int) else None,
            expected_start_ticks=job.get("owner_start_ticks"),
        )
        if probe is not False:
            return job
        # The owner is verifiably gone (dead or PID recycled) while the job is
        # active: it can never legitimately complete from here.
        scanner_state = self._reap_orphan_scanner(job)
        try:
            updated = store.update_job(
                job["job_id"],
                expected_revision=int(job["revision"]),
                updates={
                    "status": "lost",
                    "phase": None,
                    "error_code": "owner_lost",
                    "error_message": (
                        "owner process is gone without a terminal record; "
                        f"orphan scanner: {scanner_state}"
                    ),
                },
            )
        except JobError as exc:
            if exc.code == "revision_conflict":
                refreshed = store.get_job(job["job_id"])
                return refreshed if refreshed is not None else job
            raise
        store.finish_attempt(
            job["job_id"],
            job["run_id"],
            {
                "status": "lost",
                "ended_at": utc_now_iso(),
                "error_code": "owner_lost",
                "error_message": "owner process is gone without a terminal record",
            },
        )
        store.append_event(
            job["job_id"],
            run_id=job["run_id"],
            kind="owner_lost",
            message="owner process vanished; job marked lost (never completed)",
            data={"owner_pid": job.get("owner_pid"), "scanner": scanner_state},
        )
        return updated

    def _reap_orphan_scanner(self, job: Dict[str, Any]) -> str:
        """Bounded-kill an orphaned scanner group, only with verified identity."""

        pid = job.get("scanner_pid")
        if not isinstance(pid, int) or pid <= 0:
            return "none_recorded"
        probe = probe_process(pid, expected_start_ticks=job.get("scanner_start_ticks"))
        if probe is not True:
            return "not_running" if probe is False else "unverifiable"
        if os.name != "posix":
            return "unverifiable"
        import signal
        import time

        try:
            os.killpg(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            return "not_running"
        deadline = time.monotonic() + self.terminate_grace
        while time.monotonic() < deadline:
            if probe_process(pid, expected_start_ticks=job.get("scanner_start_ticks")) is not True:
                return "reaped"
            time.sleep(0.1)
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        time.sleep(0.2)
        if probe_process(pid, expected_start_ticks=job.get("scanner_start_ticks")) is not True:
            return "reaped"
        return "kill_failed"

    def _load_job_or_404(self, store: JobStore, job_id: str) -> Dict[str, Any]:
        if not isinstance(job_id, str) or not job_id.strip():
            raise JobError("invalid_request", "job_id is required", status_code=400)
        job = store.get_job(job_id.strip())
        if job is None:
            raise JobError(
                "job_not_found",
                f"unknown job_id {job_id!r}",
                status_code=404,
                details={"job_id": job_id},
            )
        return job

    # ------------------------------------------------------------------ idempotency

    @staticmethod
    def _payload_hash(endpoint: str, payload: Dict[str, Any]) -> str:
        canonical = json.dumps(
            {"endpoint": endpoint, "payload": payload}, sort_keys=True, default=str
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _registered_replay(
        self,
        store: JobStore,
        job_id: str,
        *,
        request_id: str,
        endpoint: str,
    ) -> Dict[str, Any]:
        """Serve an already-registered marker: the same job, no new attempt.

        A replay never re-authorizes inputs and never starts work; it
        re-reads the bound job's current state and records the replay in the
        event log so replays stay distinguishable from new attempts.
        """

        job = store.get_job(job_id)
        if job is None:
            raise JobError(
                "job_not_found",
                f"request {request_id!r} is bound to unknown job {job_id!r}",
                status_code=404,
                details={"job_id": job_id},
            )
        store.append_event(
            job_id,
            run_id=str(job["run_id"]),
            kind="request_replayed",
            message=f"duplicate {endpoint} request replayed its registered job",
            data={"request_id": request_id, "endpoint": endpoint},
        )
        return job

    def _fast_replay_or_none(
        self,
        store: JobStore,
        *,
        request_id: str,
        endpoint: str,
        payload_hash: str,
    ) -> Optional[Dict[str, Any]]:
        """Serve a registered marker before any action-side effect.

        This is a plain-read fast path for the common replay/conflict case;
        the transactional reservation methods remain the authority when a
        marker appears concurrently.
        """

        existing = store.get_request(request_id)
        if existing is None:
            return None
        if existing["endpoint"] != endpoint or existing["payload_hash"] != payload_hash:
            raise JobError(
                "request_id_conflict",
                "request_id was already used with a different request",
                status_code=409,
                details={"request_id": request_id},
            )
        return self._registered_replay(
            store, str(existing["job_id"]), request_id=request_id, endpoint=endpoint
        )

    # ------------------------------------------------------------------ spawning

    def _spawn_owner(
        self,
        *,
        store: JobStore,
        job: Dict[str, Any],
        run_dir: Path,
        launch_path: Path,
    ) -> None:
        owner_log = run_dir / "owner.log"
        argv = [
            self.python_executable,
            "-m",
            "zscope.orchestration.jobs",
            "--job-id",
            job["job_id"],
            "--run-id",
            job["run_id"],
            "--store",
            str(store.db_path),
            "--run-dir",
            str(run_dir),
            "--launch",
            str(launch_path),
            "--terminate-grace",
            str(self.terminate_grace),
        ]
        env = dict(os.environ)
        env["ZSCOPE_JOB_OWNER_TOKEN"] = str(job["owner_token"])
        try:
            log_handle = open(owner_log, "ab", buffering=0)
        except OSError as exc:
            raise JobError(
                "owner_spawn_failed",
                f"cannot open owner log {owner_log}: {exc}",
                status_code=503,
            ) from exc
        try:
            popen_kwargs: Dict[str, Any] = {
                "stdin": subprocess.DEVNULL,
                "stdout": log_handle,
                "stderr": subprocess.STDOUT,
            }
            if os.name == "posix":
                popen_kwargs["start_new_session"] = True
            else:  # pragma: no cover - windows fallback
                popen_kwargs["creationflags"] = getattr(
                    subprocess, "CREATE_NO_WINDOW", 0
                ) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            process = subprocess.Popen(argv, env=env, **popen_kwargs)
        except OSError as exc:
            raise JobError(
                "owner_spawn_failed",
                f"cannot start the detached owner process: {exc}",
                status_code=503,
            ) from exc
        finally:
            try:
                log_handle.close()
            except Exception:
                pass
        # Record the precise startup identity at spawn time.  An owner that
        # dies — or whose PID gets recycled — before publishing its own
        # identity stays verifiable by reconcile; a bare PID never is.  A
        # concurrent terminal transition (e.g. cancel of a never-launched
        # queued job) skips the recording: the owner itself stands down at
        # row verification.
        for _ in range(5):
            try:
                store.update_job(
                    job["job_id"],
                    expected_revision=int(job["revision"]),
                    updates={
                        "owner_pid": process.pid,
                        "owner_start_ticks": read_process_start_ticks(process.pid),
                        "owner_boot_id": system_boot_id(),
                    },
                )
                break
            except JobError as exc:
                if exc.code != "revision_conflict":
                    raise
                current = store.get_job(str(job["job_id"]))
                if current is None:
                    break
                if (
                    current.get("run_id") != job["run_id"]
                    or current.get("status") in TERMINAL_STATUSES
                ):
                    break
                job = current
        else:
            raise JobError(
                "store_conflict",
                "could not record the spawned owner identity after retries",
                status_code=503,
            )
        store.append_event(
            job["job_id"],
            run_id=job["run_id"],
            kind="owner_spawned",
            message=f"owner process spawned (pid={process.pid})",
            data={"pid": process.pid},
        )

    def _new_job_fields(
        self,
        fingerprint: Dict[str, Any],
        *,
        job_id: str,
        run_id: str,
        owner_token: str,
        scan_depth: Optional[str],
        stop_at_epoch: Optional[float],
        resolved_stop_time: Optional[str],
        requested_stop_at: Optional[str],
        run_dir: str,
    ) -> Dict[str, Any]:
        now = utc_now_iso()
        return {
            "job_id": job_id,
            "run_id": run_id,
            "revision": 1,
            "input_revision": fingerprint["sha256"],
            "status": "queued",
            "phase": "queued",
            "created_at": now,
            "updated_at": now,
            "requested_stop_at": requested_stop_at,
            "resolved_stop_time": resolved_stop_time,
            "stop_at_epoch": stop_at_epoch,
            "scan_depth": scan_depth,
            "config_path": str(self.config_path.resolve()),
            "config_sha256": fingerprint["config_sha256"],
            "project_root": fingerprint["project_root"],
            "project_id": fingerprint["project_id"],
            "working_directory": str(Path.cwd()),
            "run_dir": run_dir,
            "owner_token": owner_token,
            "input_components_json": fingerprint["components"],
            "progress_json": null_progress(),
            "coverage_json": null_coverage(),
            "report_json": {"available": False, "report_id": None, "path": None},
        }

    def _rearm_updates(
        self,
        fingerprint: Dict[str, Any],
        *,
        run_id: str,
        owner_token: str,
        scan_depth: Optional[str],
        run_dir: str,
    ) -> Dict[str, Any]:
        return {
            "run_id": run_id,
            "input_revision": fingerprint["sha256"],
            "input_components_json": fingerprint["components"],
            "status": "queued",
            "phase": "queued",
            "owner_token": owner_token,
            "owner_pid": None,
            "owner_start_ticks": None,
            "owner_boot_id": None,
            "owner_heartbeat_at": None,
            "scanner_pid": None,
            "scanner_start_ticks": None,
            "cancel_requested_at": None,
            "started_at": None,
            # Windows are per-attempt; the old window is not carried over.
            "requested_stop_at": None,
            "resolved_stop_time": None,
            "stop_at_epoch": None,
            "scan_depth": scan_depth,
            "config_sha256": fingerprint["config_sha256"],
            "run_dir": run_dir,
            "progress_json": null_progress(),
            "coverage_json": null_coverage(),
            "questions_json": [],
            "pending_count": None,
            "report_json": {"available": False, "report_id": None, "path": None},
            "artifacts_json": [],
            "error_code": None,
            "error_message": None,
        }

    def _launch_attempt(
        self,
        *,
        store: JobStore,
        job: Dict[str, Any],
        fingerprint: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Launch-side effects for an already-reserved job row.

        The durable reservation (job row + request marker) committed before
        this runs, so a duplicate request can only replay — never
        double-launch.  A real spawn failure persists the honest failed
        terminal state and surfaces its 503.
        """

        run_dir = Path(job["run_dir"])
        run_dir.mkdir(parents=True, exist_ok=True)
        argv = self.scan_command_builder(
            self.config_path, job.get("scan_depth"), self.python_executable
        )
        report_candidates = [
            str(Path(fingerprint["project_root"]) / name) for name in _REPORT_CANDIDATE_NAMES
        ]
        launch_path = run_dir / "launch.json"
        write_launch_file(
            launch_path,
            job_id=str(job["job_id"]),
            run_id=str(job["run_id"]),
            owner_token=str(job["owner_token"]),
            argv=argv,
            cwd=str(Path.cwd()),
            report_candidates=report_candidates,
            stop_at_epoch=job.get("stop_at_epoch"),
            resolved_stop_time=job.get("resolved_stop_time"),
        )
        if not self.spawn_owner:
            return job
        try:
            self._spawn_owner(store=store, job=job, run_dir=run_dir, launch_path=launch_path)
        except JobError as exc:
            self._mark_spawn_failure(store, job, exc)
            raise JobError(exc.code, exc.message, status_code=exc.status_code) from exc
        return store.get_job(str(job["job_id"])) or job

    def _mark_spawn_failure(self, store: JobStore, job: Dict[str, Any], exc: JobError) -> None:
        """Persist the honest failed terminal state when the owner cannot spawn."""

        last_conflict: Optional[JobError] = None
        for _ in range(5):
            current = store.get_job(str(job["job_id"]))
            if current is None or current.get("run_id") != job["run_id"]:
                return
            if current.get("status") in TERMINAL_STATUSES:
                # Someone else already resolved this job (e.g. cancel of the
                # never-launched attempt); their outcome stands.
                return
            try:
                store.update_job(
                    str(job["job_id"]),
                    expected_revision=int(current["revision"]),
                    updates={
                        "status": "failed",
                        "phase": None,
                        "error_code": exc.code,
                        "error_message": exc.message,
                    },
                )
            except JobError as conflict:
                if conflict.code != "revision_conflict":
                    raise
                last_conflict = conflict
                time.sleep(0.1)
                continue
            store.finish_attempt(
                str(job["job_id"]),
                str(job["run_id"]),
                {
                    "status": "failed",
                    "ended_at": utc_now_iso(),
                    "error_code": exc.code,
                    "error_message": exc.message,
                },
            )
            store.append_event(
                str(job["job_id"]),
                run_id=str(job["run_id"]),
                kind="job_terminal",
                message=f"job failed: {exc.code}",
                data={"status": "failed", "error_code": exc.code},
            )
            return
        if last_conflict is not None:
            raise last_conflict

    # ------------------------------------------------------------------ API: start

    @_envelope_errors
    def start(
        self,
        *,
        scan_depth: Optional[str] = None,
        stop_at: Optional[str] = None,
        request_id: str,
    ) -> ServiceResponse:
        """POST /api/jobs — create a job and spawn its detached owner.

        The request marker and the job row commit atomically *before* any
        launch side effect, so a duplicate request (same endpoint and
        payload) replays the same job across service instances, processes
        and restarts instead of starting a second owner — even after the
        first job reached a terminal state.

        When the request carries no explicit ``stop_at`` and the saved
        config is a v3 document with ``execution.stop_at``, that boundary is
        resolved once and persisted as this job's stop window (the existing
        owner/scheduler chain enforces it); an explicit, non-empty request
        ``stop_at`` wins.  v2 and window-less documents keep the current
        window-less behaviour.
        """

        depth = validate_scan_depth(scan_depth)
        request_id = validate_request_id(request_id)
        resolved_stop_time, stop_at_epoch = resolve_stop_time(stop_at)
        store, fingerprint = self._store_and_fingerprint(scan_depth=depth)
        store.initialize()
        payload_hash = self._payload_hash("start", {"scan_depth": depth, "stop_at": stop_at})
        # Serve a registered marker before resolving any config stop window:
        # a retry of an accepted request replays the original job with its
        # original window even when the saved config boundary would now
        # resolve to a different day (or fail to resolve at all).
        fast = self._fast_replay_or_none(
            store, request_id=request_id, endpoint="start", payload_hash=payload_hash
        )
        if fast is not None:
            return ServiceResponse(
                202, {"schema": SCHEMA_VERSION, "job": self._serialize_job(fast)}
            )
        stop_at_source = "request"
        config_window = self._config_stop_window() if stop_at is None else None
        if config_window is not None:
            resolved_stop_time = config_window.resolved_stop_time
            stop_at_epoch = config_window.stop_at_epoch
            stop_at = config_window.requested_stop_at
            stop_at_source = config_window.source
        for existing in store.list_jobs():
            if existing["status"] in ACTIVE_STATUSES:
                self._reconcile(store, existing)
        job_id = f"job_{uuid.uuid4().hex}"
        run_id = f"run_{uuid.uuid4().hex}"
        owner_token = secrets.token_hex(16)
        reservation = store.create_job_with_request(
            fields=self._new_job_fields(
                fingerprint,
                job_id=job_id,
                run_id=run_id,
                owner_token=owner_token,
                scan_depth=depth,
                stop_at_epoch=stop_at_epoch,
                resolved_stop_time=resolved_stop_time,
                requested_stop_at=stop_at,
                run_dir=str(store.db_path.parent / job_id / run_id),
            ),
            request_id=request_id,
            endpoint="start",
            payload_hash=payload_hash,
        )
        if not reservation.created:
            replayed = self._registered_replay(
                store, reservation.job_id, request_id=request_id, endpoint="start"
            )
            return ServiceResponse(
                202, {"schema": SCHEMA_VERSION, "job": self._serialize_job(replayed)}
            )
        job = reservation.job
        assert job is not None
        store.append_event(
            job_id,
            run_id=run_id,
            kind="job_created",
            message="job created from the saved config",
            data={
                "job_id": job_id,
                "scan_depth": depth,
                "resolved_stop_time": resolved_stop_time,
                "input_revision": fingerprint["sha256"],
                "request_id": request_id,
                "stop_at_source": stop_at_source,
                **(
                    {
                        "stop_at_local": config_window.stop_at,
                        "stop_at_timezone": config_window.timezone,
                        "resolved_stop_time_local": config_window.resolved_local,
                    }
                    if config_window is not None
                    else {}
                ),
            },
        )
        job = self._launch_attempt(store=store, job=job, fingerprint=fingerprint)
        return ServiceResponse(202, {"schema": SCHEMA_VERSION, "job": self._serialize_job(job)})

    # ------------------------------------------------------------------ API: list

    @_envelope_errors
    def list(self) -> ServiceResponse:
        """GET /api/jobs — jobs of the project owning the saved config."""

        store = self._locate_store()
        store.initialize()
        jobs: List[Dict[str, Any]] = []
        latest_job_id: Optional[str] = None
        create_blocked: Optional[Dict[str, Any]] = None
        for job in store.list_jobs():
            if job["status"] in ACTIVE_STATUSES:
                job = self._reconcile(store, job)
            if job["status"] in ACTIVE_STATUSES and create_blocked is None:
                create_blocked = {"job_id": job["job_id"], "status": job["status"]}
            latest_job_id = job["job_id"]
            jobs.append(self._serialize_job(job))
        reasons: List[Dict[str, str]] = []
        if create_blocked is not None:
            reasons.append(
                {
                    "code": "project_scan_active",
                    "message": "another scan job is already active for this project",
                }
            )
        return ServiceResponse(
            200,
            {
                "schema": SCHEMA_VERSION,
                "jobs": jobs,
                "latest_job_id": latest_job_id,
                "capabilities": {"create": create_blocked is None, "reasons": reasons},
            },
        )

    # ------------------------------------------------------------------ API: detail

    @_envelope_errors
    def detail(self, job_id: str) -> ServiceResponse:
        """GET /api/jobs/detail."""

        store = self._locate_store()
        store.initialize()
        job = self._load_job_or_404(store, job_id)
        job = self._reconcile(store, job)
        return ServiceResponse(200, {"schema": SCHEMA_VERSION, "job": self._serialize_job(job)})

    # ------------------------------------------------------------------ API: events

    @_envelope_errors
    def events(self, job_id: str, after_seq: int) -> ServiceResponse:
        """GET /api/jobs/events?job_id&after_seq."""

        after_seq = validate_after_seq(after_seq)
        store = self._locate_store()
        store.initialize()
        job = self._load_job_or_404(store, job_id)
        job = self._reconcile(store, job)
        items, has_more = store.list_events(
            job["job_id"], after_seq=after_seq, limit=EVENT_PAGE_SIZE
        )
        next_seq = items[-1]["seq"] if items else after_seq
        return ServiceResponse(
            200,
            {
                "schema": SCHEMA_VERSION,
                "job_id": job["job_id"],
                "events": items,
                "next_seq": next_seq,
                "has_more": has_more,
            },
        )

    # ------------------------------------------------------------------ API: cancel

    @_envelope_errors
    def cancel(self, job_id: str, *, base_revision: int, request_id: str) -> ServiceResponse:
        """POST /api/jobs/cancel — flag the job; the owner stops its own group.

        The marker and the cancel action commit in one transaction: a
        duplicate cancels nothing (it replays the recorded outcome), and a
        conflicting key cancels nothing at all.  A queued job whose owner was
        never spawned is finalized to ``cancelled`` — nothing else would
        ever observe the flag.
        """

        request_id = validate_request_id(request_id)
        base_revision = validate_base_revision(base_revision)
        store = self._locate_store()
        store.initialize()
        payload_hash = self._payload_hash(
            "cancel", {"job_id": job_id, "base_revision": base_revision}
        )
        fast = self._fast_replay_or_none(
            store, request_id=request_id, endpoint="cancel", payload_hash=payload_hash
        )
        if fast is not None:
            return ServiceResponse(
                200, {"schema": SCHEMA_VERSION, "job": self._serialize_job(fast)}
            )
        reservation = store.cancel_with_request(
            job_id=job_id,
            expected_revision=base_revision,
            request_id=request_id,
            endpoint="cancel",
            payload_hash=payload_hash,
        )
        job = reservation.job
        assert job is not None
        return ServiceResponse(200, {"schema": SCHEMA_VERSION, "job": self._serialize_job(job)})

    # ------------------------------------------------------------------ API: resume

    @_envelope_errors
    def resume(self, job_id: str, *, base_revision: int, request_id: str) -> ServiceResponse:
        """POST /api/jobs/resume — new run_id; old attempt results stay bound.

        The marker, the status/revision guard and the attempt re-arm commit
        in one transaction before any launch side effect: duplicates replay
        the armed attempt, conflicting keys start nothing, and a stale
        base_revision can never arm a second attempt.  ``stop_at`` windows
        are per-attempt: a resumed attempt starts without the expired
        window (start a new job for a new window).
        """

        request_id = validate_request_id(request_id)
        base_revision = validate_base_revision(base_revision)
        store = self._locate_store()
        store.initialize()
        payload_hash = self._payload_hash(
            "resume", {"job_id": job_id, "base_revision": base_revision}
        )
        fast = self._fast_replay_or_none(
            store, request_id=request_id, endpoint="resume", payload_hash=payload_hash
        )
        if fast is not None:
            return ServiceResponse(
                202, {"schema": SCHEMA_VERSION, "job": self._serialize_job(fast)}
            )
        job = self._load_job_or_404(store, job_id)
        job = self._reconcile(store, job)
        depth = job.get("scan_depth") or None
        fingerprint = self._fingerprint(scan_depth=depth)
        previous_revision = str(job.get("input_revision") or "")
        changed: List[str] = []
        if previous_revision and previous_revision != fingerprint["sha256"]:
            old_components = job.get("input_components_json") or {}
            if not isinstance(old_components, dict):
                old_components = {}
            changed = diff_components(old_components, fingerprint["components"])
        orphan = self._reap_orphan_scanner(job)
        if orphan == "kill_failed":
            raise JobError(
                "scanner_still_running",
                "a previous scanner process is still alive and could not be "
                "stopped; refusing to start a duplicate attempt",
                status_code=409,
                details={"scanner_pid": job.get("scanner_pid")},
            )
        run_id = f"run_{uuid.uuid4().hex}"
        owner_token = secrets.token_hex(16)
        reservation = store.arm_attempt_with_request(
            job_id=str(job["job_id"]),
            expected_revision=base_revision,
            from_statuses=tuple(RESUMABLE_STATUSES),
            updates=self._rearm_updates(
                fingerprint,
                run_id=run_id,
                owner_token=owner_token,
                scan_depth=depth,
                run_dir=str(store.db_path.parent / job["job_id"] / run_id),
            ),
            request_id=request_id,
            endpoint="resume",
            payload_hash=payload_hash,
        )
        if not reservation.created:
            replayed = self._registered_replay(
                store, reservation.job_id, request_id=request_id, endpoint="resume"
            )
            return ServiceResponse(
                202, {"schema": SCHEMA_VERSION, "job": self._serialize_job(replayed)}
            )
        armed = reservation.job
        assert armed is not None
        if changed:
            store.append_event(
                str(job["job_id"]),
                run_id=str(job["run_id"]),
                kind="input_revoked",
                message=(
                    "inputs changed since the previous attempt; its report and "
                    "confirmations stay revoked and the new attempt re-verifies"
                ),
                data={
                    "components": changed,
                    "previous": previous_revision,
                    "current": fingerprint["sha256"],
                },
            )
        store.append_event(
            str(job["job_id"]),
            run_id=run_id,
            kind="attempt_started",
            message=f"new attempt {run_id} started",
            data={"run_id": run_id, "input_revision": fingerprint["sha256"]},
        )
        updated = self._launch_attempt(store=store, job=armed, fingerprint=fingerprint)
        return ServiceResponse(202, {"schema": SCHEMA_VERSION, "job": self._serialize_job(updated)})

    # ------------------------------------------------------------------ API: result

    @_envelope_errors
    def result(self, job_id: str) -> ServiceResponse:
        """GET /api/jobs/result — report binding of the *current* attempt."""

        store = self._locate_store()
        store.initialize()
        job = self._load_job_or_404(store, job_id)
        job = self._reconcile(store, job)
        serialized = self._serialize_job(job)
        report = serialized["report"]
        report_available = bool(report.get("available"))
        report_id = report.get("report_id")
        reason: Optional[str] = None
        if report_available:
            reason = self._verify_report_artifact(job)
            if reason is not None:
                report_available = False
                report_id = None
        else:
            stored_reason = (job.get("report_json") or {}).get("reason")
            if isinstance(stored_reason, str) and stored_reason:
                reason = stored_reason
            elif job["status"] in ACTIVE_STATUSES:
                reason = f"job_status:{job['status']}"
            else:
                reason = "report_not_produced"
        return ServiceResponse(
            200,
            {
                "schema": SCHEMA_VERSION,
                "job_id": job["job_id"],
                "report_id": report_id,
                "report_available": report_available,
                "reason": reason,
                # The coordinator wires the existing lightweight findings
                # projection onto the bound snapshot (load_bound_report);
                # this branch does not re-implement that projection.
                "findings": None,
                "coverage": serialized["coverage"],
                "questions": serialized["questions"],
                "artifacts": serialized["artifacts"],
            },
        )

    def _read_bound_report(
        self, job: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Re-verify and decode the bound snapshot.

        Returns ``(parsed_report, reason)``.  ``parsed_report`` is the logical
        report decoded through the formal reader (``read_report`` /
        ``decode_storage``) — never the raw ``zscope.shared-json.v1`` storage
        envelope.  ``reason`` is None when the artifact is intact and
        decodable, otherwise a contract reason string.
        """

        report = job.get("report_json") or {}
        path = report.get("path")
        expected = report.get("report_id")
        if not isinstance(path, str) or not path:
            return None, "report_artifact_missing"
        target = Path(path)
        if not target.is_file():
            return None, "report_artifact_missing"
        try:
            raw = target.read_bytes()
        except OSError:
            return None, "report_artifact_missing"
        if isinstance(expected, str) and expected:
            digest = hashlib.sha256(raw).hexdigest()
            if digest != expected:
                return None, "report_artifact_mismatch"
        try:
            parsed = read_report(target)
        except (OSError, ValueError, RuntimeError):
            # A missing object reference, a wrong object digest or any other
            # undecodable graph is rejected, not served.
            return None, "report_artifact_corrupt"
        if not isinstance(parsed, dict):
            return None, "report_artifact_corrupt"
        return parsed, None

    def _verify_report_artifact(self, job: Dict[str, Any]) -> Optional[str]:
        """Re-hash and re-decode the bound snapshot; damage revokes availability."""

        _, reason = self._read_bound_report(job)
        return reason

    def load_bound_report(self, job_id: str) -> Optional[Tuple[Dict[str, Any], Path]]:
        """Return the parsed report bound to the current attempt, if intact.

        This is the coordinator's wiring point for the lightweight findings
        projection: it must read this per-attempt snapshot (decoded through
        the formal shared-JSON reader) and never the live ``report.json`` in
        the project root.
        """

        store = self._locate_store()
        store.initialize()
        job = self._load_job_or_404(store, job_id)
        report = job.get("report_json") or {}
        path = report.get("path")
        if not isinstance(path, str) or not path:
            return None
        parsed, reason = self._read_bound_report(job)
        if parsed is None:
            return None
        return parsed, Path(path)
