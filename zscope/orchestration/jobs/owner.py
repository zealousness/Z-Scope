"""Detached owner process for one scan job attempt.

The owner is spawned by :class:`zscope.orchestration.jobs.service.ScanJobService`
and outlives the UI/service that started it.  It owns the scanner child
process group, persists every meaningful state change to the job store (the
single source of truth), enforces cancel requests and the ``stop_at`` window
with bounded group termination, and binds the report produced by *this*
attempt — an unchanged pre-existing report in the project root is never
reused as this attempt's result.

Window enforcement is cooperative first: the owner passes the attempt
identifiers to the scanner through the ``ZSCOPE_JOB_*`` environment (see
:mod:`zscope.orchestration.jobs.scheduler_hook`), a session scheduler bound
to the same store observes the window/cancel flags and stops claiming new
work on its own, and only a scanner that keeps running past
``window_grace`` past the deadline is terminated at process granularity.
The watchdog is the bounded backstop of cooperative finalization, not the
primary stop mechanism.

Run as ``python -m zscope.orchestration.jobs`` (see ``__main__.py``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...reporting.json_io import read_report
from .fingerprint import compute_input_fingerprint, diff_components
from .identity import self_start_ticks, system_boot_id
from .models import (
    LAUNCH_SCHEMA_VERSION,
    OWNER_HEARTBEAT_SCHEMA,
    PHASE_FINALIZING,
    PHASE_LAUNCHING,
    PHASE_SCANNING,
    PHASE_STOPPING,
    TERMINAL_STATUSES,
    epoch_to_iso,
    merge_coverage,
    extract_questions,
    report_completeness_is_partial,
    utc_now_iso,
)
from .runner import terminate_process_group
from .scheduler_hook import (
    JOB_ENV_JOB_ID,
    JOB_ENV_OWNER_TOKEN,
    JOB_ENV_RUN_DIR,
    JOB_ENV_RUN_ID,
    JOB_ENV_STORE,
)
from .store import JobStore
from .work_queue import read_bound_queue_counts

_REPORT_MARKDOWN_CANDIDATES = ("zscope_batch_report.md", "report.md")


class _OwnerFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class Owner:
    def __init__(
        self,
        *,
        store: JobStore,
        job_id: str,
        run_id: str,
        run_dir: Path,
        launch_path: Path,
        token: str,
        heartbeat_interval: float = 1.0,
        terminate_grace: float = 10.0,
        window_finalize_grace: float = 10.0,
        cancel_finalize_grace: float = 2.0,
    ) -> None:
        self.store = store
        self.job_id = job_id
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.launch_path = Path(launch_path)
        self.token = token
        self.heartbeat_interval = max(0.2, heartbeat_interval)
        self.terminate_grace = max(0.5, terminate_grace)
        # Cooperative bounds: how long the session gets to stop itself at the
        # deadline / after a cancel before the process-group watchdog fires.
        self.window_finalize_grace = max(0.0, window_finalize_grace)
        self.cancel_finalize_grace = max(0.0, cancel_finalize_grace)
        self.launch: Dict[str, Any] = {}
        self.job: Dict[str, Any] = {}
        self.artifacts: List[Dict[str, Any]] = []
        self._stop_signal: Optional[int] = None
        self._scanner: Optional[subprocess.Popen[bytes]] = None
        self._last_heartbeat = 0.0

    # -- helpers -------------------------------------------------------------

    def _log(self, message: str) -> None:
        print(f"[owner {self.job_id}/{self.run_id}] {message}", file=sys.stderr, flush=True)

    def _event(self, kind: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        try:
            self.store.append_event(
                self.job_id, run_id=self.run_id, kind=kind, message=message, data=data
            )
        except Exception as exc:  # events must not kill the owner
            self._log(f"failed to append event {kind}: {exc}")

    def _reload_job(self) -> Dict[str, Any]:
        job = self.store.get_job(self.job_id)
        if job is None:
            raise _OwnerFailure("job_missing", "job row disappeared from the store")
        if job.get("run_id") != self.run_id:
            raise _OwnerFailure(
                "attempt_superseded",
                "job now belongs to a different run; this owner stands down",
            )
        self.job = job
        return job

    def _update(
        self,
        updates: Dict[str, Any],
        *,
        attempts: int = 5,
        attempt_fields: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        from .models import JobError

        last_error: Optional[Exception] = None
        for _ in range(attempts):
            job = self._reload_job()
            try:
                updated = self.store.update_job(
                    self.job_id,
                    expected_revision=int(job["revision"]),
                    updates=updates,
                    attempt_fields=attempt_fields,
                )
                self.job = updated
                return updated
            except JobError as exc:
                if exc.code != "revision_conflict":
                    raise _OwnerFailure(exc.code, exc.message) from exc
                last_error = exc
                time.sleep(0.1)
        raise _OwnerFailure("store_conflict", f"failed to update job after retries: {last_error}")

    def _heartbeat(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_heartbeat < self.heartbeat_interval:
            return
        self._last_heartbeat = now
        at = utc_now_iso()
        try:
            accepted = self.store.heartbeat(self.job_id, owner_token=self.token, at=at)
        except Exception as exc:
            raise _OwnerFailure("store_unavailable", f"heartbeat failed: {exc}") from exc
        if not accepted:
            raise _OwnerFailure(
                "attempt_superseded",
                "heartbeat rejected: the job row no longer belongs to this owner",
            )
        receipt = {
            "schema": OWNER_HEARTBEAT_SCHEMA,
            "job_id": self.job_id,
            "run_id": self.run_id,
            "token": self.token,
            "pid": os.getpid(),
            "start_ticks": self.job.get("owner_start_ticks"),
            "boot_id": self.job.get("owner_boot_id"),
            "at": at,
            "status": self.job.get("status"),
        }
        try:
            tmp = self.run_dir / "owner.json.tmp"
            tmp.write_text(json.dumps(receipt, indent=2), encoding="utf-8")
            os.replace(tmp, self.run_dir / "owner.json")
        except OSError as exc:
            self._log(f"cannot write owner receipt: {exc}")

    def _add_artifact(self, kind: str, path: Path, *, status: Optional[str] = None) -> None:
        if status is None:
            status = "available" if path.exists() else "missing"
        for artifact in self.artifacts:
            if artifact["kind"] == kind and artifact["path"] == str(path):
                artifact["status"] = status
                return
        self.artifacts.append({"kind": kind, "path": str(path), "status": status})

    # -- launch / verification -------------------------------------------------

    def _load_launch(self) -> None:
        try:
            payload = json.loads(self.launch_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise _OwnerFailure("launch_invalid", f"cannot read launch file: {exc}") from exc
        if payload.get("schema") != LAUNCH_SCHEMA_VERSION:
            raise _OwnerFailure("launch_invalid", "launch file schema mismatch")
        if payload.get("job_id") != self.job_id or payload.get("run_id") != self.run_id:
            raise _OwnerFailure("launch_invalid", "launch file does not match this attempt")
        if payload.get("owner_token") != self.token:
            raise _OwnerFailure("launch_invalid", "launch file token mismatch")
        argv = payload.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise _OwnerFailure("launch_invalid", "launch argv is missing or malformed")
        self.launch = payload

    def _verify_row_ownership(self) -> None:
        job = self.store.get_job(self.job_id)
        if job is None:
            raise _OwnerFailure("job_missing", "job row disappeared from the store")
        if job.get("run_id") != self.run_id:
            raise _OwnerFailure("attempt_superseded", "job belongs to a newer run")
        if job.get("owner_token") != self.token:
            raise _OwnerFailure("owner_token_mismatch", "owner token mismatch; refusing to act")
        if job.get("status") in TERMINAL_STATUSES:
            raise _OwnerFailure("attempt_superseded", f"job already terminal ({job.get('status')})")
        self.job = job

    def _publish_identity(self) -> None:
        ticks = self_start_ticks()
        boot_id = system_boot_id()
        self._update(
            {
                "owner_pid": os.getpid(),
                "owner_start_ticks": ticks,
                "owner_boot_id": boot_id,
            }
        )
        self._event(
            "owner_started",
            f"owner process started (pid={os.getpid()})",
            {"pid": os.getpid(), "start_ticks": ticks, "boot_id": boot_id},
        )

    # -- input fingerprint -------------------------------------------------------

    def _bind_inputs(self) -> None:
        config_path = str(self.job.get("config_path") or "")
        scan_depth = self.job.get("scan_depth")
        fingerprint = compute_input_fingerprint(
            Path(config_path), scan_depth=scan_depth if scan_depth else None
        )
        previous = str(self.job.get("input_revision") or "")
        current = fingerprint["sha256"]
        expected = self.launch.get("expected_input_revision")
        if expected is not None and (expected != previous or expected != current):
            raise _OwnerFailure(
                "schedule_input_changed",
                "Scheduled inputs changed before scanner launch; refusing to rebind this window.",
            )
        if previous and previous != current:
            old_components = self.job.get("input_components_json") or {}
            if not isinstance(old_components, dict):
                old_components = {}
            changed = diff_components(old_components, fingerprint["components"])
            self._event(
                "input_changed",
                "bound inputs changed since the job was created; previous attempt "
                "results stay revoked and this attempt re-verifies",
                {"components": changed, "previous": previous, "current": current},
            )
        self._update(
            {
                "input_revision": current,
                "input_components_json": fingerprint["components"],
            }
        )
        self._event(
            "input_fingerprint",
            f"attempt input fingerprint {current[:16]}…",
            {"sha256": current},
        )

    # -- report binding ---------------------------------------------------------

    @staticmethod
    def _signature(path: Path) -> Optional[tuple[int, int]]:
        try:
            stat = path.stat()
        except OSError:
            return None
        return (stat.st_mtime_ns, stat.st_size)

    def _bind_report(self, baseline: Dict[str, Optional[tuple[int, int]]]) -> Dict[str, Any]:
        report_info: Dict[str, Any] = {
            "available": False,
            "report_id": None,
            "path": None,
            "source_path": None,
            "reason": None,
        }
        candidates = self.launch.get("report_candidates") or []
        saw_stale = False
        for candidate in candidates:
            path = Path(candidate)
            now_sig = self._signature(path)
            if now_sig is None:
                continue
            if baseline.get(str(path)) == now_sig:
                saw_stale = True
                continue
            # Signature changed during this attempt: bind the new report.
            target = self.run_dir / "report.json"
            try:
                tmp = self.run_dir / "report.json.tmp"
                shutil.copyfile(path, tmp)
                os.replace(tmp, target)
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
            except OSError as exc:
                self._event("report_missing", f"report copy failed: {exc}", {"path": str(path)})
                continue
            # Decode through the formal reader so the shared-json object graph
            # (write_report_atomic's only product format) is validated — a
            # missing reference or a wrong object digest rejects the binding —
            # and the logical report, not the storage envelope, is what feeds
            # coverage/questions extraction.
            parsed: Optional[Dict[str, Any]] = None
            try:
                loaded = read_report(target)
                if isinstance(loaded, dict):
                    parsed = loaded
            except (OSError, ValueError, RuntimeError) as exc:
                self._event(
                    "report_unreadable",
                    f"report produced by this attempt is not decodable: {exc}",
                    {"path": str(path), "bound": str(target)},
                )
                continue
            if parsed is None:
                self._event(
                    "report_unreadable",
                    "report produced by this attempt did not decode to a report object",
                    {"path": str(path), "bound": str(target)},
                )
                continue
            report_info.update(
                {
                    "available": True,
                    "report_id": digest,
                    "path": str(target),
                    "source_path": str(path),
                    "size_bytes": target.stat().st_size,
                    "bound_at": utc_now_iso(),
                }
            )
            self._add_artifact("report", target)
            self._event(
                "report_bound",
                f"bound report {path.name} produced by this attempt",
                {
                    "source_path": str(path),
                    "path": str(target),
                    "sha256": digest,
                    "size_bytes": report_info["size_bytes"],
                },
            )
            self._bind_markdown(path)
            report_info["_parsed"] = parsed  # internal; stripped before persist
            return report_info
        report_info["reason"] = "report_not_updated" if saw_stale else "report_not_produced"
        self._event(
            "report_missing",
            (
                "no report produced by this attempt"
                if not saw_stale
                else "only a pre-existing report is present; not binding it"
            ),
            {"reason": report_info["reason"]},
        )
        return report_info

    def _bind_markdown(self, source_report: Path) -> None:
        for name in _REPORT_MARKDOWN_CANDIDATES:
            candidate = source_report.parent / name
            if candidate.suffix != ".md":
                continue
            try:
                stat = candidate.stat()
            except OSError:
                continue
            if time.time() - stat.st_mtime > 3600:
                continue
            target = self.run_dir / name
            try:
                shutil.copyfile(candidate, target)
            except OSError:
                continue
            self._add_artifact("report_markdown", target)
            return

    # -- scanner lifecycle ------------------------------------------------------

    def _spawn_scanner(self) -> None:
        argv = [str(part) for part in self.launch["argv"]]
        cwd = str(self.launch.get("cwd") or "") or None
        if cwd and not Path(cwd).is_dir():
            raise _OwnerFailure(
                "working_directory_missing", f"recorded working directory is gone: {cwd}"
            )
        log_path = self.run_dir / "scanner.log"
        self._add_artifact("scanner_log", log_path, status="available")
        # The session inside the scanner binds to this attempt through the
        # ZSCOPE_JOB_* environment (identity only; window/cancel state stays
        # in the job store).  A session without these identifiers keeps its
        # current unwired behaviour.
        scanner_env = dict(os.environ)
        scanner_env[JOB_ENV_STORE] = str(self.store.db_path)
        scanner_env[JOB_ENV_JOB_ID] = self.job_id
        scanner_env[JOB_ENV_RUN_ID] = self.run_id
        scanner_env[JOB_ENV_OWNER_TOKEN] = self.token
        scanner_env[JOB_ENV_RUN_DIR] = str(self.run_dir)
        log_handle = open(log_path, "ab", buffering=0)
        try:
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                cwd=cwd,
                env=scanner_env,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            log_handle.close()
            raise _OwnerFailure("scanner_spawn_failed", f"cannot start scanner: {exc}") from exc
        finally:
            # The child holds its own dup of the fd; the parent's copy may go.
            try:
                log_handle.close()
            except Exception:
                pass
        self._scanner = process
        from .identity import read_process_start_ticks

        scanner_ticks = read_process_start_ticks(process.pid)
        self._update(
            {
                "scanner_pid": process.pid,
                "scanner_start_ticks": scanner_ticks,
                "phase": PHASE_SCANNING,
            }
        )
        self._event(
            "scan_launched",
            f"scanner process started (pid={process.pid})",
            {"pid": process.pid, "argv": argv, "cwd": cwd},
        )

    def _terminate_scanner(self, *, reason: str) -> str:
        assert self._scanner is not None
        outcome = terminate_process_group(self._scanner, grace_seconds=self.terminate_grace)
        exit_code = self._scanner.poll()
        self._event(
            "scan_terminated",
            f"scanner group {outcome} after {reason}",
            {
                "outcome": outcome,
                "reason": reason,
                "exit_code": exit_code,
                "signal": -exit_code if isinstance(exit_code, int) and exit_code < 0 else None,
            },
        )
        return outcome

    # -- finalization -------------------------------------------------------------

    def _persist_window_pending(self) -> None:
        target = self.run_dir / "pending.json"
        if target.exists():
            # A session scheduler bound to this attempt already persisted the
            # real remaining queue before it exited; the owner's
            # process-granularity placeholder must never overwrite it.
            count: Optional[int] = None
            try:
                payload = json.loads(target.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    raw_count = payload.get("count")
                    if isinstance(raw_count, int):
                        count = raw_count
            except (OSError, ValueError):
                count = None
            self._add_artifact("pending", target)
            self._event(
                "pending_preserved",
                "real pending queue persisted by the session was kept",
                {"path": str(target), "count": count},
            )
            return
        payload = {
            "schema": "zscope.scan-job-pending.v1",
            "job_id": self.job_id,
            "run_id": self.run_id,
            "source": "owner_window_stop",
            "capped": False,
            "count": 0,
            "items": [],
            "note": (
                "window stop was enforced by the owner at process granularity; "
                "the scanner-internal queue is only introspected once the "
                "session scheduler hook (zscope.orchestration.jobs.scheduler_hook) "
                "is wired into ScanSessionRunner"
            ),
        }
        try:
            tmp = self.run_dir / "pending.json.tmp"
            tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, target)
            self._add_artifact("pending", target)
        except OSError as exc:
            self._log(f"cannot persist pending.json: {exc}")

    def _await_scanner_exit(self, grace_seconds: float, *, interrupt_on_cancel: bool) -> str:
        """Cooperative stop: give the session a bounded chance to exit itself.

        The session scheduler inside the scanner observes the window/cancel
        flags through the job store, stops claiming new work, finishes the
        claimed work bounded, persists the real remaining queue and exits.
        The owner heartbeats while waiting and honours an owner signal
        immediately (bounded teardown wins over the wait).  When entered
        from the cancel branch, ``interrupt_on_cancel`` is False: the cancel
        request itself is why we are waiting, not a reason to stop waiting.
        Returns ``"exited"``, ``"timeout"``, ``"cancel"`` or ``"signal"``.
        """

        assert self._scanner is not None
        deadline = time.monotonic() + max(0.0, grace_seconds)
        while True:
            if self._scanner.poll() is not None:
                return "exited"
            if self._stop_signal is not None:
                return "signal"
            if time.monotonic() >= deadline:
                return "timeout"
            self._heartbeat()
            try:
                job = self._reload_job()
            except _OwnerFailure:
                raise
            if interrupt_on_cancel and job.get("cancel_requested_at"):
                return "cancel"
            time.sleep(0.2)

    def _attempt_work_queue_path(self) -> Optional[Path]:
        """Use the actual scheduler receipt, never glob or a report-supplied path."""
        job_dir = (self.store.db_path.parent / self.job_id).resolve()
        receipt = self.store.latest_event(
            self.job_id, run_id=self.run_id, kind="session_scheduler_started"
        )
        if receipt is None:
            canonical = (job_dir / "work-queue.db").resolve()
            return canonical if canonical.parent == job_dir else None
        data = receipt["data"]
        if data.get("input_revision") != self.job.get("input_revision"):
            return None
        raw = data.get("work_queue")
        if not isinstance(raw, str) or not Path(raw).is_absolute():
            return None
        path = Path(raw).resolve()
        if path.parent not in {job_dir, self.run_dir.resolve()}:
            return None
        if path.name != "work-queue.db" and not path.name.startswith("work-queue.db."):
            return None
        return path

    def _finalize(
        self,
        *,
        status: str,
        exit_code: Optional[int],
        baseline: Dict[str, Optional[tuple[int, int]]],
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        report_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        if report_info is None:
            report_info = self._bind_report(baseline)
        parsed = report_info.pop("_parsed", None)
        coverage = merge_coverage(parsed)
        questions = extract_questions(parsed)
        # The queue is per job/input and survives attempts. Read only its real
        # SQL counts, never the number of business questions or a capped JSON
        # sample. An unwired scanner has no measured remaining denominator.
        self._verify_row_ownership()
        queue_path = self._attempt_work_queue_path()
        counts = (
            read_bound_queue_counts(
                queue_path,
                job_id=self.job_id,
                input_revision=str(self.job.get("input_revision") or ""),
            )
            if queue_path is not None
            else None
        )
        pending_count = (
            sum(counts[key] for key in ("pending", "active", "deferred"))
            if counts is not None
            else None
        )
        if status == "completed" and counts is not None and (pending_count or counts["failed"]):
            status = "partial"
            error_code = "scan_incomplete"
            error_message = "measured work queue has remaining or failed work"
        updates: Dict[str, Any] = {
            "status": status,
            "phase": None,
            "report_json": {k: v for k, v in report_info.items() if not k.startswith("_")},
            "coverage_json": coverage,
            "questions_json": questions,
            "pending_count": pending_count,
            "artifacts_json": self.artifacts,
            "error_code": error_code,
            "error_message": (error_message or "")[:2000] or None,
        }
        self._update(
            updates,
            attempt_fields={
                "status": status,
                "input_revision": self.job.get("input_revision"),
                "started_at": self.job.get("started_at"),
                "ended_at": utc_now_iso(),
                "exit_code": exit_code,
                "exit_signal": -exit_code if isinstance(exit_code, int) and exit_code < 0 else None,
                "report_path": report_info.get("path"),
                "report_id": report_info.get("report_id"),
                "error_code": error_code,
                "error_message": (error_message or "")[:2000] or None,
            },
        )
        self._event(
            "job_terminal",
            f"job reached terminal state {status}",
            {"status": status, "exit_code": exit_code, "error_code": error_code},
        )

    # -- main loop ---------------------------------------------------------------

    def run(self) -> int:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._add_artifact("launch", self.launch_path)
        self._add_artifact("owner_log", self.run_dir / "owner.log")
        self._load_launch()
        self._verify_row_ownership()
        self._publish_identity()
        self._heartbeat(force=True)

        cancel_seen_early = bool(self.job.get("cancel_requested_at"))
        self._update({"status": "running", "started_at": utc_now_iso(), "phase": PHASE_LAUNCHING})
        self.store.record_attempt(
            {
                "job_id": self.job_id,
                "run_id": self.run_id,
                "attempt_no": self.store.next_attempt_no(self.job_id),
                "status": "running",
                "input_revision": self.job.get("input_revision"),
                "started_at": utc_now_iso(),
            }
        )
        self._bind_inputs()
        baseline = {
            str(path): self._signature(Path(path))
            for path in (self.launch.get("report_candidates") or [])
        }

        if cancel_seen_early:
            self._event("cancel_observed", "cancel was requested before the scanner started")
            self._finalize(
                status="cancelled",
                exit_code=None,
                baseline=baseline,
                error_code="cancelled",
                error_message="cancelled before the scanner process started",
            )
            return 0

        stop_at_epoch = self.launch.get("stop_at_epoch")
        stop_at_epoch = float(stop_at_epoch) if stop_at_epoch is not None else None
        if stop_at_epoch is not None and time.time() >= stop_at_epoch:
            self._event("stop_window_reached", "stop window closed before scanner launch")
            self._finalize(
                status="partial",
                exit_code=None,
                baseline=baseline,
                error_code="stop_window_closed",
                error_message="window closed before scanner launch",
            )
            return 0
        self._spawn_scanner()
        assert self._scanner is not None

        terminal_status: Optional[str] = None
        terminal_error: Optional[tuple[str, str]] = None
        report_info: Optional[Dict[str, Any]] = None
        while True:
            exit_code = self._scanner.poll()
            self._heartbeat()
            job = self._reload_job()
            if self._stop_signal is not None:
                self._update({"phase": PHASE_STOPPING})
                self._event("cancel_observed", f"owner received signal {self._stop_signal}")
                self._terminate_scanner(reason=f"signal:{self._stop_signal}")
                terminal_status = "cancelled"
                terminal_error = ("owner_signal", f"owner received signal {self._stop_signal}")
                break
            if job.get("cancel_requested_at"):
                self._update({"status": "stopping", "phase": PHASE_STOPPING})
                self._event("cancel_observed", "cancel requested via the job store")
                outcome = "already_exited"
                if self._scanner.poll() is None:
                    # Cooperative first: a session scheduler bound to this
                    # attempt interrupts its work and persists the real
                    # remaining queue bounded; the watchdog only fires when
                    # the scanner ignores the request for cancel_finalize_grace.
                    outcome = self._await_scanner_exit(
                        self.cancel_finalize_grace, interrupt_on_cancel=False
                    )
                    if outcome == "signal":
                        self._event("cancel_observed", f"owner received signal {self._stop_signal}")
                    if self._scanner.poll() is None:
                        self._event(
                            "cancel_watchdog",
                            "session did not stop within the cooperative cancel grace; "
                            "watchdog teardown",
                            {"outcome": outcome},
                        )
                self._terminate_scanner(reason="cancel")
                terminal_status = "cancelled"
                terminal_error = ("cancelled", "cancel requested")
                break
            if stop_at_epoch is not None and time.time() >= stop_at_epoch:
                resolved = self.job.get("resolved_stop_time") or epoch_to_iso(stop_at_epoch)
                self._update({"status": "stopping", "phase": PHASE_STOPPING})
                self._event(
                    "stop_window_reached",
                    f"stop window reached at {resolved}; bounded finish, job will be partial",
                    {"resolved_stop_time": resolved},
                )
                # Cooperative deadline first: the session scheduler stops
                # claiming on its own and finalizes bounded (finish claimed
                # work, persist the real remaining queue, exit).  The
                # process-group termination below is only the bounded
                # backstop for a session that keeps running past the grace.
                outcome = self._await_scanner_exit(
                    self.window_finalize_grace, interrupt_on_cancel=True
                )
                if outcome == "cancel":
                    self._event("cancel_observed", "cancel requested via the job store")
                    self._terminate_scanner(reason="cancel")
                    terminal_status = "cancelled"
                    terminal_error = ("cancelled", "cancel requested")
                    break
                if outcome == "signal":
                    self._event("cancel_observed", f"owner received signal {self._stop_signal}")
                    self._terminate_scanner(reason=f"signal:{self._stop_signal}")
                    terminal_status = "cancelled"
                    terminal_error = ("owner_signal", f"owner received signal {self._stop_signal}")
                    break
                if self._scanner.poll() is None:
                    self._event(
                        "window_watchdog",
                        "session did not finish within the cooperative window; "
                        "watchdog teardown",
                        {"outcome": outcome},
                    )
                    self._terminate_scanner(reason="stop_window")
                else:
                    self._event(
                        "window_cooperative_exit",
                        "session exited after cooperative window finalization",
                        {"outcome": outcome},
                    )
                self._persist_window_pending()
                terminal_status = "partial"
                terminal_error = ("stop_window_reached", "stop window reached before completion")
                break
            if exit_code is not None:
                # Bind first so a bare exit-2 (exception without a report) is
                # not misreported as a partial scan.
                report_info = self._bind_report(baseline)
                terminal_status = self._status_from_exit(
                    exit_code, report_bound=bool(report_info.get("available"))
                )
                if terminal_status == "failed":
                    terminal_error = ("scan_failed", f"scanner exited with code {exit_code}")
                elif terminal_status == "partial":
                    terminal_error = ("scan_incomplete", "scan finished incomplete")
                break
            time.sleep(0.2)

        final_exit = self._scanner.poll()
        self._finalize(
            status=terminal_status or "failed",
            exit_code=final_exit,
            baseline=baseline,
            error_code=terminal_error[0] if terminal_error else None,
            error_message=terminal_error[1] if terminal_error else None,
            report_info=report_info,
        )
        return 0

    @staticmethod
    def _status_from_exit(exit_code: int, *, report_bound: bool) -> str:
        if exit_code in (0, 1):
            return "completed"
        if exit_code == 2 and report_bound:
            # CLI exit 2 means either an incomplete scan (report persisted) or
            # an unhandled exception (no report); the binding distinguishes.
            return "partial"
        return "failed"

    def install_signal_handlers(self) -> None:
        def _handler(signum: int, _frame: Any) -> None:
            self._stop_signal = signum

        if os.name == "posix":
            signal.signal(signal.SIGTERM, _handler)
            signal.signal(signal.SIGINT, _handler)


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="zscope.orchestration.jobs")
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--store", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--launch", required=True)
    parser.add_argument("--heartbeat-interval", type=float, default=1.0)
    parser.add_argument("--terminate-grace", type=float, default=10.0)
    parser.add_argument("--window-finalize-grace", type=float, default=10.0)
    parser.add_argument("--cancel-finalize-grace", type=float, default=2.0)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    token = os.environ.get("ZSCOPE_JOB_OWNER_TOKEN", "")
    store = JobStore(args.store)
    owner = Owner(
        store=store,
        job_id=args.job_id,
        run_id=args.run_id,
        run_dir=Path(args.run_dir),
        launch_path=Path(args.launch),
        token=token,
        heartbeat_interval=args.heartbeat_interval,
        terminate_grace=args.terminate_grace,
        window_finalize_grace=args.window_finalize_grace,
        cancel_finalize_grace=args.cancel_finalize_grace,
    )
    owner.install_signal_handlers()
    try:
        return owner.run()
    except _OwnerFailure as exc:
        owner._log(f"owner aborted: {exc.code}: {exc.message}")
        if exc.code in {"attempt_superseded", "owner_token_mismatch", "job_missing"}:
            return 2
        _mark_failed(store, owner, exc.code, exc.message)
        return 3
    except Exception as exc:  # crash must never fake a terminal success
        owner._log(f"owner crashed: {traceback.format_exc()}")
        _mark_failed(store, owner, "owner_crashed", f"{type(exc).__name__}: {exc}")
        return 3


def _mark_failed(store: JobStore, owner: Owner, code: str, message: str) -> None:
    try:
        job = store.get_job(owner.job_id)
        if job is None or job.get("run_id") != owner.run_id:
            return
        if job.get("status") in TERMINAL_STATUSES:
            return
        store.update_job(
            owner.job_id,
            expected_revision=int(job["revision"]),
            updates={
                "status": "failed",
                "error_code": code,
                "error_message": message[:2000],
            },
            attempt_fields={
                "status": "failed",
                "input_revision": job.get("input_revision"),
                "started_at": job.get("started_at"),
                "ended_at": utc_now_iso(),
                "error_code": code,
                "error_message": message[:2000],
            },
        )
        store.append_event(
            owner.job_id,
            run_id=owner.run_id,
            kind="job_terminal",
            message=f"job failed: {code}",
            data={"status": "failed", "error_code": code},
        )
    except Exception:
        pass


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
