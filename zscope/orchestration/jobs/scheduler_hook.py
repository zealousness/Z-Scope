"""Scheduler hook contract for wiring scan sessions to job windows (JOB04/06).

This module is the *contract* the coordinator wires into
``ScanSessionRunner`` / ``ParallelAnalyzer``.  The owner already passes the
attempt identifiers to the scanner through the ``ZSCOPE_JOB_*`` environment
(:func:`session_job_context_from_env`) and gives a session bound to them a
bounded cooperative window before its watchdog fires, so a wired session can
stop claiming work and persist the real remaining queue by itself.  Until
the coordinator wires the hook into the session runner, an unwired scanner
never sees these identifiers, job ``phase`` stays at owner granularity and
``progress`` stays null — JOB04 session-level "stop accepting new work" and
JOB06 fair batch draining are *not* delivered by this branch alone.

Wiring guide (for the coordinator, no behaviour change required here):

1. Inside the session process build the hook from the owner-passed
   environment: ``job_window_hook_from_environment()`` returns ``None`` for
   an unwired session (keep current behaviour) and otherwise a hook bound to
   the current ``job_id``/``run_id``/``owner_token``/store/run_dir.
2. Before dequeuing each new work item, check ``hook.stop_new_work()``; when
   True stop submitting and let in-flight work finish bounded.  The
   session-side consumer of both the hook and the persistent work queue is
   :mod:`zscope.orchestration.jobs.session_scheduler`.
3. Pass ``hook.deadline_epoch()`` into the existing ``CancellationToken``
   deadline plumbing (``zscope/common/cancellation.py``) so the session's own
   deadline path triggers instead of the owner killing the process.
4. On window/cancel exit, call ``hook.persist_pending(items, source=...)``
   with the real remaining queue so a later resume has an honest backlog.
5. Report real phases/progress via ``hook.note_phase`` / ``hook.note_progress``
   so the API never shows invented percentages.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional

from .models import PENDING_SCHEMA_VERSION, TERMINAL_STATUSES
from .store import JobStore

if TYPE_CHECKING:
    from ...retrieval.code_index import _JobRuntimeOutputs

_FLAG_TTL_SECONDS = 0.5
_MAX_PENDING_ITEMS = 10_000

#: Environment variables the detached owner passes to the scanner process so
#: the session-side hook and work scheduler can bind to the *current* job
#: attempt.  They carry identity only; window/cancel state stays in the job
#: store, which remains the single source of truth.
JOB_ENV_STORE = "ZSCOPE_JOB_STORE"
JOB_ENV_JOB_ID = "ZSCOPE_JOB_ID"
JOB_ENV_RUN_ID = "ZSCOPE_JOB_RUN_ID"
JOB_ENV_OWNER_TOKEN = "ZSCOPE_JOB_OWNER_TOKEN"
JOB_ENV_RUN_DIR = "ZSCOPE_JOB_RUN_DIR"

_JOB_ENV_KEYS = (
    JOB_ENV_STORE,
    JOB_ENV_JOB_ID,
    JOB_ENV_RUN_ID,
    JOB_ENV_OWNER_TOKEN,
    JOB_ENV_RUN_DIR,
)


@dataclass(frozen=True)
class SessionJobContext:
    """The owner-passed identifiers of the job attempt this session serves."""

    store_path: str
    job_id: str
    run_id: str
    owner_token: str
    run_dir: str


def session_job_context_from_env(
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[SessionJobContext]:
    """Read the owner-passed attempt identifiers from the environment.

    Returns ``None`` unless *every* identifier is present and non-empty — a
    partially passed set never binds a session (fail-safe: the session keeps
    running without a window, exactly like an unwired one).
    """

    env = os.environ if environ is None else environ
    values: Dict[str, str] = {}
    for key in _JOB_ENV_KEYS:
        raw = env.get(key)
        if not isinstance(raw, str) or not raw.strip():
            return None
        values[key] = raw.strip()
    return SessionJobContext(
        store_path=values[JOB_ENV_STORE],
        job_id=values[JOB_ENV_JOB_ID],
        run_id=values[JOB_ENV_RUN_ID],
        owner_token=values[JOB_ENV_OWNER_TOKEN],
        run_dir=values[JOB_ENV_RUN_DIR],
    )


def job_window_hook_from_environment(
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[JobWindowHook]:
    """Build the session-side hook from the owner-passed environment.

    ``None`` means the session process was not started by a job owner (or the
    identifiers are incomplete): the caller keeps its current unwired
    behaviour instead of guessing a binding.
    """

    context = session_job_context_from_env(environ)
    if context is None:
        return None
    return JobWindowHook(
        context.store_path,
        job_id=context.job_id,
        run_id=context.run_id,
        owner_token=context.owner_token,
        run_dir=context.run_dir,
    )


class JobWindowHook:
    """Session-side view of the job window; reads DB flags, writes pending."""

    def __init__(
        self,
        store_path: Path | str,
        *,
        job_id: str,
        run_id: str,
        owner_token: str,
        run_dir: Path | str,
        input_revision: Optional[str] = None,
    ) -> None:
        self._store = JobStore(store_path)
        self._job_id = job_id
        self._run_id = run_id
        self._owner_token = owner_token
        self._run_dir = Path(run_dir)
        # Construction performs no SQL. Only the real scheduler's captured
        # revision or the issuing native scope can provide this coordinate.
        self._input_revision = (
            input_revision if isinstance(input_revision, str) and input_revision else None
        )
        self._runtime_outputs: Optional["_JobRuntimeOutputs"] = None
        self._cached_flags: tuple[float, bool, Optional[float]] = (0.0, False, None)

    def _bind_runtime_outputs(self, scope: "_JobRuntimeOutputs") -> None:
        from ...retrieval.code_index import _JobRuntimeOutputs

        if not isinstance(scope, _JobRuntimeOutputs):
            raise ValueError("job_runtime_output_factory_hook_required")
        scope._issued()
        if (
            self._runtime_outputs is not None
            or scope._store_path != self._store.db_path
            or scope._job_id != self._job_id
            or scope._run_id != self._run_id
            or scope._owner_token != self._owner_token
            or scope._run_dir != self._run_dir
            or not scope.input_revision
            or self._input_revision not in {None, scope.input_revision}
        ):
            raise ValueError("job_runtime_output_hook_binding_mismatch")
        self._input_revision = scope.input_revision
        self._runtime_outputs = scope

    # -- queries -------------------------------------------------------------

    def _flags(self) -> tuple[bool, Optional[float]]:
        now = time.monotonic()
        cached_at, cancel_requested, stop_at_epoch = self._cached_flags
        if now - cached_at < _FLAG_TTL_SECONDS:
            return cancel_requested, stop_at_epoch
        try:
            job = self._store.get_job(self._job_id)
        except Exception:
            return cancel_requested, stop_at_epoch
        if job is None:
            return cancel_requested, stop_at_epoch
        cancel_requested = bool(job.get("cancel_requested_at"))
        raw_epoch = job.get("stop_at_epoch")
        stop_at_epoch = float(raw_epoch) if raw_epoch is not None else None
        self._cached_flags = (now, cancel_requested, stop_at_epoch)
        return cancel_requested, stop_at_epoch

    def cancel_requested(self) -> bool:
        cancel, _ = self._flags()
        return cancel

    def deadline_epoch(self) -> Optional[float]:
        _, stop_at_epoch = self._flags()
        return stop_at_epoch

    def stop_new_work(self) -> bool:
        """True when the session must stop accepting new work items."""

        cancel, stop_at_epoch = self._flags()
        if cancel:
            return True
        return stop_at_epoch is not None and time.time() >= stop_at_epoch

    # -- binding ----------------------------------------------------------------

    def stand_down_reason(self, *, expected_input_revision: Optional[str] = None) -> Optional[str]:
        """Fresh binding check against the job row; ``None`` while current.

        Returns a short code when this attempt must stop consuming work:
        ``job_missing`` (row gone), ``run_superseded`` (the job belongs to a
        newer run), ``owner_token_mismatch`` (a foreign owner token),
        ``job_terminal`` (the attempt already reached a terminal state),
        ``input_revision_changed`` (the row is bound to different inputs than
        the caller's work) or ``store_unreadable`` (the binding cannot be
        verified right now).  An unreadable binding is never authorization:
        the caller must stop consuming and keep the gap instead of guessing.
        """

        try:
            job = self._store.get_job(self._job_id)
        except Exception:
            return "store_unreadable"
        if job is None:
            return "job_missing"
        if job.get("run_id") != self._run_id:
            return "run_superseded"
        if job.get("owner_token") != self._owner_token:
            return "owner_token_mismatch"
        if job.get("status") in TERMINAL_STATUSES:
            return "job_terminal"
        if (
            expected_input_revision is not None
            and job.get("input_revision") != expected_input_revision
        ):
            return "input_revision_changed"
        return None

    def attempt_is_current(self) -> bool:
        return self.stand_down_reason() is None

    def current_input_revision(self) -> Optional[str]:
        """The job row's current input revision, or None when unbound."""

        try:
            job = self._store.get_job(self._job_id)
        except Exception:
            return None
        if job is None or job.get("run_id") != self._run_id:
            return None
        revision = job.get("input_revision")
        return revision if isinstance(revision, str) and revision else None

    # -- reporting -------------------------------------------------------------

    def persist_pending(self, items: List[Dict[str, Any]], *, source: str) -> Optional[Path]:
        """Atomically persist the remaining queue for a later resume."""

        bounded = list(items[:_MAX_PENDING_ITEMS])
        payload = {
            "schema": PENDING_SCHEMA_VERSION,
            "job_id": self._job_id,
            "run_id": self._run_id,
            "source": source,
            "capped": len(items) > _MAX_PENDING_ITEMS,
            "count": len(bounded),
            "items": bounded,
        }
        target = self._run_dir / "pending.json"
        tmp = self._run_dir / "pending.json.tmp"
        revision = self._input_revision
        if not revision:
            return None
        try:
            with self._store.bound_attempt(
                job_id=self._job_id,
                run_id=self._run_id,
                owner_token=self._owner_token,
                expected_input_revision=revision,
            ) as job:
                connection = self._store._active_transaction_connection()
                attempt = connection.execute(
                    "SELECT input_revision FROM attempts WHERE job_id=? AND run_id=?",
                    (self._job_id, self._run_id),
                ).fetchone()
                # The attempts row is written when an attempt settles, so a
                # still-running attempt legitimately has none yet; only an
                # attempt row that exists *and* disagrees may veto the write.
                # The owning job row (read inside bound_attempt) already
                # proves the run/owner/input binding above.
                if (
                    job.get("run_dir") != str(self._run_dir)
                    or self._run_dir.resolve() != self._run_dir
                    or any(
                        parent.is_symlink() for parent in (self._run_dir, *self._run_dir.parents)
                    )
                    or (attempt is not None and attempt["input_revision"] != revision)
                ):
                    return None
                fence = (
                    self._runtime_outputs.writer()
                    if self._runtime_outputs is not None
                    else nullcontext()
                )
                with fence:
                    self._run_dir.mkdir(parents=True, exist_ok=True)
                    tmp.write_text(
                        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
                    )
                    os.replace(tmp, target)
        except (OSError, ValueError):
            return None
        except Exception:
            # Unknown or stale owner/input binding authorizes no file write.
            return None
        # The event opens its own real transaction only after both fences have
        # exited. Never call append_event while holding the Store write lock.
        try:
            self._store.append_event(
                self._job_id,
                run_id=self._run_id,
                kind="pending_persisted",
                message=f"persisted {len(bounded)} pending item(s) from {source}",
                data={"path": str(target), "count": len(bounded), "source": source},
            )
        except Exception:
            pass
        return target

    def note_phase(self, phase: str) -> None:
        """Publish a real session phase; unknown phases are not invented."""

        phase = str(phase or "").strip()
        if not phase:
            return
        try:
            job = self._store.get_job(self._job_id)
            if job is None or job.get("run_id") != self._run_id:
                return
            self._store.update_job(
                self._job_id,
                expected_revision=int(job["revision"]),
                updates={"phase": phase},
            )
        except Exception:
            return

    def note_progress(
        self,
        *,
        completed: Optional[int] = None,
        total: Optional[int] = None,
        active: Optional[int] = None,
        deferred: Optional[int] = None,
        unit: Optional[str] = None,
    ) -> None:
        """Publish measured progress only; callers pass None when unknown."""

        progress = {
            "completed": completed,
            "total": total,
            "active": active,
            "deferred": deferred,
            "unit": unit,
        }
        try:
            job = self._store.get_job(self._job_id)
            if job is None or job.get("run_id") != self._run_id:
                return
            self._store.update_job(
                self._job_id,
                expected_revision=int(job["revision"]),
                updates={"progress_json": progress},
            )
        except Exception:
            return
