"""Consumption of the public config v3 ``execution.stop_at`` boundary.

The strict v3 loader resolves ``execution.stop_at`` against
``execution.timezone`` once per load into one absolute, timezone-aware
boundary (:func:`zscope.config.v3.resolve_stop_boundary`); unknown timezones
and daylight-saving gaps/folds are rejected at resolution time.  This module
bridges that once-held boundary to the two real consumers without ever
re-resolving it:

* CLI scan sessions convert the *real remaining* time into a monotonic,
  non-extendable budget tightened onto the session runner's **shared**
  cancellation token (``CancellationToken.tighten_deadline``), and a watcher
  thread converts the deadline into an explicit cooperative cancel when it
  passes, so the session's existing bounded finalization path (finish claimed
  work, persist state, interrupted result) runs instead of an unbounded
  scan.  Because the budget lives on the shared token itself — not a side
  token — every existing and future child (workflow executors, analyzers,
  the LLM client's remaining-bounded request timeouts) observes the window.
  ``ScanSessionRunner`` accepts no cancellation token of its own (verified
  against the real constructor); it builds one token and hands that same
  object to its executors by reference, so tightening that shared object is
  the real consumption path — never a side flag, and never a replacement
  that would leave executors holding the old reference.
* The persistent job service persists the boundary as the job's stop window
  at ``start`` when the request carries no explicit ``stop_at``.  The saved
  document is read once for the window, the resolved instant (local wall
  clock, timezone and UTC epoch) is persisted on the job row, and the
  existing owner/scheduler chain enforces the persisted epoch.  Replays of an
  accepted request return the original job with its original window and never
  re-resolve.
* A CLI started by a job owner (the ``ZSCOPE_JOB_*`` identifiers) takes the
  job store's **persisted** window as its only budget source — including a
  legitimate ``None`` after a resume cleared it; the config window is never
  re-applied there (:func:`session_stop_window_authority` /
  :func:`arm_persisted_deadline`).  The binding is validated against the real
  SQL row (job/run/owner/input/window/run_dir) plus the configured project's
  store location; a partially
  present or unverifiable environment is refused instead of guessed.

An explicit, non-empty request ``stop_at`` wins over the config boundary.
Documents without a stop window keep the current
window-less behaviour.  A boundary that has already passed is never silently
rolled to tomorrow's occurrence: the CLI refuses to start a scan whose
window is closed, and an expired persisted window stops the job at once.
"""

from __future__ import annotations

import math
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

from ..common.cancellation import CancellationToken
from ..config.support import (
    _expand_env,
    _resolve_config_path,
    load_yaml_unique,
)
from ..config.v3 import StopWindow, parse_user_config_v3_document

STOP_WINDOW_CANCEL_REASON = "stop window reached"
CONFIG_STOP_WINDOW_SOURCE = "config"
JOB_STOP_WINDOW_SOURCE = "job"


class ExpiredStopWindowError(RuntimeError):
    """The once-resolved stop boundary already passed; no silent roll forward.

    ``exit_code`` keeps the CLI's honest outcome: 1 for a standalone config
    refusal, 2 for a job-bound attempt whose persisted window was closed
    (the detached owner maps 2 without a report to ``failed``).
    """

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = int(exit_code)


class InvalidJobBindingError(RuntimeError):
    """Job identifiers are present but the binding cannot be validated."""


@dataclass(frozen=True)
class PersistedStopWindow:
    """One resolved stop window ready to persist on a job row.

    ``resolved_stop_time`` is the UTC ISO8601 instant the owner enforces;
    ``requested_stop_at`` is the declared local window (``HH:MM`` plus the
    IANA timezone) recorded as what this run asked for; ``resolved_local``
    keeps the actual local date and offset of this run's boundary.
    """

    source: str
    timezone: str
    stop_at: str
    resolved_stop_time: str
    stop_at_epoch: float
    requested_stop_at: str
    resolved_local: str


def stop_window_from_config(config: Any) -> Optional[StopWindow]:
    """Return the once-resolved v3 stop window of a loaded config, if any.

    Internal programmatic configs and documents without ``execution.stop_at``
    return ``None`` and keep the current window-less behaviour.
    """

    model = getattr(config, "user_config_v3", None)
    if model is None:
        return None
    window = getattr(getattr(model, "execution", None), "stop_window", None)
    return window if isinstance(window, StopWindow) else None


def remaining_seconds(window: StopWindow, *, now: Optional[datetime] = None) -> float:
    """Real seconds from ``now`` to the boundary; an expired window is 0.0.

    The boundary is never re-resolved here: a window whose instant already
    passed reports zero remaining time instead of rolling to tomorrow.
    """

    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None or reference.utcoffset() is None:
        raise ValueError("stop window remaining time requires a timezone-aware 'now'")
    return max(0.0, window.resolved_stop_time.timestamp() - reference.timestamp())


def resolve_saved_config_stop_window(
    config_path: Optional[str | Path] = None, *, now: Optional[datetime] = None
) -> Optional[PersistedStopWindow]:
    """Resolve the saved config's stop window once for a job start.

    The document is read once and the version gate shares that read with the
    v3 parse (``parse_user_config_v3_document``), so the gated document and
    the parsed model cannot drift apart. Returns ``None`` for documents
    without a stop window; old formats fail the public version gate.  Resolution keeps the strict v3
    rules — unknown timezone, daylight-saving gap and fold are rejected —
    against ``now`` (default: the real current time).
    """

    path = _resolve_config_path(str(config_path) if config_path is not None else None)
    raw: Mapping[str, Any] = _expand_env(load_yaml_unique(path))
    model = parse_user_config_v3_document(path, raw, now=now)
    window = model.execution.stop_window
    if window is None:
        return None
    epoch = window.resolved_stop_time.timestamp()
    return PersistedStopWindow(
        source=CONFIG_STOP_WINDOW_SOURCE,
        timezone=window.timezone,
        stop_at=window.stop_at,
        resolved_stop_time=datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(),
        stop_at_epoch=epoch,
        requested_stop_at=f"{window.stop_at} {window.timezone}",
        resolved_local=window.resolved_stop_time.isoformat(),
    )


def session_cancellation_token(runner: Any) -> CancellationToken:
    """Return the shared token the runner already handed to its executors.

    ``ScanSessionRunner`` constructs one token and passes that same object to
    its workflow executors by reference, so cancelling it propagates to every
    consumer.  The public executor attribute is preferred; the runner's own
    attribute is the fallback.  If neither exists there is no real
    consumption path and this refuses rather than arming a fake flag.
    """

    executor = getattr(runner, "session_executor", None)
    token = getattr(executor, "cancellation_token", None)
    if not isinstance(token, CancellationToken):
        token = getattr(runner, "_cancellation_token", None)
    if not isinstance(token, CancellationToken):
        raise RuntimeError(
            "cannot find the session runner's shared cancellation token; "
            "a deadline watcher without it would be a fake flag"
        )
    return token


class SessionDeadlineGuard:
    """Cooperative deadline watcher for one armed CLI scan session.

    The real remaining time becomes a monotonic, non-extendable budget on the
    runner's *shared* token itself (``tighten_deadline``), so every consumer
    that reads the token or any child of it — workflow executors, analyzers,
    and the LLM client's remaining-bounded request timeouts — observes the
    window; children created later inherit it.  A daemon watcher converts the
    deadline into an explicit cooperative cancel when *this window's*
    deadline is the first cancellation cause; any earlier cause — an explicit
    cancel, a cancelled parent, or a tighter pre-existing deadline — keeps
    its own true reason and state, and the watcher stands down without
    relabelling it.  ``release`` stops the watcher when the session ends for
    any reason; the budget itself stays on the token (tighten-only) because
    the window is wall-clock truth, not watcher state.
    """

    def __init__(
        self,
        runner: Any,
        window: StopWindow,
        *,
        now: Optional[datetime] = None,
        poll_seconds: float = 0.1,
    ) -> None:
        remaining = remaining_seconds(window, now=now)
        if remaining <= 0.0:
            raise ExpiredStopWindowError(expired_window_message(window))
        reason = (
            f"{STOP_WINDOW_CANCEL_REASON}: the configured execution.stop_at "
            f"boundary {window.stop_at} {window.timezone} "
            f"({window.resolved_stop_time.isoformat()}) passed before the scan finished"
        )
        self._assemble(runner, remaining, reason, poll_seconds)
        self.window: Optional[StopWindow] = window

    def _assemble(self, runner: Any, remaining: float, reason: str, poll_seconds: float) -> None:
        self.window = None
        self.remaining_seconds = remaining
        self._shared_token = session_cancellation_token(runner)
        self._reason = reason
        # The budget goes on the real shared token, never a side token: the
        # monotonic projection of the wall-clock boundary is tightened onto
        # the object the executors, analyzers and scheduler already hold, so
        # nothing has to be re-wired and no consumer can miss it.
        self._deadline = time.monotonic() + remaining
        self._shared_token.tighten_deadline(self._deadline, reason=self._reason)
        self._poll_seconds = max(0.01, float(poll_seconds))
        self._stopped = threading.Event()
        self._thread = threading.Thread(
            target=self._watch, name="zscope-stop-window-watch", daemon=True
        )

    def start(self) -> "SessionDeadlineGuard":
        self._thread.start()
        return self

    def release(self) -> None:
        """Stop the watcher; a released guard never cancels the token.

        The tightened budget stays on the token: deadlines only tighten, and
        the boundary keeps passing in wall-clock time even after the session
        that armed it has ended.
        """

        self._stopped.set()

    def _watch(self) -> None:
        while not self._stopped.wait(self._poll_seconds):
            if not self._shared_token.is_cancelled():
                continue
            # The token is cancelled.  Convert it into an explicit
            # cooperative cancel only when *this window's* deadline is the
            # first cause; every other cause (an explicit cancel, a
            # cancelled parent, or a different — possibly earlier —
            # deadline) already carries the true reason and stands.
            self._shared_token.cancel_if_deadline(self._deadline, self._reason)
            return


def arm_session_deadline(
    runner: Any, window: StopWindow, *, now: Optional[datetime] = None
) -> SessionDeadlineGuard:
    """Arm the config stop boundary on a constructed runner.

    Raises :class:`ExpiredStopWindowError` when the boundary already passed:
    the scan is refused instead of silently running to tomorrow's boundary.
    """

    return SessionDeadlineGuard(runner, window, now=now).start()


def arm_persisted_deadline(
    runner: Any,
    *,
    stop_at_epoch: float,
    resolved_stop_time: Optional[str] = None,
) -> SessionDeadlineGuard:
    """Arm the job store's persisted absolute epoch as the session budget.

    The epoch is the SQL row's authoritative window for this attempt.  An
    already-passed epoch refuses the scan (never rolled to any later
    occurrence) with the job-failure exit code so the attempt stays honest.
    """

    epoch = _finite_persisted_epoch(stop_at_epoch)
    remaining = epoch - time.time()
    if remaining <= 0.0:
        raise ExpiredStopWindowError(
            expired_persisted_window_message(epoch, resolved_stop_time), exit_code=2
        )
    label = resolved_stop_time or datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    reason = (
        f"{STOP_WINDOW_CANCEL_REASON}: the job attempt's persisted stop window "
        f"({label}) passed before the scan finished"
    )
    guard = SessionDeadlineGuard.__new__(SessionDeadlineGuard)
    guard._assemble(runner, remaining, reason, 0.1)
    return guard.start()


@dataclass(frozen=True)
class JobWindowAuthority:
    """The validated stop-window authority of a job-bound CLI session.

    ``stop_at_epoch``/``resolved_stop_time`` come straight from the job row;
    ``None`` epoch means this attempt carries no persisted window (a resume
    cleared it) and the config window must not be applied.
    """

    job_id: str
    run_id: str
    stop_at_epoch: Optional[float]
    resolved_stop_time: Optional[str]


def _finite_persisted_epoch(raw_epoch: Any) -> float:
    """Refuse corrupt SQL values before projecting a deadline onto a token."""

    try:
        epoch = float(raw_epoch)
    except (TypeError, ValueError, OverflowError) as exc:
        raise InvalidJobBindingError("job binding rejected: invalid_persisted_stop_window") from exc
    if not math.isfinite(epoch):
        raise InvalidJobBindingError("job binding rejected: nonfinite_persisted_stop_window")
    return epoch


def session_stop_window_authority(
    config_path: Optional[str | Path] = None,
    *,
    scan_depth: Optional[str] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Optional[JobWindowAuthority]:
    """Return the job-bound stop-window authority, or ``None`` when standalone.

    A CLI started by a job owner receives the ``ZSCOPE_JOB_*`` identifiers;
    with a *valid* binding the job store's persisted window is the only
    budget source.  The binding is validated through the real SQL row —
    job/run/owner identity, the scanner's own input fingerprint and the
    persisted run directory — in the configured project's store.  Identity
    and window are validated and consumed from one SELECT's row snapshot.
    That SELECT is this read's linearization point; subsequent owner/run or
    input changes still require the existing owner/scheduler checks.  This
    read neither locks the attempt for the scan's lifetime nor promises that
    the database cannot change after it returns.
    A partially present environment, or one whose binding cannot be
    verified, is refused (:class:`InvalidJobBindingError`) instead of being
    accepted or silently falling back to the config window.  Only an
    environment without any job identifier is a standalone CLI.
    """

    # Imported lazily: the jobs package imports the service, which imports
    # this module, so a module-level import would be circular.
    from .jobs.fingerprint import compute_input_fingerprint
    from .jobs.models import TERMINAL_STATUSES
    from .jobs.scheduler_hook import (
        JOB_ENV_JOB_ID,
        JOB_ENV_OWNER_TOKEN,
        JOB_ENV_RUN_DIR,
        JOB_ENV_RUN_ID,
        JOB_ENV_STORE,
        session_job_context_from_env,
    )
    from .jobs.service import STORE_DB_NAME, STORE_DIR_NAME
    from .jobs.store import JobStore

    job_env_keys = (
        JOB_ENV_STORE,
        JOB_ENV_JOB_ID,
        JOB_ENV_RUN_ID,
        JOB_ENV_OWNER_TOKEN,
        JOB_ENV_RUN_DIR,
    )
    env = os.environ if environ is None else environ
    present = [key for key in job_env_keys if str(env.get(key) or "").strip()]
    if not present:
        return None
    context = session_job_context_from_env(env)
    if context is None:
        raise InvalidJobBindingError(
            "incomplete job binding environment ("
            + ", ".join(sorted(present))
            + " of the ZSCOPE_JOB_* identifiers); a scanner with job "
            "identifiers must run under its owner"
        )
    fingerprint = compute_input_fingerprint(
        _resolve_config_path(str(config_path) if config_path is not None else None),
        scan_depth=scan_depth,
    )
    project_store = Path(fingerprint["project_root"]) / STORE_DIR_NAME / STORE_DB_NAME
    store_path = Path(context.store_path).resolve()
    if store_path != project_store.resolve():
        raise InvalidJobBindingError("job binding rejected: store_project_mismatch")
    expected_run_dir = store_path.parent / context.job_id / context.run_id
    if Path(context.run_dir).resolve() != expected_run_dir.resolve():
        raise InvalidJobBindingError(
            "job binding rejected: run_dir does not match the job store layout "
            f"({context.run_dir} vs {expected_run_dir})"
        )
    # JobStore's connection may create a missing database.  A binding lookup
    # must not create one and then mistake it for the project's authority.
    if not store_path.is_file():
        raise InvalidJobBindingError("job binding rejected: store_unreadable")
    try:
        row = JobStore(store_path).get_job(context.job_id)
    except Exception as exc:
        raise InvalidJobBindingError("job binding rejected: store_unreadable") from exc
    if row is None:
        raise InvalidJobBindingError("job binding rejected: job_missing")
    # Do not call stand_down_reason and then re-read for the window: those
    # reads can straddle an owner/run change and authorize its new window
    # using the previous owner's identity.  Every check below uses this row.
    if row.get("run_id") != context.run_id:
        raise InvalidJobBindingError("job binding rejected: run_superseded")
    if row.get("owner_token") != context.owner_token:
        raise InvalidJobBindingError("job binding rejected: owner_token_mismatch")
    if row.get("status") in TERMINAL_STATUSES:
        raise InvalidJobBindingError("job binding rejected: job_terminal")
    if row.get("input_revision") != fingerprint["sha256"]:
        raise InvalidJobBindingError("job binding rejected: input_revision_changed")
    persisted_run_dir = row.get("run_dir")
    if (
        not isinstance(persisted_run_dir, str)
        or not persisted_run_dir.strip()
        or Path(persisted_run_dir).resolve() != expected_run_dir.resolve()
    ):
        raise InvalidJobBindingError("job binding rejected: persisted_run_dir_mismatch")
    raw_epoch = row.get("stop_at_epoch")
    return JobWindowAuthority(
        job_id=context.job_id,
        run_id=context.run_id,
        stop_at_epoch=_finite_persisted_epoch(raw_epoch) if raw_epoch is not None else None,
        resolved_stop_time=row.get("resolved_stop_time"),
    )


def expired_window_message(window: StopWindow) -> str:
    return (
        f"the configured execution.stop_at boundary {window.stop_at} "
        f"{window.timezone} ({window.resolved_stop_time.isoformat()}) has "
        "already passed; refusing to start a scan whose stop window is closed "
        "(the boundary is never silently rolled to tomorrow)"
    )


def expired_persisted_window_message(epoch: float, resolved_stop_time: Optional[str]) -> str:
    label = resolved_stop_time or datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    return (
        f"the job attempt's persisted stop window ({label}) has already "
        "passed; refusing to start a scan whose stop window is closed "
        "(the persisted boundary is never silently rolled)"
    )


def persisted_window_closed(window: PersistedStopWindow, *, now: Optional[datetime] = None) -> bool:
    """True when the resolved instant already passed (never re-resolved).

    Creation-side consumers use this to refuse a boundary that can only end
    the run before any work happens.  The instant is taken from the window
    that was resolved once; nothing here rolls it to the next occurrence.
    """

    if now is not None and (now.tzinfo is None or now.utcoffset() is None):
        raise ValueError("stop window remaining time requires a timezone-aware 'now'")
    reference = (now or datetime.now(timezone.utc)).timestamp()
    return window.stop_at_epoch - reference <= 0.0


def closed_persisted_window_message(window: PersistedStopWindow) -> str:
    """Human-readable refusal for an already-closed creation-time window."""

    return (
        f"the saved config's execution.stop_at boundary {window.requested_stop_at} "
        f"({window.resolved_local}) has already passed; refusing to start a job "
        "whose persisted stop window is closed (the boundary is never silently "
        "rolled to tomorrow)"
    )


__all__ = [
    "CONFIG_STOP_WINDOW_SOURCE",
    "ExpiredStopWindowError",
    "InvalidJobBindingError",
    "JOB_STOP_WINDOW_SOURCE",
    "JobWindowAuthority",
    "PersistedStopWindow",
    "SessionDeadlineGuard",
    "STOP_WINDOW_CANCEL_REASON",
    "arm_persisted_deadline",
    "arm_session_deadline",
    "closed_persisted_window_message",
    "expired_persisted_window_message",
    "expired_window_message",
    "persisted_window_closed",
    "remaining_seconds",
    "resolve_saved_config_stop_window",
    "session_cancellation_token",
    "session_stop_window_authority",
    "stop_window_from_config",
]
