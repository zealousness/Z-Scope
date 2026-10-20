"""Session-side work scheduler consuming the persistent scan job queue.

This module is the S08 session consumer of the already-accepted building
blocks: :class:`zscope.orchestration.jobs.work_queue.WorkQueue` (persistent,
deduplicating, fair, bounded) and
:class:`zscope.orchestration.jobs.scheduler_hook.JobWindowHook` (the
session-side window/cancel view of the job store).  It provides the
scheduling contract the coordinator wires into ``ScanSessionRunner`` /
``ParallelAnalyzer``; until that wiring exists it runs standalone (the tests
drive it directly and through a real owner/scanner subprocess pair) and must
not be treated as closing JOB04/JOB06 for the shared session.

Contract implemented here:

* Binding.  The scheduler binds exactly one job attempt: ``job_id`` /
  ``run_id`` / ``owner_token`` / ``input_revision`` are verified against the
  job store at construction and re-verified before *every* claim, every
  verdict and every acceptance of discovered children.  Binding reads alone
  do not authorize queue writes: each claim and each settlement runs inside
  :meth:`zscope.orchestration.jobs.store.JobStore.bound_attempt`, a write
  lock on the job row held until the queue transaction has committed
  (store → queue lock order; no store writes and no handler execution
  inside the lock), so a superseded run, a foreign owner token, a terminal
  job, a changed input revision — or a job row that cannot be read at all —
  can no longer slip between the binding check and the queue write.  The
  affected result is rejected wholesale (no completion, no deferral, no
  business question, no discovered child) and the item keeps its claim
  state for a later attempt to re-verify.  The work queue is opened bound
  to the job's current ``input_revision``; a changed input re-binds it
  through ``WorkQueue.open_for_recovery``, revoking old completions instead
  of granting them.  Reopening with an unchanged input keeps real remaining
  work and never re-executes completed identities.
* Callbacks.  Work callbacks are registered by the *current process* via
  :meth:`SessionWorkScheduler.register_handler`.  Nothing is restored from
  persisted JSON: no commands, argv, receipts, proofs or execution
  permissions live in the queue database, and items whose ``kind`` has no
  registered handler are deferred (``handler_not_registered``), never
  executed or faked.
* Window.  Every claim passes the job's ``stop_at`` epoch into the queue, so
  at or after the deadline no new work is claimed, while already claimed
  work finishes bounded: handlers receive a cooperative
  :class:`~zscope.common.cancellation.CancellationToken`, results arriving
  within the finalize grace are committed through the *current* claim token,
  interrupted work is deferred with an honest reason, and work whose handler
  never returned is abandoned (it stays active under its lease for a later
  resume).  Cancellation interrupts in-flight tokens immediately and exits
  within a bounded cancel grace.
* Fairness / remaining.  A settlement commits the verdict and its
  acceptable discovered children in ONE queue transaction
  (:meth:`zscope.orchestration.jobs.work_queue.WorkQueue.settle`): a process
  exit can no longer land between a durable parent verdict and its
  children, and any child-enqueue failure rolls the parent's verdict back —
  a parent is never completed while its discovered work is lost.
  Discoveries enter exactly the next batch (``frontier + 1``); duplicates
  are reported, never retried as new work; per-item attempts, deferral
  backoff and the batch chain stay bounded by the queue; deferred and
  long-pending items rotate back before newer easy work through the queue's
  claim order.  When the children would exceed a persisted bound
  (``max_batches`` or the queue capacity) the verdict is replaced by an
  explicit deferral (``discovery_batch_limit`` /
  ``discovery_queue_limit``), the unaccepted discoveries are counted as
  dropped and the whole round stops claiming — the blocked parent stays
  durable unresolved work with the handler as its replay source, never a
  silent loss inside a "drained" run.  The parked deferral survives a
  same-input resume as real remaining (it is neither claimable nor
  attempt-failed and a resumed round stops on it instead of busy-looping);
  only an input change re-pends and re-verifies it.  Business unknowns are recorded as
  questions plus a deferral — never a ``waiting_user`` state.  On exit the
  real remaining queue is persisted through the hook and measured progress
  is reported; with no measured denominator every number stays ``None``.
* Honesty.  Completions happen only through the queue's token-bound
  active-state transition; a verdict whose lease was re-assigned is rejected
  and recorded (``work_verdict_rejected``), never counted as done, and its
  discovered children are never enqueued.  Claim tokens and the owner token
  never appear in events, summaries or the persisted pending items.

Explicitly NOT provided here: this module does not wire into
``scan_session``/``ParallelAnalyzer`` (coordinator-owned), does not start or
kill any process (the detached owner owns that), does not interpret item
payloads beyond handing them to the registered in-process callback, and does
not write job terminal states (the owner owns those).
"""

from __future__ import annotations

import threading
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ...common.cancellation import CancellationError, CancellationToken
from .models import PHASE_FINALIZING, PHASE_SCANNING, TERMINAL_STATUSES, JobError
from .scheduler_hook import JobWindowHook
from .store import InstanceCompletionRequest, InstanceSettlementAck, JobStore, SettlementClaim
from .work_queue import (
    DEFER_REASON_DISCOVERY_BATCH_LIMIT,
    DEFER_REASON_DISCOVERY_QUEUE_LIMIT,
    WorkQueue,
)

SESSION_SCHEDULER_SCHEMA = "zscope.scan-job-session-scheduler.v1"

#: File name of the per-job work queue, stored next to the job's run
#: directories so it survives attempts (runs) of the same job.
WORK_QUEUE_FILENAME = "work-queue.db"

DEFER_REASON_HANDLER_MISSING = "handler_not_registered"
DEFER_REASON_HANDLER_ERROR = "handler_error"
DEFER_REASON_INTERRUPTED = "session_interrupted"

PENDING_SOURCE_DRAINED = "session_scheduler"
PENDING_SOURCE_WINDOW = "session_scheduler_window"
PENDING_SOURCE_CANCEL = "session_scheduler_cancel"
PENDING_SOURCE_BLOCKED = "session_scheduler_discovery_blocked"

_MAX_KIND_CHARS = 128
_MAX_REASON_CHARS = 480
_MAX_ABANDONED_EVENT_ITEMS = 50


@dataclass
class WorkComplete:
    """Handler outcome: the claimed work is done.

    ``detail`` is a small structured record persisted to the job events;
    ``discoveries`` are new work items entering exactly the next batch.
    """

    detail: Optional[Dict[str, Any]] = None
    discoveries: List[Dict[str, Any]] = field(default_factory=list)
    instance_completion: Optional[InstanceCompletionRequest] = field(default=None, repr=False)


@dataclass
class WorkDefer:
    """Handler outcome: the claimed work is not finished.

    ``reason`` is persisted with the deferral; ``retry_after_seconds``
    overrides the queue's exponential backoff.  ``question`` records a
    business unknown (JOB02): it becomes a ``work_question`` event plus this
    deferral — never a ``waiting_user`` state and never a silent drop.
    """

    reason: str
    retry_after_seconds: Optional[float] = None
    question: Optional[Dict[str, Any]] = None
    discoveries: List[Dict[str, Any]] = field(default_factory=list)


HandlerOutcome = Union[WorkComplete, WorkDefer]
WorkHandler = Callable[["ClaimedWork"], HandlerOutcome]


@dataclass(frozen=True)
class ClaimedWork:
    """The token-free view of a claimed item handed to the handler.

    The claim token never crosses into handler code: only the scheduler may
    commit a verdict, so a handler cannot complete or defer work whose lease
    was re-assigned, and tokens cannot leak into handler-written logs.
    """

    item_id: int
    kind: str
    scope_key: str
    build: Optional[str]
    payload: Dict[str, Any]
    batch_no: int
    attempts: int
    deferred_count: int
    last_defer_reason: Optional[str]
    deadline_epoch: Optional[float]
    cancellation: CancellationToken


def _bounded_reason(reason: str) -> str:
    text = str(reason or "unspecified").strip() or "unspecified"
    return text[:_MAX_REASON_CHARS]


class SessionWorkScheduler:
    """Bounded consumer of one job's persistent work queue.

    One instance serves one ``run()`` of one job attempt inside the scanner
    process.  The queue database is per *job* (not per run): a later attempt
    of the same job reopens it, keeps completed identities completed while
    the input revision is unchanged, and re-pends every verdict after a real
    input change.
    """

    def __init__(
        self,
        *,
        store_path: Path | str,
        job_id: str,
        run_id: str,
        owner_token: str,
        run_dir: Path | str,
        work_queue_path: Optional[Path | str] = None,
        worker_count: int = 1,
        claim_batch_size: int = 8,
        finalize_grace_seconds: float = 30.0,
        cancel_grace_seconds: float = 5.0,
        idle_poll_seconds: float = 0.05,
        progress_interval_seconds: float = 1.0,
        lease_seconds: float = 600.0,
        max_attempts: int = 3,
        max_batches: int = 32,
        defer_base_seconds: float = 1.0,
        defer_max_seconds: float = 3600.0,
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(job_id, str) or not job_id.strip():
            raise JobError("invalid_request", "job_id must be a non-empty string", status_code=400)
        if not isinstance(run_id, str) or not run_id.strip():
            raise JobError("invalid_request", "run_id must be a non-empty string", status_code=400)
        if not isinstance(owner_token, str) or not owner_token.strip():
            raise JobError(
                "invalid_request", "owner_token must be a non-empty string", status_code=400
            )
        if not isinstance(worker_count, int) or isinstance(worker_count, bool) or worker_count < 1:
            raise JobError(
                "invalid_request", "worker_count must be a positive integer", status_code=400
            )
        for name, value in (
            ("finalize_grace_seconds", finalize_grace_seconds),
            ("cancel_grace_seconds", cancel_grace_seconds),
            ("idle_poll_seconds", idle_poll_seconds),
            ("progress_interval_seconds", progress_interval_seconds),
        ):
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0.0:
                raise JobError(
                    "invalid_request", f"{name} must be a non-negative number", status_code=400
                )
        self.store_path = Path(store_path)
        self.job_id = job_id
        self.run_id = run_id
        self.owner_token = owner_token
        self.run_dir = Path(run_dir)
        self.worker_count = worker_count
        self.claim_batch_size = max(1, min(int(claim_batch_size), 1000))
        self.finalize_grace_seconds = float(finalize_grace_seconds)
        self.cancel_grace_seconds = float(cancel_grace_seconds)
        self.idle_poll_seconds = max(0.005, float(idle_poll_seconds))
        self.progress_interval_seconds = float(progress_interval_seconds)
        self._now = now_fn

        self._store = JobStore(self.store_path)
        job = self._store.get_job(self.job_id)
        if job is None:
            raise JobError(
                "job_not_found", f"no job row {self.job_id!r} in the job store", status_code=404
            )
        if job.get("run_id") != self.run_id:
            raise JobError(
                "attempt_superseded",
                "the job belongs to a different run; this scheduler stands down",
                status_code=409,
            )
        if job.get("owner_token") != self.owner_token:
            raise JobError(
                "owner_token_mismatch",
                "owner token does not match the job row; refusing to consume work",
                status_code=409,
            )
        if job.get("status") in TERMINAL_STATUSES:
            raise JobError(
                "job_terminal",
                f"job is already in terminal state {job.get('status')!r}",
                status_code=409,
            )
        input_revision = job.get("input_revision")
        if not isinstance(input_revision, str) or not input_revision:
            raise JobError(
                "invalid_binding",
                "job row has no input revision to bind the work queue",
                status_code=409,
            )
        self.input_revision = input_revision

        self._hook = JobWindowHook(
            self.store_path,
            job_id=self.job_id,
            run_id=self.run_id,
            owner_token=self.owner_token,
            run_dir=self.run_dir,
            input_revision=self.input_revision,
        )
        if work_queue_path is None:
            queue_path = self.store_path.parent / self.job_id / WORK_QUEUE_FILENAME
        else:
            queue_path = Path(work_queue_path)
        self._queue_bounds: Dict[str, Any] = {
            "lease_seconds": lease_seconds,
            "max_attempts": max_attempts,
            "max_batches": max_batches,
            "defer_base_seconds": defer_base_seconds,
            "defer_max_seconds": defer_max_seconds,
        }
        self.work_queue_path = queue_path
        self._queue = self._open_queue(queue_path)

        self._handlers: Dict[str, WorkHandler] = {}
        self._dispatch: "Queue[Optional[Dict[str, Any]]]" = Queue()
        self._results: "Queue[Tuple[Dict[str, Any], HandlerOutcome]]" = Queue()
        self._in_flight: Dict[int, Dict[str, Any]] = {}
        self._active_tokens: Dict[int, CancellationToken] = {}
        self._closing = False
        self._ran = False
        self._workers: List[threading.Thread] = []
        self._stood_down_reason: Optional[str] = None
        # Set when a settlement hit a persisted bound (batch/capacity): the
        # current scheduling round must stop claiming and keep the blocked
        # parent as explicit pending work.
        self._round_stop_request: Optional[str] = None

        # Run-lifetime counters (the queue snapshot stays the source of truth
        # for item states; these only count this run's outcomes).
        self._completed_run = 0
        self._deferred_run = 0
        self._rejected = 0
        self._questions = 0
        self._discoveries_enqueued = 0
        self._duplicates = 0
        self._discoveries_dropped = 0
        self._abandoned = 0
        self._last_progress_at = 0.0

    # -- public API -----------------------------------------------------------

    def register_handler(self, kind: str, handler: WorkHandler) -> None:
        """Register the in-process callback for one work ``kind``.

        Handlers are code, never persisted data: the queue database holds no
        callbacks, commands or execution permissions, and reopening a queue
        never restores a handler.  Items of an unregistered kind are deferred
        with ``handler_not_registered`` instead of being executed or dropped.
        """

        if not isinstance(kind, str) or not kind.strip():
            raise JobError("invalid_request", "kind must be a non-empty string", status_code=400)
        if len(kind) > _MAX_KIND_CHARS:
            raise JobError(
                "invalid_request",
                f"kind must be at most {_MAX_KIND_CHARS} characters",
                status_code=400,
            )
        if not callable(handler):
            raise JobError("invalid_request", "handler must be callable", status_code=400)
        self._handlers[kind.strip()] = handler

    @property
    def registered_kinds(self) -> List[str]:
        return sorted(self._handlers)

    def submit(self, items: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Submit work items into exactly the next open batch.

        The initial backlog and handler discoveries share this rule: the
        batch is always ``frontier + 1`` (the batch after the highest batch
        ever claimed), so new roots cannot jump ahead of the batch being
        worked.  Existing identities are reported as duplicates, never
        re-enqueued.
        """

        if not isinstance(items, (list, tuple)) or not items:
            raise JobError("invalid_request", "items must be a non-empty list", status_code=400)
        try:
            with self._store.bound_attempt(
                job_id=self.job_id,
                run_id=self.run_id,
                owner_token=self.owner_token,
                expected_input_revision=self.input_revision,
            ):
                frontier = int(self._queue.snapshot(now=self._now())["frontier_batch"])
                result = self._queue.enqueue(list(items), batch_no=frontier + 1)
        except JobError as exc:
            if exc.code in (
                "job_missing",
                "run_superseded",
                "owner_token_mismatch",
                "job_terminal",
                "input_revision_changed",
                "store_unreadable",
            ):
                self._stand_down("store_unreadable" if exc.code == "store_unreadable" else exc.code)
            raise
        self._emit(
            "work_submitted",
            f"submitted {len(result['enqueued'])} item(s) to batch {frontier + 1}",
            {
                "batch_no": frontier + 1,
                "enqueued": len(result["enqueued"]),
                "duplicates": len(result["duplicates"]),
            },
        )
        return result

    def snapshot(self) -> Dict[str, Any]:
        """Real queue state; counts are SQL counts, never estimates."""

        return self._queue.snapshot(now=self._now())

    def run(self) -> Dict[str, Any]:
        """Drain the queue bounded by the job window; return the run summary.

        The loop stops claiming at the ``stop_at`` deadline or a cancel
        request, finishes claimed work within the bounded grace, persists the
        real remaining queue through the hook and reports measured progress.
        """

        if self._ran:
            raise JobError(
                "invalid_state", "run() was already called on this scheduler", status_code=409
            )
        self._ran = True
        self._emit(
            "session_scheduler_started",
            "session work scheduler started",
            {
                "worker_count": self.worker_count,
                "work_queue": str(self.work_queue_path),
                "input_revision": self.input_revision,
                "registered_kinds": self.registered_kinds,
            },
        )
        self._hook.note_phase(PHASE_SCANNING)
        stop_cause: Optional[str] = None
        fatal: Optional[JobError] = None
        self._start_workers()
        try:
            while True:
                guard = self._binding_guard()
                if guard is not None:
                    self._stand_down(guard)
                    stop_cause = "stood_down"
                    break
                self._drain_results(block=False)
                self._report_progress()
                if stop_cause is None:
                    if self._hook.cancel_requested():
                        stop_cause = "cancel"
                        self._enter_finalize(stop_cause)
                    elif self._hook.stop_new_work():
                        stop_cause = "window"
                        self._enter_finalize(stop_cause)
                    elif self._round_stop_request is not None:
                        stop_cause = "discovery_blocked"
                        self._enter_finalize(stop_cause)
                if stop_cause is not None:
                    if not self._in_flight:
                        break
                    outcome = self._await_in_flight(stop_cause)
                    if outcome == "settled":
                        continue
                    if outcome == "stood_down":
                        stop_cause = "stood_down"
                    break
                free = self.worker_count - len(self._in_flight)
                if free > 0:
                    claim_outcome = self._claim_and_dispatch(free)
                    if claim_outcome == "stood_down":
                        stop_cause = "stood_down"
                        break
                    if claim_outcome == "window_closed":
                        stop_cause = "window"
                        self._enter_finalize(stop_cause)
                        continue
                    if not self._in_flight:
                        snapshot = self._queue.snapshot(now=self._now())
                        if snapshot["unresolved_count"] == 0:
                            break
                        parked_bound = self._parked_bound_code(snapshot)
                        if parked_bound is not None:
                            # Every remaining item is parked on a persisted
                            # discovery bound: no retry can change the bounds,
                            # so stop this round instead of busy-waiting on
                            # work that can never be claimed again.  The
                            # obligation stays durable unresolved remaining.
                            self._round_stop_request = parked_bound
                            stop_cause = "discovery_blocked"
                            self._enter_finalize(stop_cause)
                            continue
                        self._report_progress(snapshot=snapshot)
                        time.sleep(self.idle_poll_seconds)
                    else:
                        self._drain_results(block=True, timeout=self.idle_poll_seconds)
                else:
                    self._drain_results(block=True, timeout=0.05)
        except JobError as exc:
            fatal = exc
        finally:
            self._closing = True
            for _ in self._workers:
                self._dispatch.put(None)
        return self._finish(stop_cause, fatal)

    # -- queue binding ----------------------------------------------------------

    def _open_queue(self, queue_path: Path) -> WorkQueue:
        kwargs: Dict[str, Any] = {
            "job_id": self.job_id,
            "input_revision": self.input_revision,
            "project_root": None,
            **self._queue_bounds,
        }
        if not queue_path.exists():
            return WorkQueue(queue_path, **kwargs)
        try:
            return WorkQueue(queue_path, **kwargs)
        except JobError as exc:
            if exc.code != "input_revision_mismatch":
                raise
            recorded_revision = str(exc.details.get("recorded_input_revision", ""))
        recovered = WorkQueue.open_for_recovery(
            queue_path,
            job_id=self.job_id,
            new_input_revision=self.input_revision,
            **self._queue_bounds,
        )
        self._emit(
            "queue_recovered",
            "input revision changed; queue re-bound and previous verdicts re-pended",
            {
                "from_input_revision": recorded_revision,
                "to_input_revision": self.input_revision,
            },
        )
        return recovered

    # -- worker plumbing ----------------------------------------------------------

    def _start_workers(self) -> None:
        for index in range(self.worker_count):
            thread = threading.Thread(
                target=self._worker_loop,
                name=f"zscope-session-scheduler-{self.job_id}-{index}",
                daemon=True,
            )
            thread.start()
            self._workers.append(thread)

    def _worker_loop(self) -> None:
        while True:
            try:
                claimed = self._dispatch.get(timeout=0.2)
            except Empty:
                if self._closing:
                    return
                continue
            if claimed is None or self._closing:
                return
            outcome = self._execute(claimed)
            self._results.put((claimed, outcome))

    def _execute(self, claimed: Dict[str, Any]) -> HandlerOutcome:
        token = self._token_for(claimed)
        view = ClaimedWork(
            item_id=int(claimed["item_id"]),
            kind=str(claimed["kind"]),
            scope_key=str(claimed["scope_key"]),
            build=claimed.get("build"),
            payload=claimed.get("payload") or {},
            batch_no=int(claimed.get("batch_no") or 0),
            attempts=int(claimed.get("attempts") or 0),
            deferred_count=int(claimed.get("deferred_count") or 0),
            last_defer_reason=claimed.get("last_defer_reason"),
            deadline_epoch=claimed.get("claim_expires_at"),
            cancellation=token,
        )
        handler = self._handlers.get(view.kind)
        if handler is None:
            return WorkDefer(reason=DEFER_REASON_HANDLER_MISSING)
        try:
            outcome = handler(view)
        except CancellationError as exc:
            return WorkDefer(reason=_bounded_reason(f"{DEFER_REASON_INTERRUPTED}:{exc}"))
        except Exception as exc:  # a failing callback is bounded work, not a crash
            return WorkDefer(
                reason=_bounded_reason(f"{DEFER_REASON_HANDLER_ERROR}:{type(exc).__name__}: {exc}")
            )
        if not isinstance(outcome, (WorkComplete, WorkDefer)):
            return WorkDefer(
                reason=_bounded_reason(
                    f"{DEFER_REASON_HANDLER_ERROR}:handler_returned_{type(outcome).__name__}"
                )
            )
        return outcome

    def _token_for(self, claimed: Dict[str, Any]) -> CancellationToken:
        now_epoch = self._now()
        deadline_epoch = claimed.get("claim_expires_at")
        candidates: List[float] = []
        if isinstance(deadline_epoch, (int, float)):
            candidates.append(float(deadline_epoch))
        stop_at = self._hook.deadline_epoch()
        if stop_at is not None:
            candidates.append(float(stop_at) + self.finalize_grace_seconds)
        remaining = min((value - now_epoch for value in candidates), default=None)
        if remaining is None or remaining <= 0:
            token = CancellationToken()
        else:
            token = CancellationToken(timeout_seconds=remaining)
        self._active_tokens[int(claimed["item_id"])] = token
        return token

    def _claim_and_dispatch(self, free: int) -> str:
        """Claim up to ``free`` items after re-verifying the binding.

        Returns ``"claimed"`` (work dispatched), ``"window_closed"`` (the
        claim window reached its deadline; nothing was claimed) or
        ``"stood_down"`` (the binding no longer holds; nothing was claimed).
        The claim itself runs inside the store's ``bound_attempt`` lock, so
        a binding that flipped between the read guard and the queue write
        cannot claim under a dead attempt.
        """

        guard = self._binding_guard()
        if guard is not None:
            self._stand_down(guard)
            return "stood_down"
        try:
            with self._store.bound_attempt(
                job_id=self.job_id,
                run_id=self.run_id,
                owner_token=self.owner_token,
                expected_input_revision=self.input_revision,
            ):
                claim = self._queue.claim_batch(
                    min(free, self.claim_batch_size),
                    now=self._now(),
                    stop_time=self._hook.deadline_epoch(),
                )
        except JobError as exc:
            if exc.code == "queue_unavailable":
                raise
            self._stand_down("store_unreadable" if exc.code == "store_unreadable" else exc.code)
            return "stood_down"
        for item_id in claim["failed_exhausted"]:
            self._emit(
                "work_failed",
                f"item {item_id} exhausted its attempts",
                {"item_id": item_id, "fail_reason": "max_attempts_exhausted"},
            )
        if claim["window_closed"]:
            return "window_closed"
        for claimed in claim["claimed"]:
            self._in_flight[int(claimed["item_id"])] = claimed
            self._dispatch.put(claimed)
        return "claimed"

    # -- results ----------------------------------------------------------------

    def _drain_results(self, *, block: bool, timeout: float = 0.0) -> bool:
        """Move finished handler results into queue verdicts.

        Returns True when at least one result was processed.  Verdicts are
        always committed through the claim token of the *current* claim; a
        re-assigned lease rejects the verdict (recorded, never counted done).
        """

        processed = False
        while True:
            try:
                if block:
                    claimed, outcome = self._results.get(timeout=timeout)
                    block = False
                else:
                    claimed, outcome = self._results.get_nowait()
            except Empty:
                return processed
            processed = True
            self._settle(claimed, outcome)

    def _settle(self, claimed: Dict[str, Any], outcome: HandlerOutcome) -> None:
        """Commit one handler result atomically with its discovered children.

        The job-store attempt binding is held under a write lock
        (:meth:`zscope.orchestration.jobs.store.JobStore.bound_attempt`)
        while the queue settles the verdict *and* enqueues every acceptable
        child in one transaction, so neither a binding flip nor a process
        exit can land between the parent verdict and its children.  A
        verdict whose binding no longer holds (old run, foreign owner token,
        changed input revision, unreadable store) or whose claim token is
        stale is rejected wholesale — no completion, no deferral, no business
        question, no children — and the item keeps its claim state for a
        later attempt to re-verify.

        When the children hit a persisted bound (``max_batches`` or the
        queue capacity) the queue replaces the verdict with an explicit
        deferral; the scheduler counts the unaccepted discoveries as dropped
        and stops the whole round — the obligation stays durable unresolved
        work instead of silently disappearing into a "drained" run.
        """

        item_id = int(claimed["item_id"])
        self._in_flight.pop(item_id, None)
        self._active_tokens.pop(item_id, None)
        identity = {
            "item_id": item_id,
            "kind": claimed.get("kind"),
            "scope_key": claimed.get("scope_key"),
            "build": claimed.get("build"),
            "batch_no": claimed.get("batch_no"),
        }
        guard = self._binding_guard()
        if guard is not None:
            self._rejected += 1
            self._emit(
                "work_verdict_rejected",
                f"verdict for item {claimed.get('scope_key')!r} was rejected; the "
                f"attempt binding no longer holds ({guard})",
                {**identity, "action": "settle", "code": "binding_changed", "reason": guard},
            )
            if outcome.discoveries:
                self._discoveries_dropped += len(outcome.discoveries)
            return
        if isinstance(outcome, WorkDefer):
            action = "defer"
            reason = _bounded_reason(outcome.reason)
            retry_after = outcome.retry_after_seconds
        else:
            action = "complete"
            reason = None
            retry_after = None
        # Lock order is store → queue: the job-row write lock is held while
        # the queue transaction commits, and no store writes (events,
        # progress) happen inside the block.
        instance_ack: Optional[InstanceSettlementAck] = None
        request = outcome.instance_completion if isinstance(outcome, WorkComplete) else None
        try:
            if request is not None:
                if (
                    request.current.job_id != self.job_id
                    or request.current.run_id != self.run_id
                    or request.current.owner_token != self.owner_token
                    or request.current.input_revision != self.input_revision
                    or request.current.run_dir.resolve() != self.run_dir.resolve()
                ):
                    raise JobError(
                        "invalid_instance_binding",
                        "handler attempt coordinates mismatch",
                        status_code=409,
                    )
                instance_ack = self._store.settle_instance_result(
                    current=request.current,
                    queue=self._queue,
                    claim=SettlementClaim(
                        item_id=item_id,
                        claim_token=claimed["claim_token"],
                        kind=str(claimed.get("kind") or ""),
                        scope_key=str(claimed.get("scope_key") or ""),
                        build=str(claimed.get("build") or ""),
                    ),
                    expected=request.expected,
                    instance=request.instance,
                    semantics_digest=request.semantics_digest,
                    mode=request.mode,
                    prepared=request.prepared,
                    restored_receipt=request.restored_receipt,
                    discoveries=list(outcome.discoveries),
                    input_current_guard=request.input_current_guard,
                    now=self._now(),
                )
                result = json.loads(instance_ack.queue_result_json)
            else:
                with self._store.bound_attempt(
                    job_id=self.job_id,
                    run_id=self.run_id,
                    owner_token=self.owner_token,
                    expected_input_revision=self.input_revision,
                ):
                    result = self._queue.settle(
                        item_id,
                        action=action,
                        claim_token=claimed["claim_token"],
                        reason=reason,
                        retry_after_seconds=retry_after,
                        discoveries=list(outcome.discoveries),
                        expected_input_revision=self.input_revision,
                        now=self._now(),
                    )
        except JobError as exc:
            self._handle_verdict_rejection(exc, identity, action, outcome)
            return
        # The verdict and its children are durably committed; observability
        # counters and events happen after the locks are released.
        if instance_ack is not None and instance_ack.committed and request is not None:
            request.accept_settlement(instance_ack)
        self._discoveries_enqueued += len(result["enqueued"])
        self._duplicates += len(result["duplicates"])
        if result["duplicates"]:
            self._emit(
                "work_discoveries_deduplicated",
                f"{len(result['duplicates'])} discovered item(s) already tracked",
                {"count": len(result["duplicates"])},
            )
        blocked = result.get("discovery_blocked")
        if blocked is not None:
            unaccepted = len(outcome.discoveries) - len(result["duplicates"])
            self._discoveries_dropped += max(0, unaccepted)
            if self._round_stop_request is None:
                self._round_stop_request = str(blocked)
                self._emit(
                    "discovery_blocked",
                    f"discovered children cannot be scheduled under the persisted "
                    f"bounds ({blocked}); the parent stays explicit pending work "
                    "and this round stops claiming",
                    {**identity, "reason": result.get("reason"), "blocked": blocked},
                )
        if result["status"] == "completed":
            self._completed_run += 1
            data: Dict[str, Any] = dict(identity)
            detail = outcome.detail if isinstance(outcome, WorkComplete) else None
            if detail:
                data["detail"] = detail
            self._emit("work_completed", f"item {claimed.get('scope_key')!r} completed", data)
            return
        if result["status"] == "failed":
            # The deferral hit the attempt bound and the item failed; no
            # business question is recorded for a verdict that did not defer.
            self._emit(
                "work_failed",
                f"item {claimed.get('scope_key')!r} exhausted its attempts",
                {**identity, "fail_reason": result.get("reason")},
            )
            return
        self._deferred_run += 1
        # A blocked settlement defers even a WorkComplete outcome, so the
        # question is read defensively from the handler result.
        question = outcome.question if isinstance(outcome, WorkDefer) else None
        if question is not None:
            self._questions += 1
            self._emit(
                "work_question",
                f"business unknown recorded for {claimed.get('scope_key')!r}; "
                "work deferred, not waiting for a user",
                {**identity, "question": question},
            )
        self._emit(
            "work_deferred",
            f"item {claimed.get('scope_key')!r} deferred: {result.get('reason')}",
            {**identity, "reason": result.get("reason")},
        )

    def _binding_guard(self) -> Optional[str]:
        """Re-verify job/run/owner/input against the live job row.

        ``None`` means the binding verifiably still holds.  A row that
        cannot be read is not authorization: ``store_unreadable`` stands the
        run down and keeps the gap instead of guessing.
        """

        return self._hook.stand_down_reason(expected_input_revision=self.input_revision)

    @staticmethod
    def _parked_bound_code(snapshot: Dict[str, Any]) -> Optional[str]:
        """The discovery bound parking *every* remaining item, if any.

        A same-input resume must not drain parked obligations, fail them by
        attempt accounting or busy-loop on them; when nothing else remains
        the round stops with ``discovery_blocked`` instead.
        """

        unresolved = int(snapshot.get("unresolved_count") or 0)
        parked = int(snapshot.get("discovery_blocked_count") or 0)
        if unresolved <= 0 or parked < unresolved:
            return None
        for entry in snapshot.get("remaining", []):
            reason = entry.get("reason")
            if reason == DEFER_REASON_DISCOVERY_BATCH_LIMIT:
                return "batch_limit"
            if reason == DEFER_REASON_DISCOVERY_QUEUE_LIMIT:
                return "queue_limit"
        return "batch_limit" if parked else None

    def _handle_verdict_rejection(
        self, exc: JobError, identity: Dict[str, Any], action: str, outcome: HandlerOutcome
    ) -> None:
        if exc.code == "discovery_invalid":
            # Malformed children rolled the parent's verdict back: the item
            # keeps its claim state and the handler replays on a later
            # attempt; nothing was enqueued.
            self._rejected += 1
            self._discoveries_dropped += len(outcome.discoveries)
            self._emit(
                "work_verdict_rejected",
                f"{action} verdict for item {identity.get('scope_key')!r} was rolled "
                "back: the handler produced an invalid discovered child",
                {**identity, "action": action, "code": exc.code},
            )
            return
        if exc.code in ("stale_claim", "invalid_state"):
            self._rejected += 1
            if outcome.discoveries:
                self._discoveries_dropped += len(outcome.discoveries)
            self._emit(
                "work_verdict_rejected",
                f"{action} verdict for item {identity.get('scope_key')!r} was rejected "
                f"({exc.code}); the claim no longer belongs to this run",
                {**identity, "action": action, "code": exc.code},
            )
            return
        if exc.code in (
            "job_missing",
            "run_superseded",
            "owner_token_mismatch",
            "job_terminal",
            "input_revision_changed",
            "input_revision_mismatch",
            "store_unreadable",
        ):
            self._rejected += 1
            if outcome.discoveries:
                self._discoveries_dropped += len(outcome.discoveries)
            self._emit(
                "work_verdict_rejected",
                f"{action} verdict for item {identity.get('scope_key')!r} was rejected; "
                f"the attempt binding no longer holds ({exc.code})",
                {**identity, "action": action, "code": "binding_changed", "reason": exc.code},
            )
            return
        raise exc

    # -- finalization -------------------------------------------------------------

    def _enter_finalize(self, cause: str) -> None:
        self._hook.note_phase(PHASE_FINALIZING)
        if cause == "cancel":
            for token in list(self._active_tokens.values()):
                token.cancel("cancelled")
            self._emit(
                "session_scheduler_cancelled",
                "cancel observed; no new claims, in-flight work interrupted bounded",
                {"in_flight": len(self._in_flight)},
            )
        elif cause == "discovery_blocked":
            self._emit(
                "session_scheduler_discovery_blocked",
                "discovered children cannot be scheduled under the persisted "
                "bounds; no new claims this round, the blocked parent stays "
                "explicit pending work",
                {"in_flight": len(self._in_flight), "blocked": self._round_stop_request},
            )
        else:
            self._emit(
                "session_scheduler_window_closed",
                "stop window reached; no new claims, claimed work finishes bounded",
                {"in_flight": len(self._in_flight)},
            )

    def _await_in_flight(self, stop_cause: str) -> str:
        """Wait bounded for in-flight results.

        Returns ``"settled"`` when every in-flight item got a verdict,
        ``"abandoned"`` when the grace expired (the leftover items stay
        active under their leases for a later resume) or ``"stood_down"``
        when the attempt lost the job while finalizing (no more verdicts).
        """

        grace = self.cancel_grace_seconds if stop_cause == "cancel" else self.finalize_grace_seconds
        deadline = time.monotonic() + grace
        while self._in_flight:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                abandoned = sorted(self._in_flight)
                self._abandoned += len(abandoned)
                self._emit(
                    "work_abandoned",
                    f"{len(abandoned)} in-flight item(s) did not finish within the "
                    "finalize grace; left active under their leases for a later resume",
                    {"count": len(abandoned), "item_ids": abandoned[:_MAX_ABANDONED_EVENT_ITEMS]},
                )
                return "abandoned"
            reason = self._binding_guard()
            if reason is not None:
                self._stand_down(reason)
                return "stood_down"
            self._drain_results(block=True, timeout=min(remaining, 0.1))
        return "settled"

    def _stand_down(self, reason: str) -> None:
        """Record the stand-down (first reason wins) and stop consuming.

        In-flight items keep their claim state — a later attempt re-verifies
        them; nothing is completed, deferred or discovered by this run.
        """

        if self._stood_down_reason is not None:
            return
        self._stood_down_reason = reason
        self._emit(
            "session_scheduler_stood_down",
            f"scheduler stands down: {reason}",
            {"reason": reason, "in_flight": len(self._in_flight)},
        )

    def _report_progress(
        self, *, force: bool = False, snapshot: Optional[Dict[str, Any]] = None
    ) -> None:
        now = time.monotonic()
        if not force and now - self._last_progress_at < self.progress_interval_seconds:
            return
        self._last_progress_at = now
        snap = snapshot if snapshot is not None else self._queue.snapshot(now=self._now())
        counts = snap["counts"]
        measured = counts["completed"] + counts["failed"] + snap["unresolved_count"]
        if measured <= 0:
            # No measured denominator: every number stays unknown.
            self._hook.note_progress()
            return
        self._hook.note_progress(
            completed=counts["completed"],
            total=measured,
            active=counts["active"],
            deferred=counts["deferred"],
            unit="work_items",
        )

    def _finish(self, stop_cause: Optional[str], fatal: Optional[JobError]) -> Dict[str, Any]:
        snapshot: Optional[Dict[str, Any]] = None
        pending_path: Optional[Path] = None
        if fatal is None and stop_cause != "stood_down":
            snapshot = self._queue.snapshot(now=self._now())
            source = {
                "window": PENDING_SOURCE_WINDOW,
                "cancel": PENDING_SOURCE_CANCEL,
                "discovery_blocked": PENDING_SOURCE_BLOCKED,
            }.get(stop_cause or "", PENDING_SOURCE_DRAINED)
            pending_path = self._hook.persist_pending(snapshot["remaining"], source=source)
            self._report_progress(force=True, snapshot=snapshot)
        status = "aborted" if fatal is not None else self._status_of(stop_cause)
        if fatal is not None:
            self._emit(
                "session_scheduler_aborted",
                f"scheduler aborted after a queue error: {fatal.code}",
                {"code": fatal.code, "message": fatal.message[:200]},
            )
        else:
            self._emit(
                "session_scheduler_finished",
                f"scheduler finished with status {status}",
                {
                    "status": status,
                    "completed_this_run": self._completed_run,
                    "deferred_this_run": self._deferred_run,
                    "abandoned_in_flight": self._abandoned,
                },
            )
        counts = snapshot["counts"] if snapshot else None
        return {
            "schema": SESSION_SCHEDULER_SCHEMA,
            "job_id": self.job_id,
            "run_id": self.run_id,
            "input_revision": self.input_revision,
            "status": status,
            "stood_down_reason": self._stood_down_reason,
            "window_closed": stop_cause == "window",
            "cancel_observed": stop_cause == "cancel",
            "discovery_blocked": self._round_stop_request,
            "error": {"code": fatal.code, "message": fatal.message} if fatal is not None else None,
            "counts": counts,
            "completed_this_run": self._completed_run,
            "deferred_this_run": self._deferred_run,
            "rejected_verdicts": self._rejected,
            "questions_recorded": self._questions,
            "discoveries_enqueued": self._discoveries_enqueued,
            "duplicates": self._duplicates,
            "discoveries_dropped": self._discoveries_dropped,
            "abandoned_in_flight": self._abandoned,
            "pending_path": str(pending_path) if pending_path is not None else None,
            "remaining_count": snapshot["unresolved_count"] if snapshot else None,
        }

    @staticmethod
    def _status_of(stop_cause: Optional[str]) -> str:
        if stop_cause == "window":
            return "window_closed"
        if stop_cause == "cancel":
            return "cancelled"
        if stop_cause == "stood_down":
            return "stood_down"
        if stop_cause == "discovery_blocked":
            return "discovery_blocked"
        return "drained"

    # -- events ------------------------------------------------------------------

    def _emit(self, kind: str, message: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Append a job event; observability must never kill the scheduler.

        Events never contain claim tokens or the owner token.
        """

        try:
            self._store.append_event(
                self.job_id, run_id=self.run_id, kind=kind, message=message, data=data
            )
        except Exception:
            pass
