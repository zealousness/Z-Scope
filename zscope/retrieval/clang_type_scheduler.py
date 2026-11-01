"""One execution permit for background and demand-driven type materialization.

Parked worker stacks retain function continuations. Only the coordinator owns
the disk cache and publishes SQLite; callers merely register independent waiters.
"""

from __future__ import annotations

import logging
import json
import os
import queue
import threading
import time
import uuid
from collections import deque
from concurrent.futures import Future, TimeoutError as FutureTimeout
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Iterator

from . import clang_type_state as state
from .clang_type_worker import FunctionTypeCollector, TypeCollectionCancelled
from .knowledge_db import KnowledgeDB
from .indexing_identity import atomic_json

logger = logging.getLogger(__name__)
WAIT_SECONDS = 300.0
IDLE_SECONDS = 60.0
HEARTBEAT_SECONDS = 30.0
MAX_CONTINUATIONS = 8


@dataclass
class Waiter:
    future: Future[Any]
    deadline: float
    started: float


@dataclass
class Job:
    record: dict[str, Any]
    waiters: list[Waiter] = field(default_factory=list)
    attempt: str = ""
    thread: threading.Thread | None = None
    runnable: bool = True
    cancelled: bool = False
    turn: int = 0


class FunctionTypeScheduler:
    def __init__(
        self,
        backend: Any,
        *,
        collector_factory: Callable[..., Any] = FunctionTypeCollector,
        own_connection: bool = False,
    ):
        self._own_connection = own_connection
        self.db = KnowledgeDB(str(backend._db._db_path)) if own_connection else backend._db
        self.backend = (
            SimpleNamespace(**{**vars(backend), "_db": self.db}) if own_connection else backend
        )
        self.generation = self.db.get_metadata(state.GENERATION_KEY)
        self.collector_factory = collector_factory
        self.backend._type_ref_cache_nonce = uuid.uuid4().hex
        self.engine: Any = None
        self._events: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self._condition = threading.Condition()
        self._closing = False
        self._pauses = 0
        self._quiescent = threading.Event()
        self._quiescent.set()
        self._jobs: dict[int, Job] = {}
        self._unvalidated: list[tuple[dict[str, Any], Waiter]] = []
        self._admitted: dict[int, tuple[dict[str, Any], Waiter]] = {}
        self._active: Job | None = None
        self._turn = 0
        self._global_error: state.TypeContextUnavailable | None = None
        self._inputs_invalidated = False
        self._idle_since = time.monotonic()
        self._started_at = self._idle_since
        self._last_checkpoint = time.monotonic()
        self._last_resource_check = 0.0
        self._retired_rpc_count = 0
        self._session_metrics: deque[dict[str, Any]] = deque(maxlen=16)
        self._background_page: deque[dict[str, Any]] = deque()
        self._background_after: tuple[str, int, int] = ("", -1, -1)
        self._latencies: deque[float] = deque(maxlen=256)
        self._stats: dict[str, Any] = dict(
            completed=0,
            failed=0,
            joined=0,
            yields=0,
            requests=0,
            timed_out=0,
            background_completed=0,
            demand_completed=0,
            prepare_seconds=0.0,
            wait_sum_seconds=0.0,
        )
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._run, name="ClangTypeCoordinator", daemon=True)
        self._heartbeat = threading.Thread(
            target=self._log_loop, name="ClangTypeHeartbeat", daemon=True
        )
        self._thread.start()
        self._heartbeat.start()

    def ensure(self, record: dict[str, Any], *, deadline: float | None = None) -> None:
        started = time.monotonic()
        deadline = started + WAIT_SECONDS if deadline is None else deadline
        future: Future[Any] = Future()
        waiter = Waiter(future, deadline, started)
        if not self._condition.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise state.TypeContextUnavailable("type_context_timeout")
        try:
            if self._closing:
                raise state.TypeContextUnavailable("backend_closed")
            self._admitted[id(waiter)] = (record, waiter)
            self._stats["requests"] += 1
            self._events.put(("request", record, waiter))
            self._condition.notify_all()
        finally:
            self._condition.release()
        try:
            future.result(timeout=max(0.0, deadline - time.monotonic()))
        except FutureTimeout:
            self._events.put(("expired", waiter))
            # A slow validation/publication must not extend this caller's deadline.
            # The coordinator polls the queue even when notification is skipped.
            if self._condition.acquire(blocking=False):
                try:
                    self._condition.notify_all()
                finally:
                    self._condition.release()
            raise state.TypeContextUnavailable(
                "type_context_timeout", "Function type context wait exceeded 300 seconds"
            ) from None

    def drain_background(self, *, timeout_seconds: float = WAIT_SECONDS) -> dict[str, Any]:
        """Wait until the current native type generation is fully published.

        Instance semantics freeze exact native receipts.  Letting the background
        coordinator publish another function after that point would correctly
        invalidate those receipts in the middle of a scan.  Fast project scans
        therefore use this barrier before freezing their semantics manifest.
        It does not authorize partial output: a tool failure or timeout is a
        hard error and the caller must not form a formal scan result.
        """

        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        with self._condition:
            while True:
                counts = state.counts(self.db)
                if counts.get("pending", 0) == 0 and counts.get("in_progress", 0) == 0:
                    return dict(self.snapshot(), functions=counts)
                if self._closing:
                    raise state.TypeContextUnavailable("backend_closed")
                if self._global_error is not None:
                    raise self._global_error
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise state.TypeContextUnavailable(
                        "type_context_timeout",
                        "Function type background materialization did not settle before scan",
                    )
                self._condition.notify_all()
                self._condition.wait(min(0.1, remaining))

    @contextmanager
    def paused(self) -> Iterator[None]:
        with self._condition:
            self._pauses += 1
            self._quiescent.clear()
            self._condition.notify_all()
        self._interrupt()
        try:
            if not self._quiescent.wait(15):
                raise state.TypeContextUnavailable("type_collection_pause_timeout")
            yield
        finally:
            with self._condition:
                self._pauses -= 1
                self._condition.notify_all()

    def _interrupt(self) -> None:
        engine = self.engine
        if engine is not None:
            engine.interrupt()

    def close(self) -> None:
        with self._condition:
            self._closing = True
            self._condition.notify_all()
        self._interrupt()
        self._thread.join(timeout=15)
        if self._thread.is_alive():
            # Do not close KnowledgeDB underneath its live owner.
            raise RuntimeError("type reference coordinator did not stop")
        if any(job.thread and job.thread.is_alive() for job in self._jobs.values()):
            raise RuntimeError("type reference continuation did not stop")
        self._heartbeat.join(timeout=15)
        if self._heartbeat.is_alive():
            raise RuntimeError("type heartbeat did not stop")
        if self._own_connection:
            self.db.close()

    def snapshot(self) -> dict[str, Any]:
        with self._condition:
            jobs = list(self._jobs.values())
            now = time.monotonic()
            admitted = list(self._admitted.values())
            waiting = [w for _, w in admitted if not w.future.done()]
            latencies = sorted(self._latencies)
            return dict(
                self._stats,
                foreground=len({record["id"] for record, w in admitted if not w.future.done()}),
                elapsed_seconds=now - self._started_at,
                functions_per_second=self._stats["completed"] / max(0.001, now - self._started_at),
                retired_rpc_count=self._retired_rpc_count,
                continuations=sum(job.thread is not None for job in jobs),
                active=(
                    "{name}@{file_path}:{start_line}".format(**self._active.record)
                    if self._active
                    else ""
                ),
                paused=bool(self._pauses),
                error=str(self._global_error or ""),
                oldest_wait_seconds=max((now - w.started for w in waiting), default=0),
                p95_wait_seconds=(
                    latencies[max(0, (len(latencies) * 95 + 99) // 100 - 1)] if latencies else 0
                ),
                average_wait_seconds=self._stats["wait_sum_seconds"]
                / max(1, self._stats["requests"]),
            )

    def _log_loop(self) -> None:
        while not self._stopped.wait(HEARTBEAT_SECONDS):
            try:
                summary = state.counts(self.db)
                metrics = self.engine.metrics() if self.engine is not None else {}
                with self._condition:
                    self._stats.update(functions=summary)
                snapshot = self.snapshot()
                if (
                    snapshot["continuations"]
                    or snapshot["foreground"]
                    or any(summary[k] for k in ("pending", "in_progress", "failed"))
                ):
                    logger.info("[function-type-refs] %s", dict(snapshot, **metrics))
            except Exception:
                logger.debug("Type heartbeat raced with backend shutdown", exc_info=True)

    def _complete_waiter(self, waiter: Waiter, error: BaseException | None = None) -> None:
        if waiter.future.done():
            return
        with self._condition:
            self._admitted.pop(id(waiter), None)
        latency = time.monotonic() - waiter.started
        self._latencies.append(latency)
        self._stats["wait_sum_seconds"] += latency
        if error is None:
            waiter.future.set_result(None)
        else:
            waiter.future.set_exception(error)

    def _register(
        self, record: dict[str, Any], waiter: Waiter, *, retry_global: bool = False
    ) -> None:
        if time.monotonic() >= waiter.deadline:
            self._complete_waiter(waiter, state.TypeContextUnavailable("type_context_timeout"))
            return
        if self._global_error:
            if (
                retry_global
                and self.engine is None
                and self._global_error.reason in {"clangd_unavailable", "resource_memory_exceeded"}
            ):
                self._global_error = None
                self._unvalidated.append((record, waiter))
                return
            self._complete_waiter(waiter, self._global_error)
            return
        if not self.engine:
            self._unvalidated.append((record, waiter))
            return
        if record["generation"] != self.generation:
            self._complete_waiter(waiter, state.TypeContextUnavailable("base_generation_changed"))
            return
        try:
            self.engine.check_inputs(record)
        except state.TypeContextUnavailable as error:
            self._global_error = error
            self._complete_waiter(waiter, error)
            return
        current = self.db._conn.execute(
            "SELECT status FROM function_type_ref_state WHERE function_id=? AND generation=?",
            (record["id"], self.generation),
        ).fetchone()
        if current and current[0] == "current":
            self._stats["current_hits"] = self._stats.get("current_hits", 0) + 1
            self._complete_waiter(waiter)
            return
        if not current:
            self._complete_waiter(waiter, state.TypeContextUnavailable("function_deleted"))
            return
        job = self._jobs.get(record["id"])
        if job is None:
            job = self._jobs[record["id"]] = Job(record)
        else:
            self._stats["joined"] += 1
        job.waiters.append(waiter)

    def _checkpoint(self, job: Job) -> None:
        with self._condition:
            if job.cancelled or self._closing or self._pauses or self._global_error:
                raise TypeCollectionCancelled()
            job.runnable = False
            self._events.put(("yield", job))
            self._condition.notify_all()
            while self._active is not job or not job.runnable:
                if job.cancelled or self._closing or self._pauses or self._global_error:
                    raise TypeCollectionCancelled()
                self._condition.wait()

    def _worker(self, job: Job) -> None:
        result, error = None, None
        try:
            with self._condition:
                while self._active is not job:
                    if job.cancelled or self._closing or self._pauses:
                        raise TypeCollectionCancelled()
                    self._condition.wait()
            result = self.engine.collect(job.record, lambda: self._checkpoint(job))
        except BaseException as exc:
            error = exc
        finally:
            with self._condition:
                self._events.put(("done", job, result, error))
                self._condition.notify_all()

    def _done(self, job: Job, rows: Any, error: BaseException | None) -> None:
        from .clang_source_snapshot import SourceInputsChanged

        if isinstance(error, SourceInputsChanged):
            error = state.TypeContextUnavailable("inputs_changed", str(error))
        if self._active is job:
            self._active = None
        if job.thread:
            job.thread.join()
            job.thread = None
        if isinstance(error, TypeCollectionCancelled):
            state.release(self.db, job.record["id"], self.generation, job.attempt)
            job.cancelled = False
            job.runnable = True
            if not job.waiters:
                self._jobs.pop(job.record["id"], None)
            return
        try:
            if error is None:
                # Correctness boundary: never publish rows against inputs that
                # were not live-verified after collection finished.
                self.engine.check_inputs(job.record, verify=True)
            if not state.finish(
                self.db,
                job.record["id"],
                self.generation,
                job.attempt,
                rows if error is None else None,
                str(error or ""),
            ):
                error = state.TypeContextUnavailable("base_generation_changed")
        except Exception as exc:
            error = exc
            state.release(self.db, job.record["id"], self.generation, job.attempt)
        if error is not None:
            if isinstance(error, state.TypeContextUnavailable) and error.reason in {
                "inputs_changed",
                "base_generation_changed",
                "clangd_unavailable",
            }:
                self._global_error = error
            self._stats["failed"] += 1
            if self._stats["failed"] <= 3:
                logger.warning(
                    "[function-type-refs-failed] function=%s reason=%s",
                    job.record["identity"],
                    error,
                )
            error = (
                error
                if isinstance(error, state.TypeContextUnavailable)
                else state.TypeContextUnavailable("type_collection_failed", str(error))
            )
        else:
            self._stats["completed"] += 1
            self._stats["demand_completed" if job.waiters else "background_completed"] += 1
        for waiter in job.waiters:
            self._complete_waiter(waiter, error)
        self._jobs.pop(job.record["id"], None)
        if self.engine.cache:
            self.engine.cache.checkpoint()

    def _events_pass(self) -> None:
        for _ in range(128):
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            if event[0] == "request":
                self._register(event[1], event[2], retry_global=True)
            elif event[0] == "expired":
                self._stats["timed_out"] += 1
                self._complete_waiter(
                    event[1], state.TypeContextUnavailable("type_context_timeout")
                )
            elif event[0] == "yield":
                job = event[1]
                if self._active is job:
                    self._active = None
                self._turn += 1
                job.turn = self._turn
                job.runnable = True
                self._stats["yields"] += 1
            else:
                self._done(event[1], event[2], event[3])
        now = time.monotonic()
        for job in self._jobs.values():
            for waiter in job.waiters:
                if now >= waiter.deadline and not waiter.future.done():
                    self._complete_waiter(
                        waiter, state.TypeContextUnavailable("type_context_timeout")
                    )
            job.waiters[:] = [w for w in job.waiters if not w.future.done()]

    def _background(self) -> dict[str, Any] | None:
        if not self._background_page:
            file, line, identifier = self._background_after
            rows = self.db._conn.execute(
                "SELECT f.*,s.identity,s.context,s.generation FROM function_type_ref_state s "
                "JOIN functions f ON f.id=s.function_id WHERE s.generation=? AND s.status='pending' "
                "AND s.file_path>=? AND (s.file_path>? OR s.start_line>? "
                "OR (s.start_line=? AND s.function_id>?)) "
                "ORDER BY s.file_path,s.start_line,s.function_id LIMIT 64",
                (self.generation, file, file, line, line, identifier),
            ).fetchall()
            self._background_page.extend(dict(row) for row in rows)
        if self._background_page:
            result = self._background_page.popleft()
            self._background_after = (result["file_path"], result["start_line"], result["id"])
            return result
        # Earlier functions can become pending again after a pause. Rewind only
        # at the end of a page walk; never sort the entire remaining queue per job.
        self._background_after = ("", -1, -1)
        row = self.db._conn.execute(
            "SELECT f.*,s.identity,s.context,s.generation FROM function_type_ref_state s "
            "JOIN functions f ON f.id=s.function_id WHERE s.generation=? AND s.status='failed' "
            "AND s.retry_count<=3 AND s.retry_after<=? ORDER BY s.retry_after LIMIT 1",
            (self.generation, time.time()),
        ).fetchone()
        return dict(row) if row else None

    def _has_background(self) -> bool:
        return bool(
            self.db._conn.execute(
                "SELECT 1 FROM function_type_ref_state WHERE generation=? AND "
                "(status='pending' OR (status='failed' AND retry_count<=3 AND retry_after<=?)) LIMIT 1",
                (self.generation, time.time()),
            ).fetchone()
        )

    def _prepare(self) -> None:
        self._quiescent.clear()
        self.engine = self.collector_factory(self.backend)
        with self._condition:
            if self._closing or self._pauses:
                self.engine.close()
                self.engine = None
                self._quiescent.set()
                return
        try:
            self.engine.prepare()
            previous = self.db.get_metadata("clang_type_refs_epoch")
            invalidate = previous != self.engine.epoch
            state.reset_unfinished(self.db, self.generation, invalidate=invalidate)
            self._background_page.clear()
            self._background_after = ("", -1, -1)
            self.db.set_metadata("clang_type_refs_epoch", self.engine.epoch)
        except TypeCollectionCancelled:
            self.engine.close()
            self.engine = None
            return
        except Exception as exc:
            self._global_error = (
                exc
                if isinstance(exc, state.TypeContextUnavailable)
                else state.TypeContextUnavailable("clangd_unavailable", str(exc))
            )
            self.engine.close()
            self.engine = None
            logger.warning("[function-type-refs] background paused: %s", exc)
        with self._condition:
            waiting, self._unvalidated = self._unvalidated, []
            for record, waiter in waiting:
                self._register(record, waiter)

    def _schedule(self) -> None:
        if self._active or not self.engine:
            return
        jobs = list(self._jobs.values())
        running_count = sum(j.thread is not None for j in jobs)
        if running_count >= MAX_CONTINUATIONS and any(j.waiters and j.thread is None for j in jobs):
            parked = next((j for j in jobs if j.thread is not None and not j.waiters), None)
            if parked is not None:
                # Release a background stack under pressure; completed RPCs are
                # already in the spill cache and survive the subsequent replay.
                parked.cancelled = True
                self._condition.notify_all()
                return
        eligible = [
            j
            for j in jobs
            if j.runnable and (j.thread is not None or running_count < MAX_CONTINUATIONS)
        ]
        foreground = [j for j in eligible if j.waiters]
        if foreground:
            job = min(foreground, key=lambda j: j.turn)
        elif eligible:
            job = min(eligible, key=lambda j: (str(j.record["file_path"]), j.record["start_line"]))
        else:
            record = self._background()
            if not record:
                return
            job = self._jobs.setdefault(record["id"], Job(record))
        if job.thread is None:
            retry = self.db._conn.execute(
                "SELECT retry_count FROM function_type_ref_state WHERE function_id=?",
                (job.record["id"],),
            ).fetchone()
            if retry and retry[0] and self.engine.cache:
                self.engine.cache.discard_volatile()
            job.attempt = uuid.uuid4().hex
            if not state.claim(self.db, job.record["id"], self.generation, job.attempt):
                for waiter in job.waiters:
                    self._complete_waiter(waiter, state.TypeContextUnavailable("task_claim_failed"))
                self._jobs.pop(job.record["id"], None)
                return
            job.thread = threading.Thread(
                target=self._worker, args=(job,), name="ClangTypeFunction", daemon=True
            )
            job.thread.start()
        self._active = job
        self._idle_since = time.monotonic()
        self._condition.notify_all()

    def _suspend(self) -> None:
        for job in self._jobs.values():
            if job.thread:
                job.cancelled = True
        self._condition.notify_all()
        if any(j.thread is not None for j in self._jobs.values()):
            return
        self._active = None
        if self.engine:
            self._retire_engine()
        self._quiescent.set()

    def _retire_engine(self) -> None:
        if self.engine is None:
            return
        getter = getattr(self.engine, "metrics", None)
        metrics = getter() if callable(getter) else {}
        self._retired_rpc_count += sum(
            int(item.get("sent", item.get("count", 0))) for item in metrics.get("rpc", {}).values()
        )
        self._session_metrics.append(metrics)
        self.engine.close()
        self.engine = None

    def _run(self) -> None:
        try:
            state.reset_unfinished(self.db, self.generation)
            while True:
                if self.engine:
                    self.engine.pump()
                    check_resources = getattr(self.engine, "check_resources", None)
                    if (
                        callable(check_resources)
                        and time.monotonic() - self._last_resource_check >= 5
                    ):
                        self._last_resource_check = time.monotonic()
                        try:
                            check_resources()
                        except state.TypeContextUnavailable as exc:
                            self._global_error = exc
                            self._interrupt()
                    if self.engine.cache and time.monotonic() - self._last_checkpoint >= 1:
                        self.engine.cache.checkpoint()
                        self._last_checkpoint = time.monotonic()
                with self._condition:
                    self._events_pass()
                    if self.db.get_metadata(state.GENERATION_KEY) != self.generation:
                        self._global_error = state.TypeContextUnavailable("base_generation_changed")
                    if self._closing or self._pauses or self._global_error:
                        if (
                            self._global_error
                            and self._global_error.reason == "inputs_changed"
                            and not self._inputs_invalidated
                        ):
                            state.invalidate_inputs(self.db, self.generation, "inputs_changed")
                            self._inputs_invalidated = True
                        self._suspend()
                        if self._global_error:
                            for job in self._jobs.values():
                                for waiter in job.waiters:
                                    self._complete_waiter(waiter, self._global_error)
                            for _, waiter in self._unvalidated:
                                self._complete_waiter(waiter, self._global_error)
                            self._unvalidated.clear()
                        if self._closing and self._quiescent.is_set():
                            break
                    elif not self.engine and (
                        self._unvalidated or self._jobs or self._has_background()
                    ):
                        # Preparation can parse/hash inputs. Never hold the admission
                        # lock: waiter deadlines and shutdown must remain responsive.
                        self._condition.release()
                        preparing_at = time.monotonic()
                        try:
                            self._prepare()
                        finally:
                            self._condition.acquire()
                            self._stats["prepare_seconds"] += time.monotonic() - preparing_at
                    else:
                        self._schedule()
                        if (
                            self.engine
                            and not self._jobs
                            and time.monotonic() - self._idle_since >= IDLE_SECONDS
                        ):
                            self._retire_engine()
                            self._quiescent.set()
                    self._condition.wait(0.01 if self._active else 0.05)
        except BaseException as exc:
            logger.exception("Function type coordinator failed")
            self._global_error = state.TypeContextUnavailable("coordinator_failed", str(exc))
        finally:
            try:
                self._shutdown_owner()
            except Exception:
                logger.exception("Type collector cleanup failed")
            finally:
                self._stopped.set()

    def _shutdown_owner(self) -> None:
        with self._condition:
            self._closing = True
            self._condition.notify_all()
        # Pump outstanding cache calls while workers unwind their leases.
        while any(j.thread and j.thread.is_alive() for j in self._jobs.values()):
            if self.engine:
                self.engine.interrupt()
                self.engine.pump()
            time.sleep(0.01)
        for job in self._jobs.values():
            try:
                state.release(self.db, job.record["id"], self.generation, job.attempt)
            except Exception:
                logger.warning("Could not checkpoint interrupted type task", exc_info=True)
            for waiter in job.waiters:
                self._complete_waiter(
                    waiter, self._global_error or state.TypeContextUnavailable("backend_closed")
                )
        for _, waiter in self._unvalidated:
            self._complete_waiter(waiter, state.TypeContextUnavailable("backend_closed"))
        while True:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            if event[0] == "request":
                self._complete_waiter(event[2], state.TypeContextUnavailable("backend_closed"))
        if self.engine:
            self._retire_engine()
        report = dict(
            self.snapshot(),
            generation=self.generation,
            functions=state.counts(self.db),
            sessions=list(self._session_metrics),
        )
        if self.db.get_metadata(state.GENERATION_KEY) == self.generation:
            self.db.set_metadata("clang_type_refs_stats", json.dumps(report))
            atomic_json(Path(self.db._db_path).parent / "clang_type_refs_report.json", report)
        logger.info("[function-type-refs] stopped %s", self.snapshot())


_registry_lock = threading.RLock()
_registry: dict[str, tuple[FunctionTypeScheduler, int]] = {}


def _database_key(db: Any) -> str:
    return os.path.normcase(str(Path(db._db_path).resolve()))


def acquire_scheduler(backend: Any, **kwargs: Any) -> FunctionTypeScheduler:
    """Multiple CodeIndex instances in one process share the same DB owner."""
    key = _database_key(backend._db)
    with _registry_lock:
        existing = _registry.get(key)
        if existing:
            service, references = existing
            if not service._closing and service.generation == backend._db.get_metadata(
                state.GENERATION_KEY
            ):
                _registry[key] = (service, references + 1)
                return service
            service.close()
        service = FunctionTypeScheduler(backend, own_connection=True, **kwargs)
        _registry[key] = (service, 1)
        return service


def release_scheduler(service: FunctionTypeScheduler) -> None:
    key = _database_key(service.db)
    with _registry_lock:
        existing = _registry.get(key)
        if existing and existing[0] is service:
            if existing[1] > 1:
                _registry[key] = (service, existing[1] - 1)
                return
            del _registry[key]
        service.close()


@contextmanager
def pause_registered_scheduler(db: Any) -> Iterator[None]:
    with _registry_lock:
        entry = (
            _registry.get(_database_key(db)) if getattr(db, "_db_path", None) is not None else None
        )
        if entry:
            _registry[_database_key(db)] = (entry[0], entry[1] + 1)
    if entry:
        try:
            with entry[0].paused():
                yield
        finally:
            release_scheduler(entry[0])
    else:
        yield
