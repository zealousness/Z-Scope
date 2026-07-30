"""One bounded, priority-aware scheduler shared by a complete scan."""

from __future__ import annotations

import itertools
import queue
import threading
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


ENTRY_ROLE = "entry"
VALIDATOR_ROLE = "validator"
INVESTIGATOR_ROLE = "investigator"


@dataclass(frozen=True)
class SchedulerLimits:
    entry_workers: int
    validator_workers: int
    investigator_workers: int


class ScanScheduler:
    """Fixed scan-level worker groups backed by priority queues.

    A role has one pool for the entire scan.  Entry analyzers therefore do not
    recursively create validator or investigator pools.
    """

    def __init__(
        self,
        *,
        entry_workers: int,
        validator_workers: int,
        investigator_workers: int,
    ) -> None:
        self.limits = SchedulerLimits(
            entry_workers=max(1, int(entry_workers or 1)),
            validator_workers=max(1, int(validator_workers or 1)),
            investigator_workers=max(1, int(investigator_workers or 1)),
        )
        self._queues: Dict[str, "queue.PriorityQueue[tuple[Any, ...]]"] = {
            ENTRY_ROLE: queue.PriorityQueue(),
            VALIDATOR_ROLE: queue.PriorityQueue(),
            INVESTIGATOR_ROLE: queue.PriorityQueue(),
        }
        self._sequence = itertools.count()
        self._threads: list[threading.Thread] = []
        self._shutdown = False
        self._lock = threading.Lock()
        for role, count in (
            (ENTRY_ROLE, self.limits.entry_workers),
            (VALIDATOR_ROLE, self.limits.validator_workers),
            (INVESTIGATOR_ROLE, self.limits.investigator_workers),
        ):
            for index in range(count):
                thread = threading.Thread(
                    target=self._worker,
                    args=(role,),
                    name=f"zscope-{role}-{index}",
                    daemon=True,
                )
                thread.start()
                self._threads.append(thread)

    def submit(
        self,
        role: str,
        fn: Callable[..., Any],
        /,
        *args: Any,
        priority: int = 0,
        **kwargs: Any,
    ) -> Future[Any]:
        if role not in self._queues:
            raise ValueError(f"Unknown scheduler role: {role}")
        with self._lock:
            if self._shutdown:
                raise RuntimeError("Scan scheduler has been shut down")
            future: Future[Any] = Future()
            # PriorityQueue sorts low values first; larger domain priority runs first.
            self._queues[role].put(
                (-int(priority), next(self._sequence), future, fn, args, kwargs)
            )
            return future

    def shutdown(self, *, wait: bool = True, cancel_futures: bool = False) -> None:
        with self._lock:
            if not self._shutdown:
                self._shutdown = True
                if cancel_futures:
                    for task_queue in self._queues.values():
                        self._cancel_queued(task_queue)
                for role, task_queue in self._queues.items():
                    worker_count = sum(
                        1
                        for thread in self._threads
                        if thread.name.startswith(f"zscope-{role}-")
                    )
                    for _ in range(worker_count):
                        task_queue.put(
                            (float("inf"), next(self._sequence), None, None, (), {})
                        )
        if wait:
            for thread in self._threads:
                thread.join()

    @staticmethod
    def _cancel_queued(task_queue: "queue.PriorityQueue[tuple[Any, ...]]") -> None:
        retained: list[tuple[Any, ...]] = []
        while True:
            try:
                item = task_queue.get_nowait()
            except queue.Empty:
                break
            future = item[2]
            if isinstance(future, Future):
                future.cancel()
            else:
                retained.append(item)
            task_queue.task_done()
        for item in retained:
            task_queue.put(item)

    def _worker(self, role: str) -> None:
        task_queue = self._queues[role]
        while True:
            _priority, _sequence, future, fn, args, kwargs = task_queue.get()
            try:
                if future is None or fn is None:
                    return
                if not future.set_running_or_notify_cancel():
                    continue
                try:
                    result = fn(*args, **kwargs)
                except BaseException as exc:
                    future.set_exception(exc)
                else:
                    future.set_result(result)
            finally:
                task_queue.task_done()

    def __enter__(self) -> "ScanScheduler":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.shutdown(wait=True, cancel_futures=True)
