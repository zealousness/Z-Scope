"""Versioned single-flight ownership for all semantic modeling entry points."""

from __future__ import annotations

from concurrent.futures import Future, TimeoutError
from copy import deepcopy
from dataclasses import dataclass, field
import threading
import time
from typing import Any, Callable, cast

from ..common.cancellation import CancellationToken, current_cancellation_token


class _SharedTaskCancellation(CancellationToken):
    """Cancel shared work only after every participating scan has cancelled."""

    def __init__(self, root: CancellationToken | None) -> None:
        super().__init__()
        self._roots: set[CancellationToken | None] = {root}
        self._roots_guard = threading.RLock()

    def add(self, root: CancellationToken | None) -> None:
        with self._roots_guard:
            self._roots.add(root)

    def _participants(self) -> tuple[CancellationToken | None, ...]:
        with self._roots_guard:
            return tuple(self._roots)

    def is_cancelled(self) -> bool:
        return self._event.is_set() or all(
            root is not None and root.is_cancelled() for root in self._participants()
        )

    @property
    def reason(self) -> str:
        if self._event.is_set():
            return self._reason or "cancelled"
        roots = self._participants()
        if all(root is not None and root.is_cancelled() for root in roots):
            return next((root.reason for root in roots if root is not None), "cancelled")
        return ""

    def remaining_seconds(self) -> float | None:
        roots = [root for root in self._participants() if root is None or not root.is_cancelled()]
        if not roots:
            return 0.0
        remaining = [root.remaining_seconds() if root is not None else None for root in roots]
        if any(value is None for value in remaining):
            return None
        return max((value for value in remaining if value is not None), default=None)

    def wait(self, timeout: float) -> bool:
        until = time.monotonic() + max(0.0, timeout)
        while not self.is_cancelled():
            left = until - time.monotonic()
            if left <= 0:
                return False
            self._event.wait(min(left, 0.05))
        return True


@dataclass
class _SharedTask:
    future: Future[Any]
    cancellation: _SharedTaskCancellation


_INFLIGHT: dict[tuple[str, str], _SharedTask] = {}
_INFLIGHT_GUARD = threading.RLock()


@dataclass
class ModelingCoordinator:
    """One owner per input; callers wait without reserving an LLM permit.

    A coordinator belongs to one scan epoch. Failed futures deliberately remain
    cached for that epoch, so a crowd of waiters cannot each launch fresh retries.
    Active tasks are shared across scan roots in the same namespace. Completed
    failures stay local to participating epochs so a later scan can retry.
    Publication belongs inside the owner's operation, before the future resolves.
    """

    namespace: str = ""
    _jobs: dict[str, Future[Any]] = field(default_factory=dict)
    _guard: Any = field(default_factory=threading.RLock)
    requests: int = 0
    unique_tasks: int = 0
    joined_requests: int = 0
    wait_seconds: float = 0.0
    active: int = 0
    peak_concurrency: int = 0
    task_attempts: int = 0
    physical_llm_calls: int = 0
    tokens: int = 0
    successful_llm_responses: int = 0
    provider_reported_tokens: int = 0
    conservative_tokens: int = 0
    cache_hits: int = 0

    def run(
        self,
        key: str,
        operation: Callable[[], Any],
        *,
        on_shared: Callable[[Any], Any] | None = None,
    ) -> Any:
        token = current_cancellation_token()
        if token:
            token.raise_if_cancelled()
        scan_token = token
        while scan_token is not None and scan_token._parent is not None:
            scan_token = scan_token._parent
        shared_task = None
        flight_key = (self.namespace, key)
        with self._guard:
            self.requests += 1
            future = self._jobs.get(key)
            owner = future is None
            if future is None:
                if self.namespace:
                    with _INFLIGHT_GUARD:
                        shared_task = _INFLIGHT.get(flight_key)
                        owner = shared_task is None
                        if shared_task is None:
                            shared_task = _SharedTask(Future(), _SharedTaskCancellation(scan_token))
                            _INFLIGHT[flight_key] = shared_task
                        else:
                            shared_task.cancellation.add(scan_token)
                        future = shared_task.future
                else:
                    future = Future()
                self._jobs[key] = future
                self.unique_tasks += int(owner)
                self.joined_requests += int(not owner)
            else:
                self.joined_requests += 1
        if owner:
            with self._guard:
                self.active += 1
                self.peak_concurrency = max(self.peak_concurrency, self.active)
            try:
                from ..common.cancellation import bind_cancellation_token

                # Independent scans can share one active task. Cancelling
                # one requester cannot invalidate another requester's result.
                operation_token = shared_task.cancellation if shared_task else scan_token
                with bind_cancellation_token(operation_token):
                    result = operation()
                future.set_result(deepcopy(result))
            except BaseException as exc:
                future.set_exception(exc)
                raise
            finally:
                if shared_task is not None:
                    with _INFLIGHT_GUARD:
                        if _INFLIGHT.get(flight_key) is shared_task:
                            del _INFLIGHT[flight_key]
                with self._guard:
                    self.active -= 1
        started = time.monotonic()
        token = current_cancellation_token()
        try:
            while True:
                if token:
                    token.raise_if_cancelled()
                try:
                    value = deepcopy(future.result(timeout=0.1))
                    return on_shared(value) if not owner and on_shared is not None else value
                except TimeoutError:
                    if future.done():
                        # TimeoutError may be the owner's actual exception.
                        raise
        finally:
            with self._guard:
                self.wait_seconds += time.monotonic() - started

    def record_completion(self, metadata: dict[str, Any]) -> None:
        with self._guard:
            self.task_attempts += int(metadata.get("semantic_model_attempt_count") or 0)
            self.physical_llm_calls += int(
                metadata.get("provider_attempt_count", metadata.get("api_call_count")) or 0
            )
            self.successful_llm_responses += int(
                metadata.get("provider_success_count", metadata.get("api_call_count")) or 0
            )
            self.tokens += int(
                metadata.get(
                    "provider_accounted_tokens",
                    metadata.get("cumulative_total_tokens") or metadata.get("context_tokens"),
                )
                or 0
            )
            self.provider_reported_tokens += int(metadata.get("provider_reported_tokens") or 0)
            self.conservative_tokens += int(metadata.get("provider_conservative_tokens") or 0)

    def record_cache_hit(self) -> None:
        with self._guard:
            self.cache_hits += 1

    def metrics(self) -> dict[str, Any]:
        with self._guard:
            return {
                "requests": self.requests,
                "task_attempts": self.task_attempts,
                "physical_llm_calls": self.physical_llm_calls,
                "tokens": self.tokens,
                "successful_llm_responses": self.successful_llm_responses,
                "provider_reported_tokens": self.provider_reported_tokens,
                "conservative_tokens": self.conservative_tokens,
                "cache_hits": self.cache_hits,
                "unique_tasks": self.unique_tasks,
                "joined_requests": self.joined_requests,
                "wait_seconds": self.wait_seconds,
                "peak_concurrency": self.peak_concurrency,
            }


# Weak scan roots bound lifetime without retaining old failures across scans.
import weakref
from pathlib import Path

_SCANS: Any = weakref.WeakKeyDictionary()
_SCANS_GUARD = threading.RLock()
_LOCAL_SCOPES: Any = weakref.WeakValueDictionary()


def scan_coordinator(namespace: str, fallback_owner: Any) -> ModelingCoordinator:
    token = current_cancellation_token()
    owner = token
    while owner is not None and owner._parent is not None:
        owner = owner._parent
    owner = owner or fallback_owner
    with _SCANS_GUARD:
        scopes = _SCANS.setdefault(owner, {})
        key = str(Path(namespace).resolve())
        if token is None:
            coordinator = _LOCAL_SCOPES.get(key)
            if coordinator is None:
                coordinator = ModelingCoordinator(namespace=key)
                _LOCAL_SCOPES[key] = coordinator
            scopes[key] = coordinator
        return cast(ModelingCoordinator, scopes.setdefault(key, ModelingCoordinator(namespace=key)))


def reset_local_epoch(namespace: str, owner: Any) -> None:
    """Direct API scans without a cancellation scope start a fresh retry epoch."""
    with _SCANS_GUARD:
        scopes = _SCANS.setdefault(owner, {})
        key = str(Path(namespace).resolve())
        scopes[key] = ModelingCoordinator(namespace=key)
        _LOCAL_SCOPES[key] = scopes[key]
