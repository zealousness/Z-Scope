"""Cooperative cancellation and deadline propagation for one scan.

The token is intentionally small and dependency-free so it can cross the
orchestration, validation, agent, and transport layers without coupling them.
Child tokens inherit parent cancellation while applying a tighter local
deadline.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
import time
from dataclasses import dataclass
from typing import Iterator, Optional


class CancellationError(RuntimeError):
    """Raised when work must stop because its token was cancelled or expired."""


@dataclass(frozen=True)
class CancellationState:
    cancelled: bool
    reason: str
    remaining_seconds: Optional[float]


class CancellationToken:
    """Thread-safe cooperative token with an optional monotonic deadline."""

    def __init__(
        self,
        *,
        parent: Optional["CancellationToken"] = None,
        timeout_seconds: Optional[float] = None,
        deadline: Optional[float] = None,
    ) -> None:
        self._parent = parent
        self._event = threading.Event()
        self._reason = ""
        self._deadline: Optional[float]
        if deadline is not None:
            self._deadline = float(deadline)
        elif timeout_seconds is not None and float(timeout_seconds) > 0:
            self._deadline = time.monotonic() + float(timeout_seconds)
        else:
            self._deadline = None

    def child(self, timeout_seconds: Optional[float] = None) -> "CancellationToken":
        deadline = self._deadline
        if timeout_seconds is not None and float(timeout_seconds) > 0:
            local_deadline = time.monotonic() + float(timeout_seconds)
            deadline = min(deadline, local_deadline) if deadline is not None else local_deadline
        return CancellationToken(parent=self, deadline=deadline)

    def cancel(self, reason: str = "cancelled") -> None:
        if not self._event.is_set():
            self._reason = str(reason or "cancelled")
            self._event.set()

    @property
    def reason(self) -> str:
        if self._event.is_set():
            return self._reason or "cancelled"
        if self._parent is not None and self._parent.is_cancelled():
            return self._parent.reason
        if self._deadline is not None and time.monotonic() >= self._deadline:
            return "deadline_exceeded"
        return ""

    def remaining_seconds(self) -> Optional[float]:
        remaining: Optional[float] = None
        if self._deadline is not None:
            remaining = max(0.0, self._deadline - time.monotonic())
        if self._parent is not None:
            parent_remaining = self._parent.remaining_seconds()
            if parent_remaining is not None:
                remaining = (
                    parent_remaining
                    if remaining is None
                    else min(remaining, parent_remaining)
                )
        return remaining

    def is_cancelled(self) -> bool:
        if self._event.is_set():
            return True
        if self._parent is not None and self._parent.is_cancelled():
            return True
        remaining = self.remaining_seconds()
        return remaining is not None and remaining <= 0

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            raise CancellationError(self.reason or "cancelled")

    def wait(self, timeout: float) -> bool:
        """Wait interruptibly; return True when cancellation became observable."""
        if self.is_cancelled():
            return True
        bounded = max(0.0, float(timeout))
        remaining = self.remaining_seconds()
        if remaining is not None:
            bounded = min(bounded, remaining)
        self._event.wait(bounded)
        return self.is_cancelled()

    def state(self) -> CancellationState:
        return CancellationState(
            cancelled=self.is_cancelled(),
            reason=self.reason,
            remaining_seconds=self.remaining_seconds(),
        )


_CURRENT_TOKEN: contextvars.ContextVar[Optional[CancellationToken]] = contextvars.ContextVar(
    "zscope_cancellation_token",
    default=None,
)


def current_cancellation_token() -> Optional[CancellationToken]:
    return _CURRENT_TOKEN.get()


@contextlib.contextmanager
def bind_cancellation_token(token: Optional[CancellationToken]) -> Iterator[None]:
    marker = _CURRENT_TOKEN.set(token)
    try:
        yield
    finally:
        _CURRENT_TOKEN.reset(marker)
