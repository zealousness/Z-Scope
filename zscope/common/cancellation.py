"""Cooperative cancellation and deadline propagation for one scan.

The token is intentionally small and dependency-free so it can cross the
orchestration, validation, agent, and transport layers without coupling them.
Child tokens inherit parent cancellation while applying a tighter local
deadline.  ``tighten_deadline`` is the only mutation besides ``cancel``: it
puts a monotonic, non-extendable budget on an already-shared token so
consumers that read ``remaining_seconds`` (request timeouts, wait bounds)
observe a window that armed after the token was created.
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


@dataclass(frozen=True)
class _CancellationCause:
    occurred_at: Optional[float]
    reason: str
    source: "CancellationToken"
    deadline: Optional[float] = None


class CancellationToken:
    """Cooperative token whose first effective cancellation cause is immutable.

    Related tokens share one state lock. Observations and mutations compare
    ancestor causes and local expiry under that lock; equal times prefer the
    ancestor. A deadline registered in the past takes effect at registration,
    so subsequent tightening cannot retroactively replace an earlier cause.
    """

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
        self._cause: Optional[_CancellationCause] = None
        self._deadline: Optional[float]
        self._deadline_reason = ""
        self._state_lock: threading.RLock = (
            parent._state_lock if parent is not None else threading.RLock()
        )
        now = time.monotonic()
        if deadline is not None:
            self._deadline = float(deadline)
        elif timeout_seconds is not None and float(timeout_seconds) > 0:
            self._deadline = now + float(timeout_seconds)
        else:
            self._deadline = None
        self._deadline_effective_at = (
            max(now, self._deadline) if self._deadline is not None else now
        )

    def child(self, timeout_seconds: Optional[float] = None) -> "CancellationToken":
        # Keep inherited deadlines at their source, together with their reason.
        return CancellationToken(parent=self, timeout_seconds=timeout_seconds)

    @contextlib.contextmanager
    def _locked_chain(
        self,
    ) -> Iterator[
        tuple[list["CancellationToken"], Optional[_CancellationCause], Optional[float], float]
    ]:
        chain = [self]
        parent = self._parent
        while parent is not None:
            parent_type = type(parent)
            if (
                parent_type.is_cancelled is not CancellationToken.is_cancelled
                or parent_type.reason is not CancellationToken.reason
                or parent_type.remaining_seconds is not CancellationToken.remaining_seconds
            ):
                break
            chain.append(parent)
            parent = parent._parent

        # A specialized parent (e.g. shared modeling work) owns its public
        # cancellation semantics. Call it before taking the family lock: it
        # may consult unrelated trees. An unknown occurrence time preserves
        # the original conservative parent precedence until a child records
        # a cause; observation time cannot stand in for occurrence time.
        external_cause = None
        external_remaining = None
        if parent is not None:
            if parent.is_cancelled():
                external_cause = _CancellationCause(None, parent.reason or "cancelled", parent)
            external_remaining = parent.remaining_seconds()
        with self._state_lock:
            if (
                external_cause is not None
                and parent is not None
                and parent._cause is not None
                and parent._cause.reason == external_cause.reason
            ):
                external_cause = parent._cause
            yield list(reversed(chain)), external_cause, external_remaining, time.monotonic()

    def _record_cause(self, cause: _CancellationCause) -> None:
        # All callers hold the shared family lock. Retain event/reason for
        # existing subclasses and waiters as well as the immutable receipt.
        self._cause = cause
        self._reason = cause.reason
        self._event.set()

    def _resolve_chain(
        self,
        chain: list["CancellationToken"],
        inherited: Optional[_CancellationCause],
        now: float,
        *,
        deadline_reason: Optional[tuple[float, str]] = None,
    ) -> Optional[_CancellationCause]:
        for token in chain:
            if token._cause is None:
                cause = inherited
                if token._deadline is not None and now >= token._deadline:
                    if cause is None or (
                        cause.occurred_at is not None
                        and token._deadline_effective_at < cause.occurred_at
                    ):
                        reason = token._deadline_reason or "deadline_exceeded"
                        if token is self and deadline_reason is not None:
                            if token._deadline == deadline_reason[0]:
                                reason = deadline_reason[1]
                        cause = _CancellationCause(
                            token._deadline_effective_at, reason, token, token._deadline
                        )
                if cause is not None:
                    token._record_cause(cause)
            inherited = token._cause
        return inherited

    def _snapshot(self) -> CancellationState:
        with self._locked_chain() as (chain, inherited, remaining, now):
            cause = self._resolve_chain(chain, inherited, now)
            for token in chain:
                if token._deadline is not None:
                    local = max(0.0, token._deadline - now)
                    remaining = local if remaining is None else min(remaining, local)
            return CancellationState(cause is not None, cause.reason if cause else "", remaining)

    def tighten_deadline(self, deadline: float, *, reason: str = "") -> None:
        """Tighten this token's monotonic deadline; never extend it.

        The earliest deadline always wins: a later or looser ``deadline`` is
        ignored, so an established budget can only shrink.  Children observe
        the change through their normal parent-chain reads, so one tighten
        on a shared session token bounds existing and future children.
        A token that is already cancelled keeps its
        recorded reason; when the tightened deadline is what expires, the
        ``reason`` given here (or ``deadline_exceeded``) names it.  The
        deadline stays on the monotonic clock, so wall-clock changes can
        neither extend nor shorten the budget.
        """

        new_deadline = float(deadline)
        new_reason = str(reason or "")
        with self._locked_chain() as (chain, inherited, _, now):
            self._resolve_chain(chain, inherited, now)
            if self._deadline is not None and new_deadline >= self._deadline:
                return
            self._deadline = new_deadline
            self._deadline_reason = new_reason
            self._deadline_effective_at = max(now, new_deadline)

    def cancel(self, reason: str = "cancelled") -> None:
        new_reason = str(reason or "cancelled")
        with self._locked_chain() as (chain, inherited, _, now):
            if self._resolve_chain(chain, inherited, now) is None:
                self._record_cause(_CancellationCause(now, new_reason, self))

    def cancel_if_deadline(self, deadline: float, reason: str) -> bool:
        """Cancel with ``reason`` only when ``deadline`` is the first cause.

        Only the first observation of this token's matching local expiry may
        supply its reason. Already observed causes, earlier ancestor causes,
        and different binding deadlines retain their reason. Returns True
        only when this call records the matching local deadline as the cause.
        """

        expected = float(deadline)
        new_reason = str(reason or "cancelled")
        with self._locked_chain() as (chain, inherited, _, now):
            was_cancelled = self._cause is not None
            cause = self._resolve_chain(
                chain, inherited, now, deadline_reason=(expected, new_reason)
            )
            return (
                not was_cancelled
                and cause is not None
                and cause.source is self
                and cause.deadline == expected
            )

    @property
    def reason(self) -> str:
        with self._state_lock:
            if self._cause is not None:
                return self._cause.reason
        return self._snapshot().reason

    def remaining_seconds(self) -> Optional[float]:
        return self._snapshot().remaining_seconds

    def is_cancelled(self) -> bool:
        with self._state_lock:
            if self._cause is not None:
                return True
        return self._snapshot().cancelled

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled():
            raise CancellationError(self.reason or "cancelled")

    def wait(self, timeout: float) -> bool:
        """Wait interruptibly; return True when cancellation became observable."""
        wait_until = time.monotonic() + max(0.0, float(timeout))
        while True:
            if self.is_cancelled():
                return True
            bounded = wait_until - time.monotonic()
            remaining = self.remaining_seconds()
            if remaining is not None:
                bounded = min(bounded, remaining)
            if bounded <= 0.0:
                return self.is_cancelled()
            # Ancestors (including specialized parents) own independent
            # events, and an existing deadline can tighten while we wait.
            # Re-read their public state without retaining child references.
            self._event.wait(min(bounded, 0.05))

    def state(self) -> CancellationState:
        if (
            type(self).is_cancelled is CancellationToken.is_cancelled
            and type(self).reason is CancellationToken.reason
            and type(self).remaining_seconds is CancellationToken.remaining_seconds
        ):
            return self._snapshot()
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
