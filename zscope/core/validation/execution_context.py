"""Explicit execution context crossing validation worker-thread boundaries.

``ThreadPoolExecutor`` tasks do not inherit the submitting thread's
contextvars (confirmed empirically in this tree), so every worker that
consumes build-scoped facts must carry its precise context explicitly.  A
context is captured at submit time as an immutable
:class:`ExecutionContext` — the exact build id and the analysis instance's
own entry symbol — and rebound on the worker thread with a finally-restore,
so pool threads reused across scans and variants never inherit another
instance's ambient scope, and a timed-out or cancelled task that finishes
late cannot leak its binding into the next task on the same thread.

The values are only ever captured from the already-verified scope bindings
(``bind_build_scope`` / the runner's ``InstanceScope``); a candidate's
self-reported strings, plain JSON, or environment leftovers are not a
context source.  An unscoped runner binds the empty context so its workers
also never inherit an ambient leftover from the submitting thread.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Iterator, Tuple


@dataclass(frozen=True)
class ExecutionContext:
    """The precise build/entry scope one worker must run under.

    ``build_context_id`` is the exact compilation instance; ``entry_symbol``
    is the ``(name, usr)`` identity of the analyzed function, empty when the
    submitting scope states no entry identity; ``call_facts`` is the opaque
    per-entry call binding (callee USR observations and call values) captured
    from the live :func:`~zscope.semantics.call_context.bind_call_context`
    state and frozen at capture time, or ``None`` when no entry context was
    active.  The freeze keeps the registry reference (identity checks) but
    write-protects the nested values, so a parent-thread mutation of its own
    live mapping can never rewrite a captured or submitted identity.
    Rebinding a context without call facts deliberately clears any ambient
    map — a new entry, a legacy call, or an unknown identity must never
    borrow another entry's native callee receipts.
    """

    build_context_id: str = ""
    entry_symbol: Tuple[str, str] = ("", "")
    call_facts: Any = None


EMPTY_EXECUTION_CONTEXT = ExecutionContext()


def current_execution_context() -> ExecutionContext:
    """Capture the calling thread's precise scope from the live bindings.

    Only the values already established by the accepted scope machinery
    (build scope and the per-entry call context) are read; nothing is
    inferred from names, files, candidate data, or serialized JSON.
    """

    from ...semantics import build_scope
    from ...semantics.call_context import current_call_facts, freeze_call_facts

    return ExecutionContext(
        build_context_id=build_scope.current_build_id(),
        entry_symbol=build_scope._ACTIVE_SCOPE_SYMBOL.get(),
        # The call binding is frozen into an immutable snapshot here: the
        # registry reference survives verbatim for identity checks, while
        # the nested call values and callee observations can no longer be
        # rewritten by the parent thread's live mapping after capture.
        call_facts=freeze_call_facts(current_call_facts()),
    )


@contextmanager
def rebound_execution_context(context: ExecutionContext) -> Iterator[None]:
    """Bind a captured context on the current thread; always restore after.

    All three scope variables — build id, entry symbol, and the per-entry
    call-facts binding — are set together, so switching to another entry (or
    to the empty legacy context) removes the prior entry's callee map instead
    of silently keeping it.  The finally path restores the thread's previous
    values, so a reused pool thread is exactly as scoped after the task as
    before it — including on cancellation, timeout, and exception paths.
    """

    from ...semantics import build_scope
    from ...semantics.call_context import rebound_call_facts

    build_marker = build_scope._ACTIVE_SCOPE.set(context.build_context_id)
    symbol_marker = build_scope._ACTIVE_SCOPE_SYMBOL.set(context.entry_symbol)
    with rebound_call_facts(context.call_facts):
        try:
            yield
        finally:
            build_scope._ACTIVE_SCOPE_SYMBOL.reset(symbol_marker)
            build_scope._ACTIVE_SCOPE.reset(build_marker)


def context_bound(callable_: Callable, context: ExecutionContext) -> Callable:
    """Wrap one worker callable with an explicit bind/finally-restore."""

    @wraps(callable_)
    def bound(*args: object, **kwargs: object) -> object:
        with rebound_execution_context(context):
            return callable_(*args, **kwargs)

    return bound
