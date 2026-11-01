from __future__ import annotations

import time
import threading

import pytest

from zscope.common.cancellation import (
    CancellationError,
    CancellationToken,
    bind_cancellation_token,
    current_cancellation_token,
)


def test_child_token_inherits_parent_cancellation() -> None:
    parent = CancellationToken()
    child = parent.child(timeout_seconds=60)

    parent.cancel("scan_interrupted")

    assert child.is_cancelled()
    assert child.reason == "scan_interrupted"
    with pytest.raises(CancellationError, match="scan_interrupted"):
        child.raise_if_cancelled()


def test_child_uses_tighter_deadline() -> None:
    parent = CancellationToken(timeout_seconds=60)
    child = parent.child(timeout_seconds=0.01)

    time.sleep(0.02)

    assert child.is_cancelled()
    assert child.reason == "deadline_exceeded"
    assert parent.is_cancelled() is False


def test_bound_token_is_scoped() -> None:
    token = CancellationToken()
    assert current_cancellation_token() is None

    with bind_cancellation_token(token):
        assert current_cancellation_token() is token

    assert current_cancellation_token() is None


@pytest.mark.parametrize("change", ["cancel_parent", "tighten_parent", "tighten_self"])
def test_wait_observes_cancellation_changes_while_sleeping(change, monkeypatch) -> None:
    parent = CancellationToken()
    token = parent.child()
    entered_wait = threading.Event()
    completed = threading.Event()
    results = []
    original_wait = token._event.wait

    def observe_wait(timeout):
        entered_wait.set()
        return original_wait(timeout)

    monkeypatch.setattr(token._event, "wait", observe_wait)

    def wait_for_cancel():
        results.append(token.wait(5.0))
        completed.set()

    worker = threading.Thread(target=wait_for_cancel, daemon=True)
    worker.start()
    try:
        assert entered_wait.wait(1.0)
        if change == "cancel_parent":
            parent.cancel("stopped")
        else:
            target = token if change == "tighten_self" else parent
            target.tighten_deadline(time.monotonic() + 0.01, reason="stopped")
        assert completed.wait(1.0)
        assert results == [True]
        assert token.reason == "stopped"
    finally:
        token.cancel("test_cleanup")
        worker.join(1.0)
