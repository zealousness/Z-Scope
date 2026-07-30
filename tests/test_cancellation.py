from __future__ import annotations

import time

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
