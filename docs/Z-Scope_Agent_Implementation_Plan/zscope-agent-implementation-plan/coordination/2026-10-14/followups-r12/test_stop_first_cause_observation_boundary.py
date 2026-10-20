"""Real shared-token observation order; no clock patch or watcher scheduling assumption."""
import time

from zscope.common.cancellation import CancellationToken


def test_later_parent_cancel_cannot_replace_observed_child_deadline():
    parent = CancellationToken()
    child = parent.child()
    child.tighten_deadline(time.monotonic() - 1, reason="stop window reached: child")
    assert child.is_cancelled() and child.reason == "stop window reached: child"
    parent.cancel("caller_cancel_requested")
    assert child.reason == "stop window reached: child"


def test_later_explicit_cancel_cannot_replace_observed_own_deadline():
    token = CancellationToken()
    token.tighten_deadline(time.monotonic() - 1, reason="stop window reached: own")
    assert token.is_cancelled() and token.reason == "stop window reached: own"
    token.cancel("later explicit cancel")
    assert token.reason == "stop window reached: own"
