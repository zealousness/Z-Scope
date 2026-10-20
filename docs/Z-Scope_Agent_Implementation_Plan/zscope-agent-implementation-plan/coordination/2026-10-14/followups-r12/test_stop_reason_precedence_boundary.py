"""An armed config window must preserve earlier deadline and parent cancel causes."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace

workspace = Path(os.environ["PYTHONPATH"])
sys.path.insert(0, str(workspace / "tests"))
sys.path.insert(0, str(workspace.parents[3] / "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12"))
from test_config_stop_deadline_boundary import real_runner
from zscope.common.cancellation import CancellationToken
from zscope.config.v3 import StopWindow
from zscope.orchestration.execution_profile import arm_session_deadline, session_cancellation_token


def later_window():
    return StopWindow(timezone="UTC", stop_at="08:00", resolved_stop_time=datetime.now(timezone.utc) + timedelta(seconds=10))


def test_real_session_earlier_deadline_reason_survives_config_watcher(tmp_path):
    runner = real_runner(tmp_path)
    token = session_cancellation_token(runner)
    token.tighten_deadline(time.monotonic() + .05)
    guard = arm_session_deadline(runner, later_window())
    try:
        guard._thread.join(timeout=1)
        assert not guard._thread.is_alive(), "watcher must observe the earlier cancellation"
        assert token.is_cancelled()
        assert token.reason == "deadline_exceeded", (
            "a later config window cannot relabel an earlier session deadline as stop_at"
        )
    finally:
        guard.release()


def test_parent_cancellation_reason_survives_config_watcher():
    parent = CancellationToken()
    child = parent.child()
    runner = SimpleNamespace(session_executor=SimpleNamespace(cancellation_token=child))
    guard = arm_session_deadline(runner, later_window())
    try:
        parent.cancel("caller_cancel_requested")
        guard._thread.join(timeout=1)
        assert not guard._thread.is_alive(), "watcher must observe the parent cancellation"
        assert child.is_cancelled()
        assert child.reason == "caller_cancel_requested", (
            "the watcher cannot replace inherited cancellation with its later stop_at reason"
        )
    finally:
        guard.release()
