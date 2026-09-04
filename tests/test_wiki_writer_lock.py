"""Regression tests for WikiWriterLock pid liveness probing.

``os.kill(pid, 0)`` is destructive on Windows: signal 0 equals
``CTRL_C_EVENT`` (delivered to every process attached to the calling
console) and any other value unconditionally ``TerminateProcess()es`` the
target. These tests pin the non-destructive probe behaviour so the
lock-stealing path can never kill unrelated processes again.
"""

import json
import os
import subprocess
import sys
import time

from zscope.wiki.maintenance import WikiWriterLock


def _write_lock(path, pid, token="a" * 32):
    path.write_text(
        json.dumps(
            {
                "schema_version": WikiWriterLock.SCHEMA_VERSION,
                "pid": pid,
                "token": token,
                "created_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )


def test_pid_alive_rejects_invalid_pids():
    assert WikiWriterLock._pid_alive(0) is False
    assert WikiWriterLock._pid_alive(-5) is False


def test_pid_alive_detects_current_process():
    assert WikiWriterLock._pid_alive(os.getpid()) is True


def test_pid_alive_detects_missing_process_without_side_effects():
    # A PID that virtually never exists; the probe must not signal anything.
    assert WikiWriterLock._pid_alive(99999999) is False


def test_pid_probe_never_kills_an_unrelated_live_process(tmp_path):
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    try:
        time.sleep(1.0)
        assert WikiWriterLock._pid_alive(proc.pid) is True
        time.sleep(0.5)
        assert proc.poll() is None, "pid probe killed an unrelated live process"
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_stale_lock_is_stolen_without_signalling(tmp_path):
    lock_path = tmp_path / "wiki.lock"
    _write_lock(lock_path, 99999998)
    with WikiWriterLock(lock_path, timeout_seconds=1.0):
        pass
    assert not lock_path.exists()


def test_live_lock_owner_blocks_acquisition(tmp_path):
    lock_path = tmp_path / "wiki.lock"
    _write_lock(lock_path, os.getpid())
    try:
        import pytest

        with pytest.raises(TimeoutError):
            with WikiWriterLock(lock_path, timeout_seconds=0.2):
                pass
    finally:
        lock_path.unlink()
