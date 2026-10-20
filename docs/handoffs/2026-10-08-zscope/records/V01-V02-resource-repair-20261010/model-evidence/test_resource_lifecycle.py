"""Bounded benign descendants exercise the existing deadline/cancel contract."""

import os
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

from zscope.common.cancellation import CancellationToken, bind_cancellation_token
from zscope.core.validation import dynamic_reproduction as d


def _command(marker, body):
    child = (
        "import os,time;from pathlib import Path;"
        f"Path({str(marker)!r}).write_text(str(os.getpid()));" + body
    )
    parent = (
        "import subprocess,sys,time;from pathlib import Path;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        f"marker=Path({str(marker)!r});deadline=time.monotonic()+2;"
        "\nwhile not marker.exists() and time.monotonic()<deadline:time.sleep(.005)"
    )
    return (sys.executable, "-c", parent)


def _alive(marker):
    if not marker.exists():
        return False
    status = Path(f"/proc/{int(marker.read_text())}/stat")
    try:
        return status.read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


def _cleanup(marker):
    if _alive(marker):
        try:
            os.kill(int(marker.read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass


def _assert_stopped(marker):
    until = time.monotonic() + 1
    while _alive(marker) and time.monotonic() < until:
        time.sleep(0.01)
    assert marker.is_file(), "the owned child must have actually started"
    assert not _alive(marker), "owned descendant survived the runner cleanup"


def _run(runner, tmp_path, argv):
    return runner._run_once(
        argv=argv,
        cwd=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        address_space_limit_mb=0,
        tag="owned",
        workdir=str(tmp_path),
    )


def test_shared_deadline_bounds_pipes_after_leader_exit(tmp_path):
    marker = tmp_path / "child.pid"
    runner = d.SanitizerReproductionRunner(
        "asan", policy=d.DynamicReproductionPolicy(enabled=True)
    )
    runner.use_budget(d._ExecutionBudget(run_limit=1, deadline=time.monotonic() + 0.5))
    started = time.monotonic()
    try:
        result = _run(runner, tmp_path, _command(marker, "time.sleep(3)"))
        assert result.timed_out
        assert time.monotonic() - started < 2
        _assert_stopped(marker)
    finally:
        _cleanup(marker)


def test_cancellation_kills_descendant_after_leader_exit(tmp_path):
    marker = tmp_path / "child.pid"
    token = CancellationToken()
    timer = threading.Timer(0.5, lambda: token.cancel("cancel inherited pipes"))
    runner = d.SanitizerReproductionRunner(
        "asan", policy=d.DynamicReproductionPolicy(enabled=True)
    )
    timer.start()
    try:
        with bind_cancellation_token(token), pytest.raises(d.CancellationError):
            _run(runner, tmp_path, _command(marker, "time.sleep(3)"))
        _assert_stopped(marker)
    finally:
        timer.cancel()
        timer.join()
        _cleanup(marker)


def test_eof_does_not_leave_an_owned_descendant_alive(tmp_path):
    marker = tmp_path / "child.pid"
    runner = d.SanitizerReproductionRunner(
        "asan", policy=d.DynamicReproductionPolicy(enabled=True)
    )
    try:
        result = _run(
            runner, tmp_path, _command(marker, "os.close(1);os.close(2);time.sleep(3)")
        )
        assert result.exit_code == 0 and not result.timed_out
        _assert_stopped(marker)
    finally:
        _cleanup(marker)


def test_output_cap_kills_owned_group_after_leader_exit(tmp_path):
    marker = tmp_path / "child.pid"
    runner = d.SanitizerReproductionRunner(
        "asan",
        policy=d.DynamicReproductionPolicy(enabled=True, output_capture_limit_bytes=16),
    )
    try:
        result = _run(
            runner,
            tmp_path,
            _command(marker, "time.sleep(.1);os.write(1,b'A'*64);time.sleep(3)"),
        )
        assert result.output_capped and result.stdout_truncated
        assert result.stdout_bytes == 16 and not result.timed_out
        _assert_stopped(marker)
    finally:
        _cleanup(marker)


def test_pipe_read_failure_is_not_treated_as_complete_eof(tmp_path, monkeypatch):
    import errno

    original_popen, original_read = d.subprocess.Popen, d.os.read
    capture_fds = set()

    def popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        capture_fds.update(
            pipe.fileno() for pipe in (process.stdout, process.stderr) if pipe
        )
        return process

    def read(fd, size):
        if fd in capture_fds:
            raise OSError(errno.EIO, "synthetic pipe read failure")
        return original_read(fd, size)

    monkeypatch.setattr(d.subprocess, "Popen", popen)
    monkeypatch.setattr(d.os, "read", read)
    runner = d.SanitizerReproductionRunner(
        "asan", policy=d.DynamicReproductionPolicy(enabled=True)
    )
    with pytest.raises(d._PlanViolation, match="output_capture_failed"):
        _run(runner, tmp_path, (sys.executable, "-c", "import os;os.write(1,b'A')"))
