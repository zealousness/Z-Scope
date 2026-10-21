"""Scan command construction and bounded process-group termination.

The default runner executes the existing product CLI as a child process of
the owner.  The owner never accepts argv from the network: the command is
built by the service from the saved config path and persisted in the run
directory as ``launch.json`` before the owner starts.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .models import LAUNCH_SCHEMA_VERSION

ScanCommandBuilder = Callable[[Path, Optional[str], str], List[str]]


def build_cli_command(
    config_path: Path,
    scan_depth: Optional[str],
    python_executable: str,
) -> List[str]:
    """Default scan command: the existing single entry point ``zscope`` CLI."""

    command = [python_executable, "-m", "zscope.cli.cli", "-c", str(config_path)]
    if scan_depth:
        command += ["--scan-depth", scan_depth]
    return command


def write_launch_file(
    path: Path,
    *,
    job_id: str,
    run_id: str,
    owner_token: str,
    argv: List[str],
    cwd: str,
    report_candidates: List[str],
    stop_at_epoch: Optional[float],
    resolved_stop_time: Optional[str],
) -> None:
    import json

    payload: Dict[str, Any] = {
        "schema": LAUNCH_SCHEMA_VERSION,
        "job_id": job_id,
        "run_id": run_id,
        "owner_token": owner_token,
        "argv": list(argv),
        "cwd": cwd,
        "report_candidates": list(report_candidates),
        "stop_at_epoch": stop_at_epoch,
        "resolved_stop_time": resolved_stop_time,
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def terminate_process_group(
    process: Any,
    *,
    grace_seconds: float = 10.0,
    poll_interval: float = 0.1,
) -> str:
    """SIGTERM then SIGKILL the *scanner's own* process group, bounded.

    The scanner was spawned with ``start_new_session=True`` so its PGID equals
    its PID and every child it spawned belongs to that group.  Returns a short
    outcome label for events: ``already_exited``, ``terminated`` or ``killed``.
    """

    if process.poll() is not None:
        return "already_exited"
    pid = int(process.pid)
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.terminate()
        except OSError:
            pass
    deadline = time.monotonic() + max(0.0, grace_seconds)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return "terminated"
        time.sleep(poll_interval)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=max(1.0, grace_seconds))
    except Exception:
        pass
    return "killed"
