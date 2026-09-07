"""Bounded resource admission and observable compiler/analysis subprocesses."""

from __future__ import annotations

import ctypes
import logging
import math
import os
import signal
import subprocess
import threading
import time
from contextlib import contextmanager
from functools import wraps
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)


def observed(phase: str):
    def decorate(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            with heartbeat(phase):
                return function(*args, **kwargs)

        return wrapped

    return decorate


@contextmanager
def heartbeat(
    phase: str, state: Optional[Dict[str, Any]] = None, interval: float = 30.0
) -> Iterator[None]:
    """Progress independent of task completions, including hashing and import."""
    stop = threading.Event()
    started = time.monotonic()

    def report() -> None:
        while not stop.wait(interval):
            summary = {
                key: len(value) if isinstance(value, (list, set, dict)) else value
                for key, value in list((state or {}).items())
            }
            logger.info(
                "[indexing-heartbeat] phase=%s elapsed=%.1fs rss=%s state=%s",
                phase,
                time.monotonic() - started,
                process_rss(os.getpid()),
                summary,
            )

    thread = threading.Thread(target=report, name="IndexingHeartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()


def _integer(path: Path) -> Optional[int]:
    try:
        value = path.read_text().strip()
        return int(value) if value != "max" else None
    except (OSError, ValueError):
        return None


def resource_limits() -> Dict[str, Any]:
    cpus = max(
        1,
        len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 1),
    )
    available: Optional[int] = None
    if os.name == "nt":

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong)
                for name in (
                    "total",
                    "available",
                    "page_total",
                    "page_available",
                    "virtual_total",
                    "virtual_available",
                    "extended",
                )
            ]

        state = MemoryStatus()
        state.length = ctypes.sizeof(state)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
            available = int(state.available)
    else:
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemAvailable:"):
                    available = int(line.split()[1]) * 1024
        except (OSError, ValueError):
            pass
        roots = [Path("/sys/fs/cgroup")]
        v1_memory = {Path("/sys/fs/cgroup/memory")}
        v1_cpu = {Path("/sys/fs/cgroup/cpu"), Path("/sys/fs/cgroup/cpu,cpuacct")}
        try:
            for line in Path("/proc/self/cgroup").read_text().splitlines():
                hierarchy, controllers, suffix = line.split(":", 2)
                if hierarchy == "0" and not controllers:
                    current = Path("/sys/fs/cgroup") / suffix.lstrip("/")
                    if ".." not in current.parts:
                        roots.extend(
                            [
                                current,
                                *[
                                    p
                                    for p in current.parents
                                    if str(p).startswith("/sys/fs/cgroup")
                                ],
                            ]
                        )
                elif ".." not in Path(suffix).parts:
                    names = controllers.split(",")
                    for name, destinations in (("memory", v1_memory), ("cpu", v1_cpu)):
                        if name in names:
                            for mount in {
                                Path("/sys/fs/cgroup") / name,
                                Path("/sys/fs/cgroup") / controllers,
                            }:
                                current = mount / suffix.lstrip("/")
                                destinations.update(
                                    [
                                        current,
                                        mount,
                                        *[p for p in current.parents if mount in p.parents],
                                    ]
                                )
        except (OSError, ValueError):
            pass
        for root in set(roots):
            maximum, used = _integer(root / "memory.max"), _integer(root / "memory.current")
            if maximum is not None and used is not None:
                remaining = max(0, maximum - used)
                available = min(available, remaining) if available is not None else remaining
            try:
                quota_text, period_text = (root / "cpu.max").read_text().split()
                if quota_text != "max":
                    cpus = min(cpus, max(1, math.floor(int(quota_text) / int(period_text))))
            except (OSError, ValueError, ZeroDivisionError):
                pass
        for root in v1_memory:
            maximum = _integer(root / "memory.limit_in_bytes")
            used = _integer(root / "memory.usage_in_bytes")
            if maximum is not None and used is not None:
                remaining = max(0, maximum - used)
                available = min(available, remaining) if available is not None else remaining
        for root in v1_cpu:
            quota = _integer(root / "cpu.cfs_quota_us")
            period = _integer(root / "cpu.cfs_period_us")
            if quota and quota > 0 and period and period > 0:
                cpus = min(cpus, max(1, math.floor(quota / period)))
    return {
        "cpu_count": cpus,
        "available_memory_bytes": available,
        "task_memory_budget_bytes": int(available * 0.75) if available is not None else None,
    }


def admitted_workers(
    requested: int, count: int, reservation_mb: int, limits: Optional[Mapping[str, Any]] = None
) -> int:
    if count <= 0:
        return 0
    state = dict(limits) if limits is not None else resource_limits()
    workers = min(max(1, requested), count, int(state["cpu_count"]))
    budget = state.get("task_memory_budget_bytes")
    if budget is None:
        return min(workers, 1)
    return min(workers, int(budget) // max(1, reservation_mb * 1024 * 1024))


def process_rss(pid: int) -> Optional[int]:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return None


def process_tree_rss(pid: int) -> Optional[int]:
    total = 0
    known = False
    pending, seen = [pid], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        rss = process_rss(current)
        if rss is not None:
            known = True
            total += rss
        try:
            for task in Path(f"/proc/{current}/task").iterdir():
                pending.extend(int(value) for value in (task / "children").read_text().split())
        except (OSError, ValueError):
            pass
    return total if known else None


@dataclass
class MeasuredProcess:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    metrics: Dict[str, Any] = field(default_factory=dict)


def run_process(
    command: Sequence[str],
    *,
    cwd: Path,
    output_prefix: Path,
    env: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = None,
    memory_limit_mb: Optional[int] = None,
    label: str = "indexing",
    heartbeat_seconds: float = 30.0,
    output_limit: int = 16 * 1024 * 1024,
    cancel: Optional[threading.Event] = None,
    log_level: int = logging.INFO,
) -> MeasuredProcess:
    """Spool output to disk; reap per-child CPU/RSS on POSIX, never global usage.

    The RSS guard is sampled, not an OS hard limit. Admission reserves the full
    configured process budget. All statuses (including truncation) are explicit.
    """
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    stdout_path = output_prefix.with_name(output_prefix.name + ".stdout.log")
    stderr_path = output_prefix.with_name(output_prefix.name + ".stderr.log")
    metrics: Dict[str, Any] = {
        "phase": label,
        "timed_out": False,
        "memory_exceeded": False,
        "cancelled": False,
        "cpu_seconds": None,
        "peak_rss_bytes": None,
        "sampled_peak_rss_bytes": 0,
    }
    next_log = started + heartbeat_seconds
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd),
            env=dict(env) if env else None,
            stdout=stdout,
            stderr=stderr,
            start_new_session=os.name != "nt",
        )
        metrics["pid"] = process.pid
        try:
            while True:
                if os.name == "posix" and hasattr(os, "wait4"):
                    pid, status, usage = os.wait4(process.pid, getattr(os, "WNOHANG", 1))
                    if pid:
                        process.returncode = os.waitstatus_to_exitcode(status)
                        metrics["cpu_seconds"] = usage.ru_utime + usage.ru_stime
                        metrics["peak_rss_bytes"] = int(usage.ru_maxrss) * (
                            1 if getattr(os, "uname")().sysname == "Darwin" else 1024
                        )
                        break
                elif process.poll() is not None:
                    break
                now = time.monotonic()
                rss = process_tree_rss(process.pid)
                if rss is not None:
                    metrics["sampled_peak_rss_bytes"] = max(metrics["sampled_peak_rss_bytes"], rss)
                metrics["timed_out"] = metrics["timed_out"] or bool(
                    timeout is not None and now - started > timeout
                )
                metrics["memory_exceeded"] = metrics["memory_exceeded"] or bool(
                    memory_limit_mb and rss is not None and rss > memory_limit_mb * 1024 * 1024
                )
                metrics["cancelled"] = metrics["cancelled"] or bool(cancel and cancel.is_set())
                if metrics["timed_out"] or metrics["memory_exceeded"] or metrics["cancelled"]:
                    try:
                        if os.name == "posix":
                            getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL", 9))
                        else:
                            process.kill()
                    except ProcessLookupError:
                        pass
                if now >= next_log:
                    logger.log(
                        log_level,
                        "[indexing-heartbeat] phase=%s pid=%d elapsed=%.1fs rss=%s",
                        label,
                        process.pid,
                        now - started,
                        rss,
                    )
                    next_log = now + heartbeat_seconds
                time.sleep(0.05)
        except BaseException:
            try:
                if os.name == "posix":
                    getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL", 9))
                else:
                    process.kill()
            except ProcessLookupError:
                pass
            process.wait()
            raise
    metrics["wall_seconds"] = time.monotonic() - started
    metrics["exit_code"] = process.returncode
    metrics["stdout_path"] = str(stdout_path)
    metrics["stderr_path"] = str(stderr_path)
    metrics["output_truncated"] = any(
        p.stat().st_size > output_limit for p in (stdout_path, stderr_path)
    )

    def read_output(path: Path) -> str:
        with path.open("rb") as handle:
            return handle.read(output_limit).decode("utf-8", errors="replace")

    logger.log(log_level, "[indexing-process] %s", metrics)
    return MeasuredProcess(
        int(process.returncode), read_output(stdout_path), read_output(stderr_path), metrics
    )
