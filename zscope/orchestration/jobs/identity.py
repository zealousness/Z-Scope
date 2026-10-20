"""Process identity probing for job owners and their scanner groups.

A PID alone is never proof of identity: the kernel recycles PIDs.  Identity
is the triple ``(pid, /proc/<pid>/stat start_ticks, boot_id)``.  All signal
decisions require the probe to match the recorded triple, so a recycled PID
or a crashed owner is never signalled by mistake.

This is a Linux-first capability (``/proc``).  On platforms without ``/proc``
the probe returns ``None`` and callers must degrade to ``unknown`` instead of
guessing.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def system_boot_id() -> Optional[str]:
    try:
        return _BOOT_ID_PATH.read_text(encoding="ascii").strip() or None
    except OSError:
        return None


def read_process_stat(pid: int) -> Optional[tuple[int, str]]:
    """Return ``(start_ticks, state)`` or None when the process is not visible.

    None is returned both when the process is gone and when /proc is not
    available; callers distinguish those via :func:`proc_available`.
    """

    if pid <= 0:
        return None
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    # comm may contain spaces and parentheses; fields resume after the last ')'.
    close = raw.rfind(")")
    if close < 0 or close + 2 > len(raw):
        return None
    fields = raw[close + 2 :].split()
    # fields[0] is state (field 3); start time is field 22 -> index 19.
    if len(fields) <= 19:
        return None
    try:
        return int(fields[19]), fields[0]
    except ValueError:
        return None


def read_process_start_ticks(pid: int) -> Optional[int]:
    stat = read_process_stat(pid)
    return stat[0] if stat is not None else None


def proc_available() -> bool:
    return os.name == "posix" and Path("/proc/self/stat").is_file()


def probe_process(pid: Optional[int], *, expected_start_ticks: Optional[int]) -> Optional[bool]:
    """Verify a recorded identity.

    Returns True (verifiably alive with matching start time), False
    (verifiably gone: no such PID, the recorded process exited — including
    a zombie not yet reaped by its parent — or the PID was recycled), or
    None (no recorded pid, the recorded identity is incomplete, or the
    platform cannot verify).
    """

    if pid is None or pid <= 0:
        # No process was ever recorded; absence of evidence is not death.
        return None
    if not proc_available():
        return None
    stat = read_process_stat(pid)
    if stat is None:
        return False
    ticks, state = stat
    if state == "Z":
        # The process exited; the kernel still holds its PID for the parent
        # to reap, so this verdict cannot mistake a recycled PID for it.
        return False
    if expected_start_ticks is None:
        # The owner never reported its start ticks; we can see *a* process but
        # cannot confirm it is the one we recorded.
        return None
    return ticks == expected_start_ticks


def self_start_ticks() -> Optional[int]:
    return read_process_start_ticks(os.getpid())
