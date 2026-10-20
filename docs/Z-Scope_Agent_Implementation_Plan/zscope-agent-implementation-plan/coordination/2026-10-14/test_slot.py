"""Run development checks in one of two Linux-only coordination slots."""

from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main() -> int:
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    if os.environ.get("ZSCOPE_COORDINATOR_TEST_SLOT"):
        parser.error("nested test_slot invocation refused; wrap each command exactly once")
    workspace = args.workspace.resolve(strict=True)
    slots = Path("/tmp/zscope-coordination-20261014-test-slots")
    slots.mkdir(exist_ok=True)
    streams = [(slots / f"{index}.lock").open("a") for index in range(2)]
    acquired = None
    announced = False
    try:
        while acquired is None:
            for index, stream in enumerate(streams):
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = index
                    break
                except BlockingIOError:
                    pass
            if acquired is None:
                if not announced:
                    print("Both Linux check slots are busy; waiting.", flush=True)
                    announced = True
                time.sleep(1)
        temporary = tempfile.mkdtemp(prefix="zscope-branch-check-", dir="/tmp")
        env = os.environ.copy()
        env["ZSCOPE_COORDINATOR_TEST_SLOT"] = f"{os.getpid()}:{acquired}"
        env["PYTHONPATH"] = str(workspace)
        for name in ("TMPDIR", "TEMP", "TMP"):
            env[name] = temporary
        print(f"check_slot={acquired} workspace={workspace} temp={temporary}", flush=True)
        return subprocess.run(command, cwd=workspace, env=env).returncode
    finally:
        for stream in streams:
            stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
