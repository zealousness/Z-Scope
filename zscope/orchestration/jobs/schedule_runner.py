"""Detached coordinator entry point. One flock owner per saved YAML scope."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import time

from .identity import read_process_start_ticks, system_boot_id
from .schedules import LIVE, ScanScheduleService


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Persistent saved-config scan schedule coordinator"
    )
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    service = ScanScheduleService(args.config, spawn_daemon=False)
    with service.db_path.with_suffix(".coordinator.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        identity = {
            "pid": os.getpid(),
            "start_ticks": read_process_start_ticks(os.getpid()),
            "boot_id": system_boot_id(),
        }
        identity_path = service.db_path.with_suffix(".owner.json")
        temporary = identity_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(identity), encoding="utf-8")
        os.replace(temporary, identity_path)
        while True:
            service.tick()
            with service._db() as db:
                rows = [json.loads(row[0]) for row in db.execute("SELECT data FROM schedules")]
            # Stay resident while idle: exiting immediately after observing no
            # plans races a creator that just saw this process still alive.
            # The lock/identity remain valid across project switches and new
            # plans. After a host/process restart, list/create restarts us.
            active = any(row["status"] in LIVE or row.get("cancel_pending") for row in rows)
            time.sleep(2 if active else 5)


if __name__ == "__main__":
    raise SystemExit(main())
