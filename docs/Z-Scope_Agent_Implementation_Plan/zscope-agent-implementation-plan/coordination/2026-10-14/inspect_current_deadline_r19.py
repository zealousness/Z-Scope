"""Read only suspected current deadline fixture SQL, without token/env output."""
from pathlib import Path
import datetime as dt
import json
import os
import sqlite3
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-r18-queue-receipt-repaired-20261015"
directories = set()
for process in Path("/proc").iterdir():
    if not process.name.isdigit() or int(process.name) == os.getpid():
        continue
    try:
        if (process / "cwd").readlink() != ROOT:
            continue
        args = (process / "cmdline").read_bytes().split(b"\0")
        if b"pytest" not in args:
            continue
        for entry in (process / "environ").read_bytes().split(b"\0"):
            if entry.startswith(b"TMPDIR=/tmp/zscope-root-validation-"):
                directories.add(Path(entry[len(b"TMPDIR="):].decode()))
    except (OSError, ValueError):
        continue
rows = []
for directory in sorted(directories):
    for fixture in directory.glob("pytest-of-*/pytest-*/test_claimed_work_finishes_bou0"):
        for path in fixture.rglob("jobs.db"):
            conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                job_table = "jobs" if "jobs" in tables else "scan_jobs"
                event_table = "events" if "events" in tables else "job_events"
                jobs = [dict(r) for r in conn.execute(f"SELECT job_id,run_id,status,stop_at_epoch,revision FROM {job_table}")]
                columns = {r[1] for r in conn.execute(f"PRAGMA table_info({event_table})")}
                selected = [p for p in ("seq", "at", "created_at", "kind", "data_json") if p in columns]
                events = [dict(r) for r in conn.execute(f"SELECT {','.join(selected)} FROM {event_table} ORDER BY seq")]
                rows.append({"fixture": str(fixture), "jobs": jobs, "events": events})
            finally:
                conn.close()
proof = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "inferred_failure_only_until_junit": True, "fixtures": rows}
(out / "deadline-timeline-live.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(proof, ensure_ascii=False), flush=True)
