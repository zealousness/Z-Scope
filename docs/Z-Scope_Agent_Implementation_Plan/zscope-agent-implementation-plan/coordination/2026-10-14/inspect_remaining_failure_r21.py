"""Read the failed test's preserved SQLite/files and related clock observations."""
from pathlib import Path
import datetime as dt
import json
import sqlite3
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015"
source = json.loads((out / "source-evidence.json").read_text(encoding="utf-8"))
temporary = Path(source["temporary_directory"]).resolve()
assert str(temporary).startswith("/tmp/zscope-root-validation-")
matches = sorted({p.resolve() for p in temporary.glob("pytest-of-zeal/pytest-*/test_real_session_remaining_su0")})
assert len(matches) == 1
case = matches[0]
assert case.is_relative_to(temporary)
databases = list(case.rglob("jobs.db"))
assert len(databases) == 1
with sqlite3.connect(databases[0].resolve().as_uri() + "?mode=ro", uri=True) as db:
    db.row_factory = sqlite3.Row
    available = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
    fields = [k for k in ("job_id", "run_id", "status", "stop_at_epoch", "resolved_stop_time", "started_at", "updated_at", "pending_count", "progress_json") if k in available]
    job = dict(db.execute("SELECT " + ",".join(fields) + " FROM jobs").fetchone())
pending = [{"path": str(p), "data": json.loads(p.read_text(encoding="utf-8"))} for p in case.rglob("pending.json")]
executions = []
for p in case.rglob("executed.jsonl"):
    executions += [json.loads(s) for s in p.read_text(encoding="utf-8").splitlines() if s]
summary = [{"path": str(p), "data": json.loads(p.read_text(encoding="utf-8"))} for p in case.rglob("summary-*.json")]
clock = json.loads((out / "clock-observations.json").read_text(encoding="utf-8"))
times = [r["at"] for r in executions]
nearby = [r for r in clock["samples"] if times and min(times) - 8 <= r["wall_epoch"] <= max(times) + 8]
receipt = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "case": str(case), "job": job, "executions": executions, "pending": pending, "scheduler_summary": summary, "nearby_clock_samples": nearby, "clock_adjusted": False, "scope": "Actual failed test files and SQL, no scanner/job/clock mutation. Clock correlation is evidence, not a proof that all noncompiler failures share one cause."}
(out / "remaining-failure-diagnostic.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"job": job, "execution_count": len(executions), "scopes": [r["scope"] for r in executions], "execution_wall_times": times, "pending_counts": [r["data"].get("count") for r in pending], "nearby_clock_samples": nearby}, indent=2), flush=True)
