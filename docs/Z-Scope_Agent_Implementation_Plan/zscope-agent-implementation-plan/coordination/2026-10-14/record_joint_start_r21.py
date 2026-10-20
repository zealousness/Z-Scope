"""Record observed execution, without assuming any test or quality gate passed."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-r21-verified-environment-20261015"
runtime = json.loads((out / "runtime-preflight.json").read_text(encoding="utf-8"))
assert runtime["passed"]
assert (out / "command-0.log").exists()
assert (out / "launcher.py").read_bytes() == (HERE / "verify_current_root_r21.py").read_bytes()
observation = sorted(out.glob("process-observation-*.json"))[-1]
processes = json.loads(observation.read_text(encoding="utf-8"))
assert processes["processes"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "CURRENT-JOINT-R21")
assert row["status"].startswith("ready_")
row.update(status="actual_current_root_full_collection_running_quality_pending", actual_execution_observed_at=at, execution_evidence=observation.relative_to(ROOT).as_posix(), artifact_available=True, independent_acceptance=False, joint_verification=False, current_launcher_sha256=hashlib.sha256((out / "launcher.py").read_bytes()).hexdigest(), checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, current_joint=out.relative_to(ROOT).as_posix(), current_joint_status=row["status"], current_joint_execution_evidence=row["execution_evidence"], active_phase="R21 current full Root collection running; six commands mandatory; no new backend/UI dispatch yet")
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"observed_at": at, "task_id": row["id"], "actual_execution": True, "passed": False, "evidence": row["execution_evidence"]}), flush=True)
