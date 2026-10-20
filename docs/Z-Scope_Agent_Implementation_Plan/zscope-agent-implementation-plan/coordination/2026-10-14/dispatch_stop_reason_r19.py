"""Freeze the rejected seven-file delivery, then dispatch one cause-preserving repair."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
name = "config-stop-at-r19-reason"
def call(value):
    target = route / "bridge-queue" / ("080-" + value["id"] + ".request.json")
    response = route / ("bridge-response-" + value["id"] + ".json")
    assert not target.exists() and not response.exists()
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists()
    return json.loads(response.read_text(encoding="utf-8")), response
sessions, _ = call({"id": name + "-preflight", "tool": "list_sessions", "arguments": {"active_only": False}})
session = next(r for r in sessions["sessions"] if r["session_id"] == "sess_b91680bb39")
assert session["proc_state"] in {"ready", "idle_unloaded"}
assert session["model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-STOP-AT-R18")
assert row["bridge_task_id"] == "task_9565621a54"
out = ROOT / "artifacts/coordinator-stop-budget-reason-r19-probes-20261015"
review = json.loads((out / "review.json").read_text(encoding="utf-8"))
assert review["source_unchanged"] and review["junit"]["failures"] == "2"
workspace = ROOT / ".coordination/20261014/workspaces/config-stop-at-r18"
for p in row["write_paths"]:
    assert hashlib.sha256((workspace / p).read_bytes()).hexdigest() == review["after"][p]
    target = out / "source-before" / p
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((workspace / p).read_bytes())
(out / "producer-delivery.md").write_bytes((workspace / "DELIVERY.md").read_bytes())
request = {"id": name, "branch": "config-stop-at-r18", "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": str(ROOT), "title": "U01-STOP-AT-R19-REASON", "session_id": session["session_id"], "model": session["model"], "user_requested": True, "request_id": str(uuid4()), "message": (HERE / "followups-r12" / (name + "-message.txt")).read_text(encoding="utf-8")}}
archive = HERE / "followups-r12" / (name + "-request.json")
assert not archive.exists()
archive.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
result, response = call(request)
assert result["ok"] and result["model"] == session["model"]
print(json.dumps(result), flush=True)
row.setdefault("execution_history", []).append({"task_id": "task_9565621a54", "finished_at": "2026-10-15T19:56:44.458234+08:00", "status": "original_budget_probes2_passed_but_reason_precedence2_failed", "review": "artifacts/coordinator-stop-budget-reason-r19-probes-20261015/review.json", "independent_acceptance": False, "integrated": False})
row.update(bridge_task_id=result["task_id"], bridge_session_id=result["session_id"], request_id=request["arguments"]["request_id"], dispatch_evidence=response.relative_to(HERE).as_posix(), status="reason_precedence_repair_dispatched_execution_pending", producer_status="dispatched", artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, observed_model=None, latest_failed_review="artifacts/coordinator-stop-budget-reason-r19-probes-20261015/review.json", checked_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat())
ledger["updated_at"] = row["checked_at"]
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
