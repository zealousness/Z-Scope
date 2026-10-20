"""One durable dispatch each, after confirming the original owner's idle sessions."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
def request(value):
    target = route / "bridge-queue" / ("080-" + value["id"] + ".request.json")
    response = route / ("bridge-response-" + value["id"] + ".json")
    assert not target.exists() and not response.exists()
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists(), str(response)
    return json.loads(response.read_text(encoding="utf-8")), response
sessions, _ = request({"id": "r19-repairs-sessions-preflight", "tool": "list_sessions", "arguments": {"active_only": False}})
agents, _ = request({"id": "r19-repairs-agents-preflight", "tool": "list_agents", "arguments": {}})
assert agents["coordinator"]["dispatch_enabled"] is True
print(json.dumps({"coordinator": agents["coordinator"]}, ensure_ascii=False), flush=True)
model = "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
specs = [("validation-context-r19-snapshot", "validation-context-r18", "VALIDATION-CONTEXT-R18", "sess_a0adb99b15"), ("native-hot-cache-r19", "native-hot-cache-r19", "S07-NATIVE-HOT-R19", "sess_3b6b9a19b2")]
for name, branch, identity, session_id in specs:
    session = next(s for s in sessions["sessions"] if s["session_id"] == session_id)
    assert session["proc_state"] in {"ready", "idle_unloaded"} and session["model"] == model
    archive = HERE / "followups-r12" / (name + "-request.json")
    assert not archive.exists()
    value = {"id": name, "branch": branch, "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": str(ROOT), "title": identity + ("-SNAPSHOT" if identity == "VALIDATION-CONTEXT-R18" else ""), "session_id": session_id, "model": model, "user_requested": True, "request_id": str(uuid4()), "message": (HERE / "followups-r12" / (name + "-message.txt")).read_text(encoding="utf-8")}}
    archive.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    result, response = request(value)
    print(json.dumps({"name": name, **result}, ensure_ascii=False), flush=True)
    assert result["ok"] and result["model"] == model
    path = HERE / "tasks.json"
    ledger = json.loads(path.read_text(encoding="utf-8"))
    row = next(r for r in ledger["tasks"] if r["id"] == identity)
    if identity == "VALIDATION-CONTEXT-R18":
        row.setdefault("execution_history", []).append({"task_id": "task_bf7efdfce3", "status": "1074_collection_and_four_quality_passed_but_snapshot_probes_failed", "collection_review": "artifacts/coordinator-validation-context-r18-callee-repaired-20261015/review.json", "review": "artifacts/coordinator-validation-snapshot-r19-probes-20261015/review.json", "independent_acceptance": False, "integrated": False})
        row["latest_failed_review"] = "artifacts/coordinator-validation-snapshot-r19-probes-20261015/review.json"
    row.update(bridge_task_id=result["task_id"], bridge_session_id=result["session_id"], request_id=value["arguments"]["request_id"], accepted_model=model, status="snapshot_repair_dispatched_execution_pending" if identity == "VALIDATION-CONTEXT-R18" else "current_native_hot_repair_dispatched_execution_pending", dispatch_evidence=response.relative_to(HERE).as_posix(), artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False, checked_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat())
    ledger["updated_at"] = row["checked_at"]
    path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
