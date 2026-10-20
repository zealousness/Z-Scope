"""Read original-owner public repair state and reconcile bounded task stages."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
stamp = uuid4().hex[:10]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
requests = {
    "context": ("check_task", {"task_id": "task_bf7efdfce3"}),
    "deadline": ("check_task", {"task_id": "task_9565621a54"}),
    "sessions": ("list_sessions", {"active_only": False}),
}
responses = {}
for label, (tool, arguments) in requests.items():
    identity = f"r19-observe-{label}-{stamp}"
    target = route / "bridge-queue" / ("080-" + identity + ".request.json")
    assert not target.exists()
    target.write_text(json.dumps({"id": identity, "tool": tool, "arguments": arguments}) + "\n", encoding="utf-8", newline="\n")
    responses[label] = route / ("bridge-response-" + identity + ".json")
deadline = time.monotonic() + 40
while not all(p.exists() for p in responses.values()) and time.monotonic() < deadline:
    time.sleep(.25)
values = {}
for label, path in responses.items():
    if not path.exists():
        print(json.dumps({"label": label, "response_pending": str(path)}), flush=True)
        continue
    raw = json.loads(path.read_text(encoding="utf-8"))
    if label == "sessions":
        values[label] = {"sessions": [{k: row.get(k) for k in ("session_id", "agent", "model", "proc_state", "task_id", "cwd")} for row in raw.get("sessions", []) if row.get("session_id") in {"sess_a0adb99b15", "sess_b91680bb39", "sess_3b6b9a19b2", "sess_261a55289f"}]}
    else:
        values[label] = {k: raw.get(k) for k in ("ok", "task_id", "session_id", "status", "model", "observed_model", "started_at", "finished_at", "failure", "warnings")}
        values[label]["actual_tool_activity"] = [r for r in raw.get("recent_activity", []) if isinstance(r, str) and r.startswith("tool_call")]
    values[label]["receipt"] = path.relative_to(HERE).as_posix()
    print(json.dumps({"label": label, "checked_at": at, **values[label]}, ensure_ascii=False), flush=True)
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
if "deadline" in values and values["deadline"].get("ok"):
    row = rows["U01-STOP-AT-R18"]
    if row.get("bridge_task_id") != "task_9565621a54":
        row.setdefault("execution_history", []).append({"task_id": "task_5b722e514f", "status": "delivered_independent_deadline_probes_failed", "finished_at": "2026-10-15T18:57:45.691140+08:00", "independent_acceptance": False, "integrated": False, "review": "artifacts/coordinator-stop-deadline-r18-probes-20261015/review.json", "result": {"passed": 0, "failed": 2, "errors": 0, "skipped": 0}})
    row.update(bridge_task_id="task_9565621a54", bridge_session_id="sess_b91680bb39", request_id="23a32604-735b-4112-8522-84df5139ac61", dispatch_evidence="route-check/bridge-response-config-stop-at-r18-deadline.json", status="repair_actual_execution_independent_acceptance_pending", producer_status=values["deadline"].get("status"), actual_execution_at=values["deadline"].get("started_at"), observed_model=values["deadline"].get("observed_model"), execution_evidence=values["deadline"]["receipt"], independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False, checked_at=at)
    row["latest_failed_review"] = "artifacts/coordinator-stop-deadline-r18-probes-20261015/review.json"
if "context" in values and values["context"].get("ok"):
    row = rows["VALIDATION-CONTEXT-R18"]
    assert row["bridge_task_id"] == "task_bf7efdfce3"
    row.update(producer_status=values["context"].get("status"), checked_at=at, execution_evidence=values["context"]["receipt"])
    if values["context"].get("status") == "completed":
        row.update(status="delivered_callee_repair_independent_acceptance_running", artifact_available=True, worker_finished_at=values["context"].get("finished_at"), independent_acceptance=False, integrated=False, joint_verification=False)
if "CURRENT-JOINT-R18" in rows:
    rows["CURRENT-JOINT-R18"].update(status="queue_receipt_test_migration_intaken_full_retry_running", evidence="artifacts/coordinator-r18-queue-receipt-repaired-20261015", checked_at=at)
ledger["updated_at"] = at
ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, current_joint="artifacts/coordinator-r18-queue-receipt-repaired-20261015", current_joint_status="running_current_root_unverified", latest_joint_attempt="artifacts/coordinator-r18-queue-receipt-repaired-20261015", latest_joint_attempt_passed=False, prior_pass_is_current_root=False, current_root_status="19:08 queue SQL receipt test migration intaken; 132-file current-root retry running, prior R17 pass historical", active_phase="Await current root full result; isolated ZCode callee and deadline repairs, no new Kimi/old S06 operation")
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
out = HERE / "followups-r12" / ("repair-observation-r19-" + stamp + ".json")
out.write_text(json.dumps({"at": at, **values}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
