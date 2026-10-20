"""Satisfy the occupancy inspection contract; never bypass or rename the branch."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import time
from uuid import uuid4
from dispatch_safety import DispatchJournal

sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def call(payload):
    request = route / "bridge-queue" / ("080-" + payload["id"] + ".request.json")
    response = route / ("bridge-response-" + payload["id"] + ".json")
    assert not request.exists() and not response.exists()
    write(request, payload)
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists(), "unknown outcome; inspect exact persisted request before any retry"
    return read(response), response

path = HERE / "tasks.json"
ledger = read(path)
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["bridge_task_id"] == "task_14643c6dda" and row["producer_status"] == "failed"
failed_path = route / "bridge-response-r20-protocol-get_result-7ee481d698.json"
failed = read(failed_path)
assert failed["status"] == "failed" and failed["task_id"] == "task_14643c6dda" and failed["failure"]["kind"] == "protocol_error"
ended_path = route / "bridge-response-r20-protocol-recovery-end-failed-session.json"
ended = read(ended_path)
assert ended["ok"] and ended["session_id"] == "sess_b91680bb39" and ended["proc_state"] == "dead"
sessions, session_receipt = call({"id": "r20-reconcile-sessions-" + uuid4().hex[:10], "tool": "list_sessions", "arguments": {"active_only": False}})
assert sessions["ok"]
old = next(r for r in sessions["sessions"] if r["session_id"] == ended["session_id"])
assert old["proc_state"] == "dead"
assert not any(r.get("proc_state") in {"busy", "running"} and str(ROOT).lower() in str(r.get("cwd", "")).lower() for r in sessions["sessions"])
review = read(ROOT / "artifacts/coordinator-job-cli-delivery-boundary-r20-preflight-20261015/review.json")
workspace = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
assert all(hashlib.sha256((workspace / p).read_bytes()).hexdigest() == h for p, h in review["delivered_hashes"].items())
original_path = HERE / "followups-r12/job-cli-window-r20-sql-protocol-recovery-request.json"
original = read(original_path)
assert original["branch"] == "job-cli-window-r20"
blocked = None
for line in (route / "post-update-owner-stdout.log").read_text(encoding="utf-8").splitlines():
    if line.startswith("{"):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if value.get("request") == original["id"]:
            blocked = value
assert blocked == {"request": original["id"], "ok": False, "error": "branch_occupied; inspect_public_task_and_execution_before_retry"}
journal = DispatchJournal(route / "dispatch-journal.sqlite")
prior = journal.db.execute("SELECT id,branch,state,task_id FROM requests WHERE task_id=?", ("task_14643c6dda",)).fetchall()
assert len(prior) == 1 and prior[0][1:] == ("job-cli-window-r20", "accepted", "task_14643c6dda")
assert journal.db.execute("SELECT id FROM requests WHERE id=?", (original["arguments"]["request_id"],)).fetchone() is None, "prior retry may have reached dispatch; inspect before proceeding"
# This is the existing evidence-based terminal API, with the public failed
# receipt and a deliberately closed ACP process. No safety predicate changes.
journal.terminal("task_14643c6dda", "failed")
after = journal.db.execute("SELECT id,branch,state,task_id FROM requests WHERE task_id=?", ("task_14643c6dda",)).fetchall()
journal.close()
assert after[0][2] == "failed"
inspection_at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"inspected_at": inspection_at, "blocked_request": blocked, "original_retry_not_entered_journal": True, "public_failed_receipt": failed_path.relative_to(HERE).as_posix(), "closed_session_receipt": ended_path.relative_to(HERE).as_posix(), "current_dead_session_receipt": session_receipt.relative_to(HERE).as_posix(), "linux_process_inspection": "inspect_workspace_processes.py job-cli-window-r20 returned [] before recovery; public end_session plus fresh dead-state confirms no active old ACP writer", "owned_source_unchanged": review["delivered_hashes"], "journal_before": prior, "journal_after": after, "journal_api": "DispatchJournal.terminal(task_14643c6dda, failed)", "branch_or_policy_changed": False, "owner_restarted": False, "model_or_provider_changed": False, "counts_as_glm_actual_delivery_failure": False, "development_failure_streak": 1}
proof_path = HERE / "followups-r12/job-cli-window-r20-protocol-reconciled.json"
write(proof_path, proof)
payload = {**original, "id": "job-cli-window-r20-sql-reconciled"}
assert payload["arguments"] == original["arguments"] and payload["branch"] == original["branch"]
write(HERE / "followups-r12/job-cli-window-r20-sql-reconciled-request.json", payload)
result, response = call(payload)
assert result["ok"] and result["model"] == row["requested_model"] and result["session_id"] != ended["session_id"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof.update(accepted_at=at, new_task_id=result["task_id"], new_session_id=result["session_id"], accepted_receipt=response.relative_to(HERE).as_posix())
write(proof_path, proof)
row.setdefault("execution_history", []).append({"task_id": "task_14643c6dda", "status": "failed_transport_protocol_closed_and_reconciled", "finished_at": "2026-10-15T22:04:03.576513+08:00", "counts_as_glm_actual_delivery_failure": False, "recovery_evidence": proof_path.relative_to(HERE).as_posix()})
row.update(bridge_task_id=result["task_id"], bridge_session_id=result["session_id"], request_id=payload["arguments"]["request_id"], dispatch_evidence=response.relative_to(HERE).as_posix(), status="sql_authority_repair_protocol_reconciled_same_model_execution_pending", producer_status="dispatched", observed_model=None, worker_finished_at=None, artifact_available=False, checked_at=at)
ledger["updated_at"] = at
write(path, ledger)
print(json.dumps({"at": at, "task_id": result["task_id"], "session_id": result["session_id"], "same_branch_model": True, "development_failure_count": 1, "reconciliation": proof_path.relative_to(HERE).as_posix()}), flush=True)
