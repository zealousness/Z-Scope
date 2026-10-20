"""Close the failed network-only ACP writer and reconcile its occupied branch."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import time
from uuid import uuid4
from dispatch_safety import DispatchJournal

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
def read(path):
    return json.loads(path.read_text(encoding="utf-8"))
def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
def call(tool, arguments):
    identity = "r20-network-close-" + tool + "-" + uuid4().hex[:10]
    write(route / "bridge-queue" / ("080-" + identity + ".request.json"), {"id": identity, "tool": tool, "arguments": arguments})
    response = route / ("bridge-response-" + identity + ".json")
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists(), "unknown outcome; inspect exact request before retry"
    return read(response), response
path = HERE / "tasks.json"
ledger = read(path)
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["bridge_task_id"] == "task_d98c531060" and row["producer_status"] == "failed"
assert row["consecutive_failed_actual_deliveries"] == 1
public, public_path = call("get_result", {"task_id": row["bridge_task_id"], "max_chars": 1000})
assert public["status"] == "failed" and public["observed_model"] is None and public["failure"]["kind"] == "protocol_error"
events = [json.loads(s) for s in (ROOT / ".coordination/20261014/bridge-route-check/transcripts/sess_e10155a00c.jsonl").read_text(encoding="utf-8").splitlines()]
retries = [r["data"]["text"] for r in events if r["type"] == "message_chunk"]
assert len(retries) == 5 and all("Network error, retrying" in r for r in retries)
assert not any("tool" in r["type"] for r in events)
expected = read(ROOT / "artifacts/coordinator-job-cli-delivery-boundary-r20-preflight-20261015/review.json")["delivered_hashes"]
branch = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in expected.items())
sessions, before_path = call("list_sessions", {"active_only": False})
assert sessions["ok"]
old = next(r for r in sessions["sessions"] if r["session_id"] == row["bridge_session_id"])
assert old["proc_state"] in {"ready", "idle_unloaded"}
assert not any(r.get("proc_state") in {"busy", "running"} and str(ROOT).lower() in str(r.get("cwd", "")).lower() for r in sessions["sessions"])
ended, end_path = call("end_session", {"session_id": old["session_id"]})
assert ended["ok"] and ended["proc_state"] == "dead"
sessions, after_path = call("list_sessions", {"active_only": False})
assert sessions["ok"] and next(r for r in sessions["sessions"] if r["session_id"] == old["session_id"])["proc_state"] == "dead"
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in expected.items())
journal = DispatchJournal(route / "dispatch-journal.sqlite")
prior = journal.db.execute("SELECT id,branch,state,task_id FROM requests WHERE task_id=?", (row["bridge_task_id"],)).fetchall()
assert len(prior) == 1 and prior[0][1:] == ("job-cli-window-r20", "accepted", row["bridge_task_id"])
journal.terminal(row["bridge_task_id"], "failed")
after = journal.db.execute("SELECT id,branch,state,task_id FROM requests WHERE task_id=?", (row["bridge_task_id"],)).fetchall()
journal.close()
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"at": at, "task_id": row["bridge_task_id"], "session_id": old["session_id"], "status": "failed_network_retries_only_closed", "failure_at": public["finished_at"], "public_failure_kind": public["failure"], "public_network_retries": retries, "tool_execution_observed": False, "observed_model": None, "owned_source_unchanged": expected, "linux_process_inspection": "22:22:38 inspector returned no workspace processes", "session_state_after": "dead", "journal_before": prior, "journal_after": after, "receipts": [p.relative_to(HERE).as_posix() for p in (public_path, before_path, end_path, after_path)], "owner_restarted": False, "provider_or_credentials_or_policy_changed": False, "counts_as_glm_actual_delivery_failure": False, "development_failure_streak": 1, "scope": "Transport network retry exhaustion; unknown turnState notification also logged but not proven causal. No platform rejection observed."}
proof_path = HERE / "followups-r12/job-cli-window-r20-network-closed.json"
write(proof_path, proof)
row.setdefault("execution_history", []).append({"task_id": row["bridge_task_id"], "status": proof["status"], "finished_at": public["finished_at"], "counts_as_glm_actual_delivery_failure": False, "recovery_evidence": proof_path.relative_to(HERE).as_posix()})
row.update(status="quiescent_complex_sql_handoff_ready", transport_failure_at=public["finished_at"], transport_failure_evidence=proof_path.relative_to(HERE).as_posix(), checked_at=at)
ledger["updated_at"] = at
write(path, ledger)
print(json.dumps({"at": at, "task_id": row["bridge_task_id"], "session_dead": True, "network_retries": 5, "development_failure_streak": 1}), flush=True)
