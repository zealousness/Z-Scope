"""Terminate only the failed idle ACP session before a same-model fresh retry."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import time
from uuid import uuid4

sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"

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
    assert response.exists(), "unknown outcome, inspect the persisted exact request instead of redispatch"
    return json.loads(response.read_text(encoding="utf-8")), response

ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["bridge_task_id"] == "task_14643c6dda" and row["producer_status"] == "failed"
assert row["consecutive_failed_actual_deliveries"] == 1
review = json.loads((ROOT / "artifacts/coordinator-job-cli-delivery-boundary-r20-preflight-20261015/review.json").read_text(encoding="utf-8"))
workspace = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
expected = review["delivered_hashes"]
def hashes():
    return {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in expected}
assert hashes() == expected
agents, agents_receipt = call({"id": "r20-protocol-recovery-agents", "tool": "list_agents", "arguments": {}})
assert agents["ok"] and agents["coordinator"]["dispatch_enabled"]
sessions, sessions_receipt = call({"id": "r20-protocol-recovery-sessions", "tool": "list_sessions", "arguments": {"active_only": False}})
assert sessions["ok"]
old = next(r for r in sessions["sessions"] if r["session_id"] == "sess_b91680bb39")
assert old["proc_state"] in {"ready", "idle_unloaded"}
assert not any(r.get("proc_state") in {"busy", "running"} and str(ROOT).lower() in str(r.get("cwd", "")).lower() for r in sessions["sessions"])
ended, ended_receipt = call({"id": "r20-protocol-recovery-end-failed-session", "tool": "end_session", "arguments": {"session_id": old["session_id"]}})
assert ended["ok"]
assert hashes() == expected
sessions, stopped_receipt = call({"id": "r20-protocol-recovery-stopped-sessions", "tool": "list_sessions", "arguments": {"active_only": False}})
assert sessions["ok"]
old_after = next((r for r in sessions["sessions"] if r["session_id"] == old["session_id"]), None)
assert old_after is None or old_after["proc_state"] in {"dead", "idle_unloaded", "closed", "ended"}, old_after
message = (HERE / "followups-r12/job-cli-window-r20-sql-message.txt").read_text(encoding="utf-8")
message = "传输恢复：上一个task_14643c6dda在session/prompt阶段protocol_error（可能已送达），协调者已核实session ready、Linux无后台、3源码SHA未变，经原owner结束该失败ACP会话并核实dead后才新开同glm-5.3会话。它不是实际开发交付失败，当前逻辑工作项开发失败连续计数仍1；不改provider/凭据/全局路由，不是平台审核拦截或规避。所有交付文件和task_492e7a7037历史保留。隔离目录仍只有job-cli-window-r20；请先读现存DELIVERY及明确三SQL独验失败再继续，不重复Root已验收工作。\n\n" + message.replace("同一 U01-JOB-CLI-WINDOW-R20 / sess_b91680bb39 / job-cli-window-r20 返修第2轮。", "同一 U01-JOB-CLI-WINDOW-R20 / job-cli-window-r20 返修第2轮，使用本新会话。")
identity = "job-cli-window-r20-sql-protocol-recovery"
payload = {"id": identity, "branch": "job-cli-window-r20", "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": str(ROOT), "title": "U01-JOB-CLI-WINDOW-R20-SQL-RECOVERY", "model": row["requested_model"], "request_id": str(uuid4()), "user_requested": True, "message": message}}
write(HERE / "followups-r12" / (identity + "-request.json"), payload)
result, receipt = call(payload)
assert result["ok"] and result["model"] == row["requested_model"]
assert result["session_id"] != old["session_id"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"at": at, "failed_task_id": "task_14643c6dda", "failure_kind": "session/prompt protocol_error, prompt_may_have_been_sent", "old_session": old["session_id"], "old_session_after": old_after, "original_owner_restarted": False, "provider_or_credentials_changed": False, "counts_as_glm_actual_delivery_failure": False, "consecutive_failed_actual_deliveries": 1, "owned_before_after": expected, "sources_unchanged": hashes() == expected, "receipts": [p.relative_to(HERE).as_posix() for p in (agents_receipt, sessions_receipt, ended_receipt, stopped_receipt, receipt)], "new_task_id": result["task_id"], "new_session_id": result["session_id"]}
write(HERE / "followups-r12/job-cli-window-r20-protocol-recovery.json", proof)
row.setdefault("execution_history", []).append({"task_id": "task_14643c6dda", "status": "failed_transport_protocol_no_observed_execution", "finished_at": "2026-10-15T22:04:03.576513+08:00", "counts_as_glm_actual_delivery_failure": False, "recovery_evidence": "followups-r12/job-cli-window-r20-protocol-recovery.json"})
row.update(bridge_task_id=result["task_id"], bridge_session_id=result["session_id"], request_id=payload["arguments"]["request_id"], dispatch_evidence=receipt.relative_to(HERE).as_posix(), status="sql_authority_repair_same_model_protocol_recovered_execution_pending", producer_status="dispatched", observed_model=None, worker_finished_at=None, artifact_available=False, checked_at=at)
ledger["updated_at"] = at
write(ledger_path, ledger)
print(json.dumps({"at": at, "task_id": result["task_id"], "session_id": result["session_id"], "old_session_state": None if old_after is None else old_after["proc_state"], "same_model": result["model"], "development_failure_count": 1}), flush=True)
