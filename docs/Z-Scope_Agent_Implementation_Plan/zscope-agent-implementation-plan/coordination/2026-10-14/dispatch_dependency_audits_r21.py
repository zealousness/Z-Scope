"""Dispatch two distinct read-only audits through the existing owner only."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import time
from uuid import uuid4

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
def read(path):
    return json.loads(path.read_text(encoding="utf-8"))
def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
gate = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/review.json"
review = read(gate)
assert review["all_current_selected_validation_passed"] and review["is_current_root"] and review["commands_passed"] == 6
source = read(gate.parent / "source-evidence.json")["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source.items())
def call(payload):
    target = route / "bridge-queue" / ("080-" + payload["id"] + ".request.json")
    response = route / ("bridge-response-" + payload["id"] + ".json")
    assert not target.exists() and not response.exists()
    write(target, payload)
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists(), "Unknown outcome; inspect this persisted request and existing owner, never blind retry"
    return read(response), response
stamp = uuid4().hex[:10]
sessions, session_receipt = call({"id": "r21-design-preflight-sessions-" + stamp, "tool": "list_sessions", "arguments": {"active_only": True}})
agents, agent_receipt = call({"id": "r21-design-preflight-agents-" + stamp, "tool": "list_agents", "arguments": {}})
assert sessions["ok"] and agents["ok"] and agents["coordinator"]["dispatch_enabled"]
assert not sessions.get("sessions"), "Unexpected active Bridge task: reconcile owner and ownership before dispatch"
specs = [("S01-INSTANCE-MODELING-DESIGN-R21", "s01-instance-modeling-design-r21"), ("S08-PARTIAL-RECOVERY-DESIGN-R21", "s08-partial-recovery-design-r21")]
for identity, name in specs:
    ledger = read(HERE / "tasks.json")
    assert identity not in {r["id"] for r in ledger["tasks"]}
    baseline = read(HERE / "followups-r12" / (name + "-baseline.json"))
    assert baseline["task"]["id"] == identity and baseline["task"]["owns"] == []
    branch = ROOT / ".coordination/20261014/workspaces" / name
    assert all(hashlib.sha256((branch / r["path"]).read_bytes()).hexdigest() == r["sha256"] for r in baseline["files"])
    payload = read(HERE / "followups-r12" / (name + "-request.json"))
    assert payload["arguments"]["model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3" and payload["arguments"]["user_requested"]
    result, response = call(payload)
    assert result["ok"] and result["model"] == payload["arguments"]["model"]
    at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    row = {**baseline["task"], "agent_kind": "agent_bridge", "bridge_task_id": result["task_id"], "bridge_session_id": result["session_id"], "request_id": payload["arguments"]["request_id"], "requested_model": payload["arguments"]["model"], "accepted_model": result["model"], "status": "readonly_design_audit_dispatched_actual_execution_pending", "producer_status": "dispatched", "dispatched_at": at, "dispatch_evidence": response.relative_to(HERE).as_posix(), "active_sessions_preflight": session_receipt.relative_to(HERE).as_posix(), "agents_preflight": agent_receipt.relative_to(HERE).as_posix(), "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "product_changed": False, "whole_package_complete": False, "consecutive_failed_actual_deliveries": 0, "checked_at": at}
    ledger["tasks"].append(row)
    rows = {r["id"]: r for r in ledger["tasks"]}
    pending, done, layers = set(rows), set(), []
    while pending:
        ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
        assert ready
        layers.append(ready)
        done.update(ready)
        pending.difference_update(ready)
    ledger.update(updated_at=at, topological_layers=layers)
    write(HERE / "tasks.json", ledger)
    print(json.dumps({"logical_task": identity, "task_id": result["task_id"], "session_id": result["session_id"], "accepted_model": result["model"], "at": at, "actual_execution": False, "independent_acceptance": False, "evidence": row["dispatch_evidence"]}), flush=True)
