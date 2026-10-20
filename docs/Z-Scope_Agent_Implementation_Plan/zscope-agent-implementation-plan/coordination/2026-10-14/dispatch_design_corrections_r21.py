"""Resume the same two read-only design obligations through the existing owner."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
def read(p):
    return json.loads(p.read_text(encoding="utf-8"))
def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
def call(payload):
    target = route / "bridge-queue" / ("080-" + payload["id"] + ".request.json")
    response = route / ("bridge-response-" + payload["id"] + ".json")
    assert not target.exists() and not response.exists()
    write(target, payload)
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists(), "Unknown outcome: inspect this persisted request; never blind retry or start an owner"
    return read(response), response
stamp = uuid4().hex[:12]
sessions, preflight = call({"id": "r21-correction-active-" + stamp, "tool": "list_sessions", "arguments": {"active_only": True}})
agents, agent_preflight = call({"id": "r21-correction-agents-" + stamp, "tool": "list_agents", "arguments": {}})
assert sessions["ok"] and agents["ok"] and agents["coordinator"]["dispatch_enabled"]
targets = {"S01-INSTANCE-MODELING-DESIGN-R21", "S08-PARTIAL-RECOVERY-DESIGN-R21"}
known = {r["bridge_session_id"] for r in read(HERE / "tasks.json")["tasks"] if r["id"] in targets}
active = sessions.get("sessions", [])
assert {s["session_id"] for s in active} == known, "Reconcile missing or unexpected sessions before correction dispatch"
assert all(s.get("proc_state") == "ready" and s.get("model") == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3" for s in active), "Never resume a busy task or change its model"
for identity, name in (("S01-INSTANCE-MODELING-DESIGN-R21", "s01-instance-modeling-design-r21"), ("S08-PARTIAL-RECOVERY-DESIGN-R21", "s08-partial-recovery-design-r21")):
    ledger = read(HERE / "tasks.json")
    row = next(r for r in ledger["tasks"] if r["id"] == identity)
    assert row["status"] == "readonly_design_delivery_changes_requested_original_frozen"
    old_task, old_session = row["bridge_task_id"], row["bridge_session_id"]
    branch = ROOT / ".coordination/20261014/workspaces" / name
    baseline = read(HERE / "followups-r12" / (name + "-baseline.json"))
    assert all(hashlib.sha256((branch / r["path"]).read_bytes()).hexdigest() == r["sha256"] for r in baseline["files"])
    payload = read(HERE / "followups-r12" / (name + "-revision-1-request.json"))
    assert payload["arguments"]["session_id"] == old_session
    windows_branch = r"C:\Users\10273\home\work\Z-Scope_1.31\Z-Scope\.coordination\20261014\workspaces" + "\\" + name
    payload["arguments"]["message"] = f"原隔离 Windows 目录 {windows_branch}；Linux 对应 {branch}，必须继续在同一副本，只读产品。\n" + payload["arguments"]["message"]
    result, response = call(payload)
    if not result.get("ok"):
        print(json.dumps({"logical_task": identity, "dispatch_accepted": False, "evidence": response.relative_to(HERE).as_posix(), "error": result.get("error"), "failure": result.get("failure")}), flush=True)
        raise RuntimeError("Existing-owner correction dispatch rejected; no alternate route or automatic retry")
    assert result["model"] == payload["arguments"]["model"] and result["session_id"] == old_session
    at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    row.setdefault("design_revision_dispatches", []).append({"revision": 1, "original_task_id": old_task, "task_id": result["task_id"], "session_id": old_session, "dispatched_at": at, "evidence": response.relative_to(HERE).as_posix()})
    row.update(bridge_task_id=result["task_id"], original_design_task_id=old_task, design_revision=1, request_id=payload["arguments"]["request_id"], accepted_model=result["model"], status="same_logical_readonly_design_revision_dispatched_execution_pending", producer_status="dispatched", dispatched_at=at, dispatch_evidence=response.relative_to(HERE).as_posix(), active_sessions_preflight=preflight.relative_to(HERE).as_posix(), agents_preflight=agent_preflight.relative_to(HERE).as_posix(), artifact_available=False, current_revision_artifacts_frozen=False, worker_finished_at=None, checked_at=at)
    for key in ("actual_tool_execution_observed_at", "actual_execution_at", "worker_process_started_at", "observed_model"):
        row.pop(key, None)
    ledger["updated_at"] = at
    write(HERE / "tasks.json", ledger)
    print(json.dumps({"logical_task": identity, "revision": 1, "original_task_id": old_task, "task_id": result["task_id"], "session_id": old_session, "at": at, "actual_execution": False, "independent_acceptance": False, "evidence": response.relative_to(HERE).as_posix()}), flush=True)
