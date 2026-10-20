"""Dispatch two isolated candidates only after current Root and contract acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import time
from bridge_queue_publish_r23 import publish_request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def call(payload):
    target = route / "bridge-queue" / ("080-" + payload["id"] + ".request.json")
    response = route / ("bridge-response-" + payload["id"] + ".json")
    assert not target.exists() and not response.exists(), "Existing request must be reconciled, never redispatched blindly"
    publish_request(route / "bridge-queue", payload)
    until = time.monotonic() + 40
    result = None
    while time.monotonic() < until:
        if response.exists():
            try:
                result = read(response)
                break
            except json.JSONDecodeError:
                pass  # Only wait for the existing response; never redispatch.
        time.sleep(.25)
    assert result is not None, "Unknown original-owner outcome: inspect persisted request, do not restart or retry another route"
    return result, response

assert len(sys.argv) == 2
preflight_path = HERE / sys.argv[1]
preflight = read(preflight_path)
assert preflight["existing_owner_only"] and preflight["atomic_request_publication"] and preflight["active_sessions"] == []
observed = dt.datetime.fromisoformat(preflight["at"])
assert abs((dt.datetime.now(observed.tzinfo) - observed).total_seconds()) < 300, "Need a fresh read-only owner/session preflight"
agents = read(HERE / preflight["response_paths"]["list_agents"])
assert agents["ok"] and agents["coordinator"]["dispatch_enabled"]
assert any(a.get("agent") == "zcode" and a.get("available") for a in agents["agents"])
joint_dir = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016"
joint = read(joint_dir / "review.json")
source = read(joint_dir / "source-evidence.json")
assert joint["all_current_selected_validation_passed"] and joint["is_current_root"]
assert joint["commands_passed"] == 6 and joint["pytest_file_count"] == 171
assert joint["failed"] == joint["errors"] == joint["skipped"] == 0
assert all(sha(ROOT / p) == h for p, h in source["after"].items())
design_path = ROOT / "artifacts/design-contract-independent-review-r23-20261016/review.json"
design = read(design_path)
assert design["source_review_passed"] and design["design_dispatch_ready"] and not design["blocking_findings"]
assert all(sha(ROOT / p) == h for p, h in design["reviewed_contract_hashes"].items())
assert all(sha(ROOT / p) == h for p, h in design["source_hashes_after"].items())
dispatch_review = read(ROOT / "artifacts/module-dispatch-independent-review-r23-20261016/final-review.json")
assert dispatch_review["source_review_passed"] and dispatch_review["tests_executed"] == 0
required_reviewed = {str((HERE / p).relative_to(ROOT)) for p in (
    "dispatch_modules_r23.py", "observe_module_tasks_r23.py", "prepare_module_workspaces_r23.py",
    "freeze_module_contract_r23.py", "preflight_parallel_r23.py", "bridge_queue_publish_r23.py",
    "followups-r12/s01-instance-semantics-min-r23-request.json", "followups-r12/s08-instance-recovery-min-r23-request.json",
)}
assert set(dispatch_review["reviewed_hashes"]) == required_reviewed
assert all(sha(ROOT / p) == h for p, h in dispatch_review["reviewed_hashes"].items())
known_sessions = set()
for identity, name in (("S01-INSTANCE-SEMANTICS-MIN-R23", "s01-instance-semantics-min-r23"), ("S08-INSTANCE-RECOVERY-MIN-R23", "s08-instance-recovery-min-r23")):
    ledger = read(HERE / "tasks.json")
    row = next(r for r in ledger["tasks"] if r["id"] == identity)
    assert row["status"] == "prepared_not_dispatched_root_joint_and_contract_gates_pending" and not row.get("bridge_task_id")
    branch = ROOT / ".coordination/20261014/workspaces" / name
    baseline = read(HERE / "followups-r12" / (name + "-baseline.json"))
    assert all(sha(branch / r["path"]) == r["sha256"] for r in baseline["files"])
    dependencies = read(HERE / "followups-r12" / (name + "-dependencies.json"))
    assert len(dependencies["files"]) == 2 and all(r["read_only"] for r in dependencies["files"])
    assert all(sha(branch / r["path"]) == r["sha256"] == sha(ROOT / r["path"]) for r in dependencies["files"])
    assert all(not (branch / p).exists() and not (ROOT / p).exists() for p in row["write_paths"])
    assert set(row["write_paths"]).isdisjoint({p for other in ledger["tasks"] if other["id"] != identity and other.get("workspace") == name for p in other.get("write_paths", [])})
    active, active_path = call({"id": name + "-dispatch-active-check", "tool": "list_sessions", "arguments": {"active_only": True}})
    assert active["ok"] and {s["session_id"] for s in active.get("sessions", [])} <= known_sessions, "New or duplicate active worker: reconcile before dispatch"
    payload = read(HERE / "followups-r12" / (name + "-request.json"))
    assert payload["arguments"]["model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3" and "session_id" not in payload["arguments"]
    result, response = call(payload)
    if not result.get("ok"):
        row.update(status="dispatch_rejected_no_alternate_route", dispatch_evidence=response.relative_to(HERE).as_posix(), independent_acceptance=False)
        write(HERE / "tasks.json", ledger)
        print(json.dumps({"logical_task": identity, "dispatch_accepted": False, "error": result.get("error"), "failure": result.get("failure"), "evidence": row["dispatch_evidence"]}), flush=True)
        raise RuntimeError("Original-owner dispatch rejected; stop affected operation without route change")
    assert result["model"] == payload["arguments"]["model"]
    known_sessions.add(result["session_id"])
    at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    row.update(agent_kind="agent_bridge", bridge_task_id=result["task_id"], bridge_session_id=result["session_id"], request_id=payload["arguments"]["request_id"], requested_model=payload["arguments"]["model"], accepted_model=result["model"], status="dispatched_execution_unconfirmed_module_candidate_only", producer_status="dispatched", dispatched_at=at, dispatch_evidence=response.relative_to(HERE).as_posix(), active_sessions_preflight=active_path.relative_to(HERE).as_posix(), original_owner_preflight=preflight_path.relative_to(HERE).as_posix(), contract_review=design_path.relative_to(ROOT).as_posix(), current_root_joint=(joint_dir / "review.json").relative_to(ROOT).as_posix(), artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
    ledger["updated_at"] = at
    write(HERE / "tasks.json", ledger)
    print(json.dumps({"logical_task": identity, "task_id": result["task_id"], "session_id": result["session_id"], "dispatched_at": at, "actual_execution_confirmed": False, "independent_acceptance": False, "integrated": False, "evidence": row["dispatch_evidence"]}), flush=True)
