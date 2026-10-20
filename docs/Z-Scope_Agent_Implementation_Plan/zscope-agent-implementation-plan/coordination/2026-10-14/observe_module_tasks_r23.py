"""Read only the new module tasks via their real accepted IDs."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4
from bridge_queue_publish_r23 import publish_request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

identities = {"S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23"}
ledger = read(HERE / "tasks.json")
targets = {r["id"]: r for r in ledger["tasks"] if r["id"] in identities}
assert set(targets) == identities
stamp = uuid4().hex[:12]
responses = {}
for identity, row in sorted(targets.items()):
    assert row["agent_kind"] == "agent_bridge" and row["bridge_task_id"] and not row["integrated"]
    name = "r23-module-status-" + identity.lower() + "-" + stamp
    request = route / "bridge-queue" / ("080-" + name + ".request.json")
    response = route / ("bridge-response-" + name + ".json")
    assert not request.exists() and not response.exists()
    publish_request(route / "bridge-queue", {"id": name, "tool": "check_task", "arguments": {"task_id": row["bridge_task_id"]}})
    responses[identity] = response
until = time.monotonic() + 40
parsed = {}
while len(parsed) != len(responses) and time.monotonic() < until:
    for identity, path in responses.items():
        if identity not in parsed and path.exists():
            try:
                parsed[identity] = read(path)
            except json.JSONDecodeError:
                pass
    if len(parsed) == len(responses):
        break
    time.sleep(.25)
assert len(parsed) == len(responses), "Original-owner status pending; never redispatch or restart"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
observations = {}
for identity, path in responses.items():
    raw = parsed[identity]
    row = targets[identity]
    assert raw.get("task_id") == row["bridge_task_id"]
    safe = {k: raw.get(k) for k in ("task_id", "session_id", "status", "model", "observed_model", "started_at", "finished_at")}
    count = sum(isinstance(a, str) and a.startswith("tool_call") for a in (raw.get("recent_activity") or []))
    branch = ROOT / ".coordination/20261014/workspaces" / row["workspace"]
    artifact = "instance-semantics-r23" if identity.startswith("S01") else "instance-recovery-r23"
    safe.update(recent_tool_activity_count=count, delivery_present=(branch / "DELIVERY.md").is_file(), review_present=(branch / "artifacts" / artifact / "review.json").is_file(), owned_source_present=[p for p in row["write_paths"] if (branch / p).is_file()], receipt=path.relative_to(HERE).as_posix(), independent_acceptance=False, integrated=False, joint_verification=False)
    observations[identity] = safe
    print(json.dumps({"logical_task": identity, "observed_at": at, **safe}), flush=True)
ledger = read(HERE / "tasks.json")
for row in ledger["tasks"]:
    if row["id"] not in observations:
        continue
    safe = observations[row["id"]]
    assert row["bridge_task_id"] == safe["task_id"]
    row.update(producer_status=safe["status"], worker_process_started_at=safe["started_at"], worker_finished_at=safe["finished_at"], observed_model=safe["observed_model"], execution_evidence=safe["receipt"], checked_at=at, artifact_available=safe["delivery_present"] and safe["review_present"])
    if safe["recent_tool_activity_count"]:
        row.setdefault("actual_tool_execution_observed_at", at)
    if safe["status"] == "completed":
        row["status"] = "producer_completed_module_candidate_independent_acceptance_pending"
    elif safe["status"] == "failed":
        row["status"] = "producer_failed_classification_pending_no_automatic_retry"
    elif safe["recent_tool_activity_count"] or row.get("actual_tool_execution_observed_at"):
        row["status"] = "module_candidate_actual_tool_execution_in_progress"
    else:
        row["status"] = "dispatched_worker_process_observed_tool_execution_unconfirmed"
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
write(HERE / "followups-r12" / ("module-observation-r23-" + stamp + ".json"), {"at": at, "tasks": observations, "archived_session_requested": False, "service_started": False})
