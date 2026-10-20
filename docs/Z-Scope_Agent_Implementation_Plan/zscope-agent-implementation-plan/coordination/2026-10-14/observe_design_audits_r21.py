"""Read only the two newly dispatched design tasks through the existing owner."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
identities = {"S01-INSTANCE-MODELING-DESIGN-R21", "S08-PARTIAL-RECOVERY-DESIGN-R21"}
ledger = json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))
targets = {r["id"]: r for r in ledger["tasks"] if r["id"] in identities}
assert set(targets) == identities, "Both design tasks must already have real dispatch receipts"
requests = {}
stamp = uuid4().hex[:12]
for identity, row in sorted(targets.items()):
    assert row["agent_kind"] == "agent_bridge" and row["owns"] == []
    name = "r21-design-status-" + identity.lower() + "-" + stamp
    request = {"id": name, "tool": "check_task", "arguments": {"task_id": row["bridge_task_id"]}}
    target = route / "bridge-queue" / ("080-" + name + ".request.json")
    response = route / ("bridge-response-" + name + ".json")
    assert not target.exists() and not response.exists()
    target.write_text(json.dumps(request) + "\n", encoding="utf-8", newline="\n")
    requests[identity] = response
until = time.monotonic() + 40
while not all(p.exists() for p in requests.values()) and time.monotonic() < until:
    time.sleep(.25)
assert all(p.exists() for p in requests.values()), "Existing owner response pending; do not restart or redispatch"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
observations = {}
for identity, path in requests.items():
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw.get("task_id") == targets[identity]["bridge_task_id"]
    tool_count = sum(isinstance(v, str) and v.startswith("tool_call") for v in raw.get("recent_activity", []))
    branch = ROOT / ".coordination/20261014/workspaces" / targets[identity]["workspace"]
    artifact = "instance-modeling-design-r21" if identity.startswith("S01") else "partial-recovery-design-r21"
    revision = targets[identity].get("design_revision", 0)
    artifact_dir = branch / "artifacts" / artifact
    delivery_path = branch / "DELIVERY.md"
    if revision:
        artifact_dir /= f"revision-{revision}"
        delivery_path = artifact_dir / "DELIVERY.md"
    safe = {k: raw.get(k) for k in ("task_id", "session_id", "status", "model", "observed_model", "started_at", "finished_at")}
    safe.update(recent_tool_activity_count=tool_count, receipt=path.relative_to(HERE).as_posix(), design_revision=revision, delivery_file_present=delivery_path.is_file(), audit_file_present=(artifact_dir / "audit.json").is_file(), independent_acceptance=False, integrated=False, joint_verification=False)
    observations[identity] = safe
    print(json.dumps({"logical_task": identity, "observed_at": at, **safe}), flush=True)
ledger = json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))
for row in ledger["tasks"]:
    if row["id"] not in observations:
        continue
    safe = observations[row["id"]]
    assert row["bridge_task_id"] == safe["task_id"]
    row.update(producer_status=safe["status"], worker_process_started_at=safe["started_at"], worker_finished_at=safe["finished_at"], observed_model=safe["observed_model"], execution_evidence=safe["receipt"], checked_at=at)
    if not row.get("independent_acceptance"):
        if safe["recent_tool_activity_count"]:
            row.setdefault("actual_tool_execution_observed_at", at)
            row.setdefault("actual_execution_at", safe["started_at"])
        if safe["status"] == "completed":
            row["status"] = "producer_completed_readonly_design_review_pending"
        elif safe["status"] == "failed":
            row["status"] = "producer_failed_classification_pending_no_automatic_retry"
        elif safe["recent_tool_activity_count"] or row.get("actual_tool_execution_observed_at"):
            row["status"] = "readonly_design_actual_tool_execution_review_pending"
        else:
            row["status"] = "dispatched_worker_process_observed_tool_execution_unconfirmed"
ledger["updated_at"] = at
(HERE / "tasks.json").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "followups-r12" / ("design-observation-r21-" + stamp + ".json")
path.write_text(json.dumps({"at": at, "tasks": observations}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
