"""Observe exactly the three current disjoint tasks via the original Bridge owner."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
ledger = json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))
identities = ("VALIDATION-CONTEXT-R18", "U01-STOP-AT-R18", "S07-NATIVE-HOT-R19", "U01-JOB-CLI-WINDOW-R20")
targets = {r["id"]: r for r in ledger["tasks"] if r["id"] in identities and r.get("agent_kind") != "native_subagent"}
assert len(targets) >= 3
requests = {}
stamp = uuid4().hex[:10]
for identity, row in targets.items():
    name = "r19-active-" + identity.lower() + "-" + stamp
    request = {"id": name, "tool": "check_task", "arguments": {"task_id": row["bridge_task_id"]}}
    (route / "bridge-queue" / ("080-" + name + ".request.json")).write_text(json.dumps(request) + "\n", encoding="utf-8", newline="\n")
    requests[identity] = route / ("bridge-response-" + name + ".json")
until = time.monotonic() + 40
while not all(p.exists() for p in requests.values()) and time.monotonic() < until:
    time.sleep(.25)
observations = {}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for identity, path in requests.items():
    if not path.exists():
        print(json.dumps({"id": identity, "pending_response": str(path)}), flush=True)
        continue
    raw = json.loads(path.read_text(encoding="utf-8"))
    safe = {k: raw.get(k) for k in ("task_id", "session_id", "status", "model", "observed_model", "started_at", "finished_at", "failure", "warnings")}
    safe["tool_activity_types"] = [s.split(":", 1)[0] for s in raw.get("recent_activity", []) if isinstance(s, str) and s.startswith("tool_call")]
    safe["receipt"] = path.relative_to(HERE).as_posix()
    observations[identity] = safe
    print(json.dumps({"id": identity, "at": at, **safe}, ensure_ascii=False), flush=True)
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
for row in ledger["tasks"]:
    if row["id"] not in observations:
        continue
    safe = observations[row["id"]]
    assert row["bridge_task_id"] == safe["task_id"]
    row.update(producer_status=safe["status"], actual_execution_at=safe["started_at"], observed_model=safe["observed_model"], execution_evidence=safe["receipt"], checked_at=at)
    if row.get("independent_acceptance") or row.get("integrated"):
        row["worker_finished_at"] = safe["finished_at"]
    elif safe["status"] == "running" and safe["tool_activity_types"]:
        row["status"] = "actual_worker_tool_execution_independent_acceptance_pending"
        row["worker_finished_at"] = None
    elif safe["status"] == "completed":
        row.update(status="producer_completed_result_and_independent_review_pending", worker_finished_at=safe["finished_at"])
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
continuation_path = HERE / "continuation-r6.json"
continuation = json.loads(continuation_path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, active_tasks=observations)
continuation_path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
(HERE / "followups-r12" / ("active-observation-r19-" + stamp + ".json")).write_text(json.dumps({"at": at, "tasks": observations}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
