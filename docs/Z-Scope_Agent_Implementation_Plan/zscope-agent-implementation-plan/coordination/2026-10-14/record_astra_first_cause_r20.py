"""Record an actually started native Astra task and preserve the Root failure."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
row = rows["U01-FIRST-CAUSE-R20"]
assert row["status"] == "prepared_not_dispatched"
gate_path = ROOT / "artifacts/coordinator-current-first-cause-r20-probes-20261015/review.json"
gate = json.loads(gate_path.read_text(encoding="utf-8"))
assert gate["source_unchanged"] and gate["probe_unchanged"] and gate["junit"]["tests"] == gate["junit"]["failures"] == "2"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row.update(agent_task_id="/root/astra_first_cause_r20", status="actual_execution_observed_independent_acceptance_pending", actual_execution_at="2026-10-15T21:48:17+08:00", execution_evidence="Native collaboration message from /root/astra_first_cause_r20: actual start, source diagnosis and before-probe execution", producer_status="running", artifact_available=False, latest_failed_review=gate_path.relative_to(ROOT).as_posix(), checked_at=at)
pending = set(rows)
done = set()
layers = []
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
ledger["topological_layers"] = layers
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, native_active_first_cause={"agent_task_id": row["agent_task_id"], "started_at": row["actual_execution_at"], "workspace": row["workspace"], "requested_model": row["requested_model"], "reasoning_effort": "xhigh", "independent_acceptance": False, "integrated": False}, current_additional_first_cause_gate={"review": gate_path.relative_to(ROOT).as_posix(), "junit": gate["junit"], "finished_at": gate["finished_at"]})
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R20 disjoint first-cause concurrency task started\n\nNative Astra /root/astra_first_cause_r20 (gpt-6-astra/xhigh) actual start21:48:17, exact R19 Root1041-input isolation astra-first-cause-r20; owns only common/cancellation.py and newtests/test_cancellation_first_cause.py. GLM task_492e7a7037 keeps CLI/execution_profile/newJob tests; no overlap/Root writes. Routing uses explicit user complex-task allowance, not delivery-counter reset or platform bypass. Root unchanged first-observation probes2/2failed at21:48:30, artifacts/coordinator-current-first-cause-r20-probes-20261015/review.json. Prior selected2314/six0 does not cover this deterministic cancellation ordering obligation. Both new tasks have no final independent acceptance/intake; accepted parent3 slices retained. Extra Job/identity Root8 failures and producer SQL2 failures remain separate. DAG {len(rows)} nodes/{len(layers)} layers validated.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task": row["agent_task_id"], "nodes": len(rows), "layers": len(layers)}), flush=True)
