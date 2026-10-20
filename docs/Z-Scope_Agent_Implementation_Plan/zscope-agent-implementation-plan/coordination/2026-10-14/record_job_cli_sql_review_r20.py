"""Retain live frozen diagnostics; no delivery failure count or intake."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
names = ["coordinator-job-cli-live-frozen-r20-probes-20261015", "coordinator-job-cli-authority-live-frozen-r20-probes-20261015"]
reviews = [read(ROOT / "artifacts" / name / "review.json") for name in names]
assert all(r["stable_frozen_inputs"] and r["producer_current_matches_frozen"] for r in reviews)
assert reviews[0]["junit"]["tests"] == "8" and reviews[0]["junit"]["failures"] == "0"
assert reviews[1]["junit"]["tests"] == "4" and reviews[1]["junit"]["failures"] == "2"
path = HERE / "tasks.json"
ledger = read(path)
rows = {r["id"]: r for r in ledger["tasks"]}
rows["U01-JOB-CLI-WINDOW-R20"].update(pending_code_review_gates=[{"review": "artifacts/" + name + "/review.json", "junit": review["junit"], "finished_at": review["finished_at"], "diagnostic_only": True, "counts_as_glm_actual_delivery_failure": False} for name, review in zip(names, reviews)], coordinator_feedback="followups-r12/job-cli-window-r20-coordinator-review.txt", coordinator_feedback_delivery="file provided in owned artifacts; worker acknowledgment not yet observed", checked_at=at)
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
write(path, ledger)
path = HERE / "continuation-r6.json"
continuation = read(path)
continuation.update(updated_at=at, additional_producer_sql_review=rows["U01-JOB-CLI-WINDOW-R20"]["pending_code_review_gates"], current_remaining_snapshot="CURRENT_STATE_R20.md")
write(path, continuation)
note = f"## {at} · R20 frozen producer SQL review remains open\n\nFrozen producer8 window/identity probes passed at21:38:18; diagnostic only. Additional actual service/SQL/fingerprint boundaries4 yielded2 original passes and2 new failures at21:40:44: validated old owner identity consumed a later foreign owner's cleared SQL window, and nonfinite SQL epoch was accepted. Source frozen/stable/current producer matched at collection end. Evidence artifacts/{names[1]}/review.json, readonly probes followups-r12/test_job_cli_window_snapshot_boundary.py. Task_492e7a7037 still has no delivery/independent acceptance/intake; these are not counted as actual GLM delivery failures. Feedback file supplied to owned artifacts, no acknowledgment yet observed. Root remainsR19 selected2314/six0 plus additional8 failed baseline; parent3 accepted slices preserved. DAG {len(rows)} nodes/{len(layers)} layers validated, original Bridge owner/S06 policies unchanged.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "nodes": len(rows), "layers": len(layers), "producer_sql_gate_passed": False}), flush=True)
