"""Record additional pre-delivery gates without counting them as GLM deliveries."""
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
gate_path = ROOT / "artifacts/coordinator-current-job-cli-window-identity-corrected-r20-probes-20261015/review.json"
gate = read(gate_path)
assert gate["source_unchanged"] and gate["junit"]["tests"] == gate["junit"]["failures"] == "8"
invalid_path = ROOT / "artifacts/coordinator-current-job-cli-window-identity-r20-probes-20261015/review.json"
invalid = read(invalid_path)
invalid.update(failure_classification="six failures retained; two apparent passes were unobservable analysis-entry fixtures, corrected with a separate marker and a real foreign directory", correction_evidence=gate_path.relative_to(ROOT).as_posix(), retained_original_counts=True)
write(invalid_path, invalid)
path = HERE / "tasks.json"
ledger = read(path)
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
row.update(title="真实Job owner到CLI持久窗口与身份消费", agent_kind="agent_bridge", accepted_model=row["requested_model"], latest_failed_review=gate_path.relative_to(ROOT).as_posix(), pre_delivery_baseline={"junit": gate["junit"], "finished_at": gate["finished_at"], "review": gate_path.relative_to(ROOT).as_posix(), "counts_as_glm_actual_delivery_failure": False}, checked_at=at)
identity = "CURRENT-JOINT-R20"
assert not any(r["id"] == identity for r in ledger["tasks"])
ledger["tasks"].append({"id": identity, "title": "保留R19全集并加入Job到CLI窗口/身份门禁的当前Root联合", "owner": "coordinator", "depends_on": ["CURRENT-JOINT-R19", "U01-JOB-CLI-WINDOW-R20"], "status": "waiting_independent_acceptance_then_intake", "whole_package_complete": False})
rows = {r["id"]: r for r in ledger["tasks"]}
pending = set(rows)
layers = []
done = set()
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready, "unknown dependency or cycle"
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
ledger["updated_at"] = at
write(path, ledger)
path = HERE / "continuation-r6.json"
continuation = read(path)
continuation.update(updated_at=at, current_additional_job_cli_gate={"review": gate_path.relative_to(ROOT).as_posix(), "junit": gate["junit"], "finished_at": gate["finished_at"], "repair_task_id": row["bridge_task_id"], "independent_acceptance": False, "integrated": False}, current_state_note="CURRENT_STATE_R20.md")
write(path, continuation)
note = f"## {at} · R20 additional real consumer gates\n\nCurrent R19 selected union remains2314/six0 (21:27:08), source unchanged. Additional8 real owner/CLI probes failed8/8 at21:32:29: explicit SQL window/resume-cleared window plus six identity boundaries, analysis-entry marker verified. Earlier apparent2 identity passes were unobservable fixtures; original6/8 counts retained and corrected8/8 separately. These are current-root pre-delivery baselines, not new GLM development-delivery failures. Task_492e7a7037 actual tool activity observed; owned adaptation source now changing, no outside-ownership writes, no completed delivery/independent acceptance/intake. CURRENT-JOINT-R20 waits independent acceptance/intake then preserves entire R19 collection plus all new tests and six commands. Current remaining/env scope snapshot CURRENT_STATE_R20.md. DAG {len(rows)} nodes/{len(layers)} layers, no unknown dependencies/cycle; archived S06 untouched.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "nodes": len(rows), "layers": len(layers), "new_delivery_failure_count": 0}), flush=True)
