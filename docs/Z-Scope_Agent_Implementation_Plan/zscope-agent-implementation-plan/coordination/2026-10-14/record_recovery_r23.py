"""Record actual recovery observations without changing frozen receipts."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def write(p, v):
    p.write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
design_path = ROOT / "artifacts/design-revision-independent-review-r23-20261016/review.json"
design = read(design_path)
assert design["source_integrity_passed"] and not design["source_review_passed"]
for key in ("S01-INSTANCE-MODELING-DESIGN-R21", "S08-PARTIAL-RECOVERY-DESIGN-R21"):
    row = rows[key]
    row.update(status="producer_completed_revision1_frozen_independent_design_changes_requested", artifact_available=True, independent_acceptance=False, integrated=False, joint_verification=False, current_revision_artifacts_frozen=True, design_review_status="changes_requested", design_review_evidence=design_path.relative_to(ROOT).as_posix(), design_review_finished_at=design["finished_at_utc"], checked_at=at)
ui_path = ROOT / "artifacts/coordinator-ui-r23-independent-20261016/review.json"
ui = read(ui_path)
assert ui["independent_acceptance_passed"]
rows["ASTRA-STOP-COVERAGE-UX-R21"].update(status="frozen_delivery_independent_accepted_intake_pending", independent_acceptance=True, integrated=False, joint_verification=False, independent_evidence=ui_path.relative_to(ROOT).as_posix(), independent_finished_at=ui["finished_at"], independent_result=ui["junit"], checked_at=at)
assert "ASTRA-DESIGN-REVISION-REVIEW-R23" not in rows
ledger["tasks"].extend([
    {"id": "ASTRA-DESIGN-REVISION-REVIEW-R23", "actual_task": design["actual_task"], "owner": "Astra", "status": "completed_independent_readonly_review_changes_requested", "artifact_available": True, "source_integrity_passed": True, "source_review_passed": False, "tests_executed": 0, "product_changed": False, "evidence": design_path.relative_to(ROOT).as_posix(), "finished_at": design["finished_at_utc"], "checked_at": at},
    {"id": "ASTRA-DESIGN-CONTRACT-R23", "actual_task": "/root/astra_design_contract_r23", "owner": "Astra", "status": "dispatched_actual_readonly_design_in_progress", "model": "gpt-6-astra", "reasoning_effort": "xhigh", "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "product_changed": False, "artifact_write_paths": ["artifacts/design-contract-r23-20261016/DELIVERY.md", "artifacts/design-contract-r23-20261016/contracts.json"], "depends_on": ["ASTRA-DESIGN-REVISION-REVIEW-R23"], "checked_at": at},
    {"id": "ASTRA-ROOT-LAUNCHER-REVIEW-R23", "actual_task": "/root/astra_design_review_r23", "owner": "Astra", "status": "dispatched_actual_readonly_review_in_progress", "artifact_available": False, "independent_acceptance": False, "integrated": False, "tests_executed": 0, "product_changed": False, "artifact_write_paths": ["artifacts/root-launcher-review-r23-20261016/DELIVERY.md", "artifacts/root-launcher-review-r23-20261016/review.json"], "checked_at": at},
])
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
note = f"## {at} · Restart reconciliation and R23 acceptance\n\nExisting Windows Bridge owner80748/start2026-10-14 16:58:25 remains; active-only original-owner queue query at10:02:32 returned no active sessions. No service start, credential/provider read, WSL process inspection or archived S06-R02 operation. All1056 R22 Root inputs still matched at10:07:23; its2539/six-command receipt remains historical evidence of these bytes. UI actual producer /root/astra_instance_ui_r18 finished01:44:52; independent coordinator acceptance finished {ui['finished_at']}: {ui['junit']['tests']}pass,0fail/error/skip,20files,nine commands0, original13 producer files/JUnit retained. Root intake/joint still pending. Evidence {ui_path.relative_to(ROOT).as_posix()}.\n\nS01 task_4d76d1be39 finished01:41:34 and S08 task_6416e33454 finished01:39:01 are actual completed revision1 deliveries; read-only independent review /root/astra_design_review_r23 finished10:11:25 rejects their implementation contracts (6 distinct blockers), while source SHA integrity passes. No product development failure increment. Evidence {design_path.relative_to(ROOT).as_posix()}. Complex contract correction /root/astra_design_contract_r23 and launcher static review /root/astra_design_review_r23 now run in disjoint artifact-only ownership; no backend implementation dispatched.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md"):
    p = HERE / name
    p.write_text(note + p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "UI_independent_passed": ui["junit"]["tests"], "design_review_passed": False, "root_intaken": False}), flush=True)
