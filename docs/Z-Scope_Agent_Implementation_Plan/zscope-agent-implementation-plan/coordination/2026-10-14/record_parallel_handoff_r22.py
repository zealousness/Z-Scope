"""Capture current tested Root separately from three running next-stage tasks."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
def read(p):
    return json.loads(p.read_text(encoding="utf-8"))
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
joint = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016"
review = read(joint / "review.json")
source = read(joint / "source-evidence.json")
assert review["all_current_selected_validation_passed"] and review["commands_passed"] == 6
assert all(sha(ROOT / p) == h for p, h in source["after"].items())
native_sha = sha(Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"))
assert native_sha == source["native_after"]
dep = read(HERE / "followups-r12/astra-stop-coverage-ux-r21-dependencies.json")
ui_branch = ROOT / ".coordination/20261014/workspaces/astra-stop-coverage-ux-r21"
assert all(sha(ui_branch / r["path"]) == r["sha256"] for r in dep["files"])
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
identities = ("S01-INSTANCE-MODELING-DESIGN-R21", "S08-PARTIAL-RECOVERY-DESIGN-R21", "ASTRA-STOP-COVERAGE-UX-R21")
active = []
for identity in identities:
    row = rows[identity]
    active.append({"logical_task": identity, "task_id": row.get("bridge_task_id", row.get("agent_task_id")), "session_id": row.get("bridge_session_id"), "status": row["status"], "producer_status": row["producer_status"], "worker_process_started_at": row.get("worker_process_started_at"), "actual_tool_execution_observed_at": row.get("actual_tool_execution_observed_at"), "actual_execution_at": row.get("actual_execution_at"), "current_revision_artifact_available": row["artifact_available"], "original_design_task_id": row.get("original_design_task_id"), "independent_acceptance": row["independent_acceptance"], "integrated": row["integrated"], "joint_verification": row["joint_verification"], "evidence": row.get("execution_evidence", row.get("dispatch_evidence"))})
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
out = ROOT / "artifacts/coordinator-parallel-handoff-r22-20261016"
out.mkdir(exist_ok=False)
proof = {"captured_at": at, "current_root_joint": (joint / "review.json").relative_to(ROOT).as_posix(), "joint_finished_at": review["finished_at"], "current_selected_passed": review["passed"], "test_files": review["pytest_file_count"], "commands_passed": 6, "root_source_inputs": len(source["after"]), "root_current_bytes_match_tested_after": True, "native_current_sha256": native_sha, "root_product_changed_after_joint": False, "next_stage_tasks": active, "coordinator_projection_dependency": dep, "whole_packages_complete": False, "full_repository_suite_run": False, "real_project_or_real_model_acceptance": False, "formal_or_portable_acceptance": False, "clock_problem_resolved": False, "blocks": ["Two readonly designs need same-logical-task revision and independent source review before implementation ownership partition", "Astra UI needs final-byte developer delivery, coordinator independent acceptance, shared resource-lock update, intake and next current-version joint regression"], "archived_s06_queried_or_resumed": False, "new_bridge_owner_started": False}
write(out / "review.json", proof)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase="R22 Root selected union still current and passed; next-stage Astra UI developer verification plus two same-session readonly design revisions", active_next_stage_tasks=active, latest_parallel_snapshot=(out / "review.json").relative_to(ROOT).as_posix(), next_root_intake_performed=False, whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"## {at} · R22 current Root preserved; next-stage work running\n\nR22 {review['passed']}/169 files, pytest plus five quality commands0, finished{review['finished_at']}; live{len(source['after'])} Root hashes/native still match and no post-joint product intake. Evidence {(out / 'review.json').relative_to(ROOT).as_posix()}. Astra /root/astra_instance_ui_r18 actual UI start01:30:05.8752216, eight exclusive paths, four coordinator dependencies frozen (117/four0 plus final independent static review, not Root-intaken). Original readonly GLM designs task_ba5695e560/task_32a0c9ef87 completed with artifacts but changes requested; originals frozen. Same-session revisions task_4d76d1be39/task_6416e33454 dispatched01:34:25/01:34:29, worker processes observed, actual tool activity remains separately recorded. No independent design/implementation acceptance, new UI intake or new joint claim. Design corrections concern unknown inferred build identity, citations, fairness bounds and timestamp provenance; not product-development failure counts. UI final-byte self/independent/resource-lock/intake/next-joint gates remain. Kimi paused under DISPATCH_POLICY, owner unchanged, archived S06 untouched, whole packages/real-project/formal/portable remain open.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md", "CURRENT_STATE_R22.md"):
    p = HERE / name
    p.write_text(note + p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "root_current_selected_passed": review["passed"], "root_inputs_unchanged": len(source["after"]), "active": active, "evidence": (out / "review.json").relative_to(ROOT).as_posix()}), flush=True)
