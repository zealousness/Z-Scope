"""Record public Bridge checks and isolated continuations without claiming joint acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
OUT = BASE / "phase7-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use unoptimized Linux Python")
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
intake = read(ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json")
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
work = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34"
source, root_inputs = intake["complete_inputs_after"], intake["root_inputs"]
assert len(source) == 1082 and all(sha(stage / p) == v for p, v in source.items())
assert len(root_inputs) == 1065 and all(sha(ROOT / p) == v for p, v in root_inputs.items())
worker_differences = [p for p, v in source.items() if not (work / p).is_file() or sha(work / p) != v]
evidence = {
    "bridge": BASE / "bridge-readonly-r34-1339.json",
    "stage_root": BASE / "stage-root-readonly-r34-1342.json",
    "v4_static": ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/format-v4-review.json",
    "pending_plan": ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/pending-writer-plan-review.json",
    "pending_ownership": ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/ownership-extension-pending-writer.json",
}
assert read(evidence["stage_root"])["passed"]
assert sha(evidence["v4_static"]) == "f9dc4b23ca6abfa25886373b5072825d7646b7afa1c6908192effaef6f1f3248"
assert sha(evidence["pending_plan"]) == "5ba61ee37ddd086a6b2f014bebff05774acb04d0de16eca229cdcd9bd8337261"
assert sha(evidence["pending_ownership"]) == "2b32a463c266257d587e032b812173df937957eec0ee3d26c3ce5d7c014d2c9e"
checkpoint = dict(
    actual_task="/root", checked_at=when, stage_inputs=1082, root_inputs=1065,
    stage_and_root_floors_exact=True, original_bridge_tasks_publicly_unknown=True,
    current_bridge_session_dead_turns_zero=True, bridge_restarted=False,
    old_s06_r02_touched=False, duplicate_dispatch=False,
    job_actual_task="/root/stage_cost_repair_r33", job_logical_task="JOB-RUNTIME-FOOTPRINT-REPAIR-R34",
    job_worker_existing_input_differences_from_stage=worker_differences,
    job_native_build_verified=False, job_independent_acceptance=False,
    pending_writer_static_plan_review_passed=True, pending_writer_behavior_acceptance=False,
    concurrency_first_wait_gate_needs_actual_protocol_alignment=True,
    joint_launcher_draft_task="/root/stage_currentness_repair_r33",
    joint_launcher_logical_task="STAGE-JOINT-LAUNCHER-DRAFT-R35",
    joint_launcher_execution_authorized_now=False,
    cost_failed_deliveries_preserved=1, s01_failed_deliveries_preserved=3,
    stage_full_joint_passed=False, root_intake=False, new_root_joint_passed=False,
    full_packages_complete=False, real_project_effect_acceptance=False,
    references_sha256={str(p.relative_to(ROOT)): sha(p) for p in evidence.values()},
)
if OUT.exists():
    raise RuntimeError("Preserve the existing checkpoint")
OUT.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
tasks = read(HERE / "tasks.json")
for task in tasks["tasks"]:
    if task.get("id") == "JOB-RUNTIME-FOOTPRINT-REPAIR-R34":
        task.update(status="isolated_test_and_pending_writer_protocol_finalization_native_rebuild_and_independent_pending", actual_task="/root/stage_cost_repair_r33", bridge_task_id=None, ownership_extension=str(evidence["pending_ownership"].relative_to(ROOT)), pending_writer_static_review=str(evidence["pending_plan"].relative_to(ROOT)), product_edits_confirmed=bool(worker_differences), independent_acceptance=False, integrated=False, stage_intake=False, root_intake=False, joint_validation_passed=False)
if not any(t.get("id") == "STAGE-JOINT-LAUNCHER-DRAFT-R35" for t in tasks["tasks"]):
    tasks["tasks"].append(dict(id="STAGE-JOINT-LAUNCHER-DRAFT-R35", owner="Codex native 6.1-sol/xhigh", actual_task="/root/stage_currentness_repair_r33", bridge_task_id=None, status="artifact_only_candidate_preparation", write_paths=["artifacts/stage-joint-launcher-draft-r35-20261017/**"], execution_confirmed=False, test_execution_confirmed=False, independent_acceptance=False, integrated=False, depends_on=["NATIVE-REGRESSION-INVENTORY-R34"], execution_depends_on=["JOB-RUNTIME-FOOTPRINT-REPAIR-R34", "new native build and independent acceptance", "final Stage intake"]))
tasks.update(updated_at=when, latest_phase7_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / "tasks.json").write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
paragraph = f"\n\n---\n\n### {when} · 公开Bridge复查与隔离续任务\n\n13:39公开只读复查两个原任务仍unknown，当前scope仅dead/turns0旧ZCode会话；已有JOB-RUNTIME-FOOTPRINT-REPAIR-R34沿用实际/root/stage_cost_repair_r33继续，不重复派单、不重启、不触碰已归档S06-R02。13:40:22只读核对Stage1082/Root1065全部精确无变化；原bounded150与七质量、checkpoint10及各Stage收据保留，完整Stage/Root新联合仍未通过。\n\npending writer仅隔离所有权扩展已源审，实际Store→namespace锁序和SQL事务外event等约束固定；源审不授行为通过。并发EOF测试首等待点须与真实SQL/namespace协议一致，旧format/静态收据保留；新native构建/实际green/协调者独验仍待证据。另由实际/root/stage_currentness_repair_r33并行准备artifact-only R35联合启动器候选，不运行测试，最终依赖新tool SHA与真实build/job独验及Stage接入，旧198集合、全部旧Counter、UI/LLVM环境与零skip标准不变。成本历史失败1/S01三不清不增；无完整工作包、真实项目或formal结论。证据 {OUT.relative_to(ROOT).as_posix()}。\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R33.md"):
    path = HERE / name
    path.write_text(path.read_text(encoding="utf-8").rstrip() + paragraph, encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(latest_phase7_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when, current_stage_inputs=1082, current_stage_joint_running=False, current_stage_joint_validation_passed=False, next_root_intake_performed=False)
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=when, stage1082_root1065_exact=True, worker_changed_existing_inputs=len(worker_differences), full_joint_passed=False)))
