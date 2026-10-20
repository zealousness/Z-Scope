"""Persist isolated Store delegation and joint-launcher review status."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
OUT = BASE / "phase8-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use unoptimized Linux Python")
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
intake = read(ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json")
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert len(intake["complete_inputs_after"]) == 1082 and all(sha(stage / p) == v for p, v in intake["complete_inputs_after"].items())
assert len(intake["root_inputs"]) == 1065 and all(sha(ROOT / p) == v for p, v in intake["root_inputs"].items())
refs = {
    "artifacts/store-active-transactions-r35-20261017/preparation.json": "39f38fb8e4815fc8dfa055479c43b3715853d84167625a3d3f65628a6b2f639c",
    "artifacts/job-runtime-footprint-source-review-r34-20261017/active-transaction-plan-review-r35.json": "42e5927eb8fc06112c04b66c752d5539a294bfbeee43aaba812c7d6a79578a34",
    "artifacts/job-runtime-footprint-source-review-r34-20261017/active-transaction-physical-identity-constraints-r35.json": "9f0b425c2160cf3b3f2d96fb553ae5f7362c61a4a2cb51e2a399f7b154d859ba",
    "artifacts/stage-joint-launcher-draft-r35-20261017/receipt-final-r35.json": "e8a3a35c17306011ca09ae76d0fb0d21bb473365671db4f711678b1e73691772",
    "artifacts/stage-joint-launcher-source-review-r35-20261017/initial-review.json": "c31715070d4c561b126a070fc558e6bbf893f1762fda8e76212f4fbcb40a7b3b",
    "artifacts/stage-joint-launcher-draft-r35-20261017/revision-3/verify_stage_joint_r35.py": "ec9eb801255e6f3c171be76b4011345c92f25c0f2039e389bbdb22833fb087f1",
}
assert all(sha(ROOT / p) == v for p, v in refs.items())
dispatch_path = ROOT / "artifacts/store-active-transactions-r35-20261017/dispatch.json"
refs[str(dispatch_path.relative_to(ROOT))] = sha(dispatch_path)
checkpoint = dict(actual_task="/root", checked_at=when, stage1082_root1065_exact=True, store_logical_task="STORE-ACTIVE-TRANSACTION-SEAM-R35", store_actual_task="/root/stage_currentness_repair_r33", store_dispatched=True, store_worker_started_confirmed=True, store_test_acceptance=False, store_source_candidate_acceptance=False, store_stage_intake=False, store_failed_deliveries=0, job_actual_task="/root/stage_cost_repair_r33", job_store_write_forbidden=True, job_static_draft_identity_count=53, job_actual_collection_accepted=False, job_native_build_accepted=False, job_independent_acceptance=False, launcher_revision2_artifact_delivered=True, launcher_revision2_source_changes_requested=True, launcher_revision3_candidate_prepared=True, launcher_revision3_review_pending=True, launcher_execution_confirmed=False, stage_full_joint_passed=False, root_intake=False, root_joint_passed=False, cost_historical_failed_deliveries=1, s01_historical_failed_deliveries=3, bridge_restarted=False, archived_s06_r02_touched=False, whole_packages_complete=False, real_project_effect_acceptance=False, reference_sha256=refs)
if OUT.exists():
    raise RuntimeError("Preserve the prior checkpoint")
OUT.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
tasks = read(HERE / "tasks.json")
if not any(t.get("id") == "STORE-ACTIVE-TRANSACTION-SEAM-R35" for t in tasks["tasks"]):
    tasks["tasks"].append(dict(id="STORE-ACTIVE-TRANSACTION-SEAM-R35", owner="Codex native 6.1-sol/xhigh", actual_task="/root/stage_currentness_repair_r33", bridge_task_id=None, status="isolated_test_preparation_running_after_bounded_plan_review", workspace=".coordination/20261014/workspaces/store-active-transactions-r35", write_paths=["zscope/orchestration/jobs/store.py", "tests/test_store_active_transactions_r35.py", "artifacts/store_active_transactions_r35/**"], dispatch_receipt=str(dispatch_path.relative_to(ROOT)), plan_source_review="artifacts/job-runtime-footprint-source-review-r34-20261017/active-transaction-plan-review-r35.json", failed_deliveries=0, test_execution_accepted=False, independent_acceptance=False, integrated=False, stage_intake=False, root_intake=False, joint_validation_passed=False, depends_on=["JOB-RUNTIME-FOOTPRINT-REPAIR-R34 protocol plan"]))
for task in tasks["tasks"]:
    if task.get("id") == "STAGE-JOINT-LAUNCHER-DRAFT-R35":
        task.update(status="revision2_artifact_delivered_source_changes_requested_revision3_fix_pending_review", artifact_delivered=True, candidate_revision3="artifacts/stage-joint-launcher-draft-r35-20261017/revision-3/verify_stage_joint_r35.py", source_review_passed=False, execution_confirmed=False, independent_acceptance=False, integrated=False)
    elif task.get("id") == "JOB-RUNTIME-FOOTPRINT-REPAIR-R34":
        task.update(status="isolated_native_hook_and_EOF_tests_preparation_parallel_Store_seam_dependency", static_draft_test_identity_count=53, actual_collection_accepted=False, store_dependency="STORE-ACTIVE-TRANSACTION-SEAM-R35", store_owned_by_other_agent=True)
tasks.update(updated_at=when, latest_phase8_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / "tasks.json").write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
paragraph = f"\n\n---\n\n### {when} · Store单独隔离派发，联合启动器保留阻断后修订\n\nSTORE-ACTIVE-TRANSACTION-SEAM-R35已派实际/root/stage_currentness_repair_r33，唯一新隔离1082基线，只拥有Store和新增事务测试；源审42e5927e/物理身份约束9f0b425c有界许可仅实现方案，不授行为验收。原Job实际/root/stage_cost_repair_r33禁止Store写，继续native/namespace/Hook及EOF测试，静态拟选53身份，实际collection/红绿/native构建与独验尚待收据。两任务均6.1-sol/xhigh，非Bridge任务无伪造task ID。\n\nR35 joint rev2 artifact已交付，但独审c3171507要求修改有效红门禁；原稿c584和blocked收据保留。协调者新revision3 ec9eb801补真实red失败/零setup error与skip、原SessionJobs失败身份及固定test/XML/Counter/rawreceipt/因果projection绑定，待独审，不执行候选。Stage1082/Root1065仍精确无变化；此前有界接纳不替代新工具与新Store验收。完整Stage联合、Root导入/新联合均未通过；成本历史失败1/S01三保留，不重启Bridge/触碰S06-R02，不宣称整个工作包或真实项目通过。证据 {OUT.relative_to(ROOT).as_posix()}。\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R33.md"):
    p = HERE / name
    p.write_text(p.read_text(encoding="utf-8").rstrip() + paragraph, encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(latest_phase8_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when, current_stage_inputs=1082, current_stage_joint_validation_passed=False, next_root_intake_performed=False)
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=when, stage_root_exact=True, store_dispatched=True, launcher_revision3_pending_review=True, full_joint_passed=False)))
