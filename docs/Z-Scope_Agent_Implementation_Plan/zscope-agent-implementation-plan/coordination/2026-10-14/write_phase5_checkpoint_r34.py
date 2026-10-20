"""Record green bounded core intake separately from unresolved job/native joint gates."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") or Path.cwd().resolve() != ROOT:
    raise RuntimeError("Checkpoint metadata requires the fixed Linux root and unoptimized Python")
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/phase5-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
intake_path = ROOT / "artifacts/stage-core-intake-r34-20261017/receipt.json"
intake = read(intake_path)
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert intake["stage_intake"] and intake["bounded_independent_acceptance_passed"]
assert len(intake["paths"]) == 14 and len(intake["complete_inputs_after"]) == 1082
assert all(sha(stage / p) == v for p, v in intake["complete_inputs_after"].items())
assert len(intake["root_inputs"]) == 1065 and all(sha(ROOT / p) == v for p, v in intake["root_inputs"].items())
independent_path = ROOT / "artifacts/coordinator-shared-style-r34-20261017/independent/review.json"
independent = read(independent_path)
assert independent["bounded_combined_repair_independent_and_full_quality_passed"]
assert independent["junit"] == dict(tests=150, failures=0, errors=0, skipped=0)
assert all(v["returncode"] == 0 for v in independent["commands"]) and all(independent["gates"].values())
old_tool = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
assert sha(old_tool) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
refs = [intake_path, independent_path, ROOT / "artifacts/coordinator-shared-style-source-review-r34-20261017/review.json", ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/core-intake-helper-review.json", ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/native-plan-v2-review.json", ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/native-lookup-contract-requirements.json", ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/ownership-extension-native.json", ROOT / "artifacts/checkpoint-test-contract-r34-20261017/receipt.json", ROOT / "artifacts/checkpoint-contract-source-review-r34-20261017/candidate-review.json", ROOT / "artifacts/checkpoint-contract-source-review-r34-20261017/launcher-review.json", ROOT / "artifacts/coordinator-checkpoint-contract-r34-20261017/independent/preflight.json", ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/bridge-readonly-original-tasks-r34-130842.json"]
checkpoint = dict(actual_task="/root", checked_at=when, core_independent_ended_at=independent["finished_at"], core_selected_tests=150, core_tests_failed=0, core_tests_errors=0, core_tests_skipped=0, core_isolated_quality_commands_returncodes=[0] * 7, core_actual_source_configuration_root_reference_native_host_guards=True, core_stage_integrated_at=intake["integrated_at"], core_stage_integrated_paths=14, current_stage_inputs=1082, root1065_unchanged=True, root_intake=False, stage_full_joint_passed=False, new_root_joint_passed=False, stage_slice_complete_is_not_whole_work_package=True, checkpoint_candidate_actual_task="/root/stage_currentness_repair_r33", checkpoint_candidate_delivered=True, checkpoint_candidate_source_review_passed=True, checkpoint_coordinator_actual_task="/root", checkpoint_coordinator_independent10_running=True, checkpoint_stage_intake=False, job_repair_actual_task="/root/stage_cost_repair_r33", job_repair_native_plan_source_review_passed=True, job_repair_native_product_implementation_authorized=True, job_repair_native_build_execution_confirmed=False, job_repair_native_tests_execution_confirmed=False, job_repair_delivery=False, job_repair_independent_acceptance=False, original_native_tool_readonly_sha256=sha(old_tool), new_tool_requires_separate_prefix_real_build_and_current_validation=True, cost_declared_broader308_regression_pending=True, cost_owned_slice_bounded_independent_and_stage_intake=True, cost_cumulative_failed_deliveries_preserved=1, s01_historical_failed_deliveries_preserved=3, new_job_failed_deliveries=0, public_old_bridge_tasks_still_unknown_at="2026-10-17T13:08:42+08:00", no_bridge_restart=True, no_archived_s06_r02=True, native_regression_inventory_actual_task="/root/stage_currentness_repair_r33", native_regression_inventory_is_readonly=True, formal_joint_additional_semantic_model_input13_required=True, whole_package_complete=False, real_project_effect_accepted=False, formal_or_portable_acceptance=False, reference_sha256={str(p.relative_to(ROOT)): sha(p) for p in refs})
assert not OUT.exists()
OUT.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
tasks = read(HERE / "tasks.json")
records = tasks["tasks"]
for task in records:
    ident = task.get("id")
    if ident in {"STAGE-CURRENTNESS-REPAIR-R33", "COORD-SESSION-HANDOFF-R33", "COORD-SHARED-STYLE-RETRY-R34"}:
        task.update(status="bounded_independent150_and_seven_quality_commands_passed_stage_intaken_joint_pending", artifact_delivered=True, bounded_independent_acceptance=True, stage_intake=True, integrated=True, stage_intake_at=intake["integrated_at"], stage_intake_receipt=str(intake_path.relative_to(ROOT)), root_intake=False, joint_validation_passed=False, latest_phase5_checkpoint=str(OUT.relative_to(ROOT)))
        if ident == "COORD-SHARED-STYLE-RETRY-R34":
            task.update(execution_confirmed=True, independent_acceptance=True, independent_receipt=str(independent_path.relative_to(ROOT)))
    elif ident == "STAGE-COST-REPAIR-R33":
        task.update(status="owned_cost_slice_independent150_passed_stage_intaken_declared_broader_regression_pending_shared_job_successor", bounded_independent_acceptance=True, independent_acceptance=False, stage_intake=True, integrated=True, stage_intake_at=intake["integrated_at"], stage_intake_receipt=str(intake_path.relative_to(ROOT)), actual_failed_deliveries=1, cumulative_returned_candidates_not_fully_accepted=1, root_intake=False, joint_validation_passed=False, latest_phase5_checkpoint=str(OUT.relative_to(ROOT)))
    elif ident == "CHECKPOINT-TEST-CONTRACT-R34":
        task.update(status="artifact_candidate_and_launcher_source_passed_coordinator_independent10_running", artifact_delivered=True, candidate_source_review_passed=True, candidate_agent_test_execution_count=0, coordinator_actual_test_task="/root", coordinator_verification_running=True, stage_intake=False, integrated=False, root_intake=False, joint_validation_passed=False)
    elif ident == "JOB-RUNTIME-FOOTPRINT-REPAIR-R34":
        task.update(status="native_plan_v2_source_passed_isolated_implementation_authorized_tests_and_build_freeze_pending", native_plan_source_review_passed=True, new_native_lookup_receipt_required=True, native_build_execution_confirmed=False, test_execution_confirmed=False, ownership_extension=str((ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/ownership-extension-native.json").relative_to(ROOT)), stage_intake=False, root_intake=False, integrated=False, joint_validation_passed=False, actual_failed_deliveries=0)
if not any(t.get("id") == "NATIVE-REGRESSION-INVENTORY-R34" for t in records):
    records.append(dict(id="NATIVE-REGRESSION-INVENTORY-R34", actual_task_id="/root/stage_currentness_repair_r33", transport="native_collaboration_followup", bridge_task_id=None, scope="readonly source and real XML inventory for final native joint", status="readonly_inventory_running_actual_missing13_cases_found", artifact_workspace="artifacts/native-regression-inventory-r34-20261017", dispatched=True, readonly_work_started=True, test_execution_confirmed=False, artifact_delivered=False, independent_acceptance=False, stage_intake=False, root_intake=False, integrated=False, joint_validation_passed=False, actual_failed_deliveries=0, checked_at=when))
tasks.update(updated_at=when, latest_phase5_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / "tasks.json").write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
paragraph = f"\n\n---\n\n### {when} · 核心150与七质量通过，14路径已接入Stage\n\n协调者/root的全新组合于{independent['finished_at']}结束：150/0F/E/skip，compileall、normal/fresh完整mypy、scripts/mypy、Black12、web-assets及pytest共七命令全0；全部1082实际输入/config/Root1065/refs/native-host/五原XML Counter守卫通过。14路径已于{intake['integrated_at']}有界接入Stage，1078→1082，Root无产品导入。证据 {intake_path.relative_to(ROOT).as_posix()}、{independent_path.relative_to(ROOT).as_posix()}。Stage完整联合、Root新联合、整个工作包均未通过。\n\n原两个Bridge任务13:08:42+08仍public unknown；不重启、不恢复S06-R02。新job修复实际/root/stage_cost_repair_r33：native PLAN-v2已独审，按明确11路径ownership实施；新ordinary include lookup要真实重编译至独立prefix，旧d39工具只读。新工具/新产品尚无编译测试或交付证据，旧150不替代新tool验收。checkpoint候选实际/root/stage_currentness_repair_r33已artifact交付和源审，协调者10原case独验正在新目录执行，尚未Stage接入。只读native inventory已发现formal joint须补semantic_model_input原13case，不降低旧Counter门禁。成本扩大308回归依赖未闭合，历史失败1和S01三不清不增；真实项目/实际LLM效果/formal/portable另列未验。\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R33.md"):
    p = HERE / name
    p.write_text(p.read_text(encoding="utf-8").rstrip() + paragraph, encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(latest_phase5_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when, current_stage_inputs=1082, current_stage_joint_running=False, current_stage_joint_validation_passed=False, next_root_intake_performed=False, current_shared_blockers=["new native ordinary lookup receipt and exact job output filter implementation/build/independent validation pending", "checkpoint test contract independent10 running", "final Stage current-tool guarded joint and fresh Root intake/joint pending"])
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=when, core150_and_quality_passed=True, stage14_intaken=True, stage1082=True, root1065_unchanged=True, joint_passed=False)))
