"""Persist accepted checkpoint test and actual LLVM readiness without claiming the pending joint."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") or Path.cwd().resolve() != ROOT:
    raise RuntimeError("Metadata checkpoint requires the fixed Linux root and unoptimized Python")
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/phase6-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
intake_path = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
intake = read(intake_path)
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert intake["stage_intake"] and intake["checkpoint_contract_independent10_and_target_black_passed"]
assert len(intake["complete_inputs_after"]) == 1082 and all(sha(stage / p) == v for p, v in intake["complete_inputs_after"].items())
assert len(intake["root_inputs"]) == 1065 and all(sha(ROOT / p) == v for p, v in intake["root_inputs"].items())
checkpoint_review = ROOT / "artifacts/coordinator-checkpoint-contract-r34-20261017/independent/review.json"
llvm_review = ROOT / "artifacts/coordinator-real-llvm-case-r34-20261017/review.json"
assert read(checkpoint_review)["bounded_checkpoint_contract_test_independent_passed"]
assert read(llvm_review)["bounded_real_llvm_svf_readiness_case_passed"]
inventory_path = ROOT / "artifacts/native-regression-inventory-r34-20261017/receipt-final-v2.json"
inventory = read(inventory_path)
assert sha(inventory_path) == "34a4d4d2f95bc93d282b42b5c158c0636ff453c2867a9944cbcdd980c5572456"
inventory_dir = inventory_path.parent
assert all(sha(inventory_dir / p) == v for p, v in inventory["artifacts_sha256_excluding_this_receipt_and_interpreter_cache"].items())
assert inventory["original_full_source_guards_exact"]
refs = [intake_path, checkpoint_review, llvm_review, inventory_path, inventory_dir / "recommendations.json", ROOT / "artifacts/coordinator-joint-llvm-preflight-r34-20261017/receipt.json", ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/checkpoint-readonly-override/receipt.json", ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/format-v2-review.json"]
checkpoint = dict(actual_task="/root", checked_at=when, current_stage_inputs=1082, checkpoint_test_independent_ended_at=read(checkpoint_review)["finished_at"], checkpoint_original10_passed=True, checkpoint_target_black_passed=True, checkpoint_all_guards_passed=True, checkpoint_stage_integrated_at=intake["integrated_at"], checkpoint_paths_integrated=1, core150_and_seven_quality_passed=True, core14_stage_integrated=True, root1065_unchanged=True, root_intake=False, stage_full_joint_passed=False, new_root_joint_passed=False, llvm_svf_environment_preflight_passed=True, actual_bitcode_svf_readiness_single_case=dict(ended_at=read(llvm_review)["finished_at"], tests=1, failures=0, errors=0, skipped=0), full_indexing_pipeline_file_passed=False, new_native_tool_built=False, new_native_tool_validated=False, job_repair_product_edits_confirmed=False, job_format_only34_actual_black_passed=True, job_format_only_pytest_execution_count=0, job_readonly_checkpoint_override_completed=True, job_new_EOF_coverage_pending_source_and_actual39_counter=True, native_inventory_metadata_v2_validated=True, inventory_initial_late_document_mismatch_preserved=True, final_joint_required_old_case_union=3829, final_joint_missing_old_files=4, final_joint_missing_old_identities=54, final_joint_additional_files_recommended=6, final_joint_actual_case_count=None, cost_failed_deliveries_preserved=1, s01_failed_deliveries_preserved=3, whole_package_complete=False, real_project_effect_accepted=False, formal_or_portable_acceptance=False, reference_sha256={str(p.relative_to(ROOT)): sha(p) for p in refs})
assert not OUT.exists()
OUT.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
tasks = read(HERE / "tasks.json")
for task in tasks["tasks"]:
    if task.get("id") == "CHECKPOINT-TEST-CONTRACT-R34":
        task.update(status="coordinator_independent_original10_and_black_passed_stage_intaken_joint_pending", candidate_agent_test_execution_count=0, coordinator_actual_test_task="/root", coordinator_verification_running=False, coordinator_independent_acceptance=True, independent_acceptance=True, stage_intake=True, integrated=True, stage_intake_at=intake["integrated_at"], stage_intake_receipt=str(intake_path.relative_to(ROOT)), root_intake=False, joint_validation_passed=False)
    elif task.get("id") == "NATIVE-REGRESSION-INVENTORY-R34":
        task.update(status="readonly_inventory_delivered_v2_metadata_validated_six_files_recommended", artifact_delivered=True, metadata_independent_review=True, independent_acceptance=False, final_receipt=str(inventory_path.relative_to(ROOT)), test_execution_confirmed=False, actual_test_count=0, actual_build_count=0, stage_intake=False, root_intake=False, integrated=False, joint_validation_passed=False)
    elif task.get("id") == "JOB-RUNTIME-FOOTPRINT-REPAIR-R34":
        task.update(status="format_only34_passed_readonly_dependency_intaken_EOF38_and_actual39_counter_freeze_pending", actual_formatting_executed=True, formatting_actual_test_execution_count=0, product_edits_confirmed=False, native_build_execution_confirmed=False, test_execution_confirmed=False, readonly_shared_test_override=str((ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/checkpoint-readonly-override/receipt.json").relative_to(ROOT)))
tasks.update(updated_at=when, latest_phase6_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / "tasks.json").write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
paragraph = f"\n\n---\n\n### {when} · checkpoint原10独验并Stage接入，LLVM真实就绪单例通过\n\n协调者/root于{read(checkpoint_review)['finished_at']}完成同名原10case独验：10/0F/E/skip、Black0，格式整AST/完整1082/config/Root1065/refs/host/原Counter真。仅tests/test_scan_checkpoint_resume.py于{intake['integrated_at']}接入Stage，仍1082；产品与其他文件未变。旧整体checkpoint篡改1F/rc1保留，现新断言明确真实SQL/codec/当前scope和一次freshvalidation，不把整体旧JSON作授权。Root无导入、Stage与Root完整新联合仍未通过。\n\nLLVM/SVF实际Linux PATH/版本/ldd预检通过，13:31:59+08真实bitcode/SVF单例1/0F/E/skip，验证编译/热复用/头变更失效/两solver执行；这是就绪探针，非test_indexing_pipeline全文件或formal验收。只读inventory最终v2收据已独立核15artifact，原v1两文档晚写mismatch保留；3829旧身份并集/54漏选/6建议文件是规划计数，非已通过计数。\n\n新job任务实际/root/stage_cost_repair_r33已仅Black原34新测试，实际pytest计数0；coor在idle复制已验checkpoint只读依赖并保留原baseline，新增并发与alias反例、实际39Counter、正式red及真实native重建均待后续。新native产品尚未改动/构建，不以旧150绿替代新tool验证。成本历史失败1/S01三保留；旧Bridge public访问仍外部等待，无服务重启/S06-R02恢复。证据 {OUT.relative_to(ROOT).as_posix()}。\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R33.md"):
    p = HERE / name
    p.write_text(p.read_text(encoding="utf-8").rstrip() + paragraph, encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(latest_phase6_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when, current_stage_inputs=1082, current_stage_joint_running=False, current_stage_joint_validation_passed=False, next_root_intake_performed=False, current_shared_blockers=["new ordinary native lookup receipt and exact runtime output filter need fixed regressions, implementation, separate-prefix rebuild and independent acceptance", "final current-tool Stage joint including original 3829 identities and additional tests pending", "Root intake and fresh Root current-version joint pending"])
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=when, checkpoint10_stage_intaken=True, llvm_real_case_passed=True, current_stage1082=True, root_unchanged=True, full_joint_passed=False)))
