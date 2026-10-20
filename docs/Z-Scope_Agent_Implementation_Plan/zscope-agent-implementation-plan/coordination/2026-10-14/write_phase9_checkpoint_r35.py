"""Record actual native build and causal probes without promoting bounded results."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
OUT = BASE / "phase9-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use unoptimized Linux Python")
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
floor = read(ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json")
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert len(floor["complete_inputs_after"]) == 1082
assert len(floor["root_inputs"]) == 1065
assert all(sha(stage / p) == v for p, v in floor["complete_inputs_after"].items())
assert all(sha(ROOT / p) == v for p, v in floor["root_inputs"].items())
job = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34"
store = ROOT / ".coordination/20261014/workspaces/store-active-transactions-r35/artifacts/store_active_transactions_r35"
build = read(job / "native-build-v4/receipt.json")
assert build["build_started"] and not build["test_started"]
assert all(c["returncode"] == 0 for c in build["commands"])
assert build["evidence_guards_passed"] and all(build["guards"].values())
refs = [
    ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json",
    ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/bridge-readonly-r35-1418.json",
    job / "native-build-v4/receipt.json",
    job / "runner-v5/red-original-v6/receipt.json",
    job / "runner-v5/red-original-v6/results.xml",
    store / "baseline-20261017T060421.791374Z/receipt.json",
    store / "baseline-20261017T060421.791374Z/pytest.xml",
    store / "trace-probe-20261017T061557.779197Z/receipt.json",
    store / "candidate-v3/receipt.json",
    ROOT / "artifacts/store-active-transactions-source-review-r35-20261017/trace-reentry-causal-review-v2.json",
    ROOT / "artifacts/stage-joint-launcher-source-review-r35-20261017/revision-3-review.json",
    ROOT / "artifacts/stage-joint-launcher-install-r35-20261017/receipt.json",
]
checkpoint = dict(
    actual_task="/root", checked_at=when, stage1082_root1065_exact=True,
    public_bridge_original_tasks_still_unknown=True,
    bridge_readonly_receipt=str(refs[1].relative_to(ROOT)),
    no_duplicate_dispatch=True, native_build_actual_returncode=0,
    native_build_finished_at=build["finished_at"], new_native_tool_sha256=build["native_tool_sha256"],
    native_build_evidence_guards_passed=True, new_tool_product_behavior_accepted=False,
    job_red_v6=dict(tests=53, passed=18, failures=35, errors=0, skipped=0,
        accepted=False, reason="Coordinator-authorized full candidate copies changed actual configuration and AGENTS sets during the run; two guards false. Preserve original receipt.",
        additional_fixture_issue="Six cases stop at strict project-header coverage before intended gate; pending narrowly reviewed probe-only filename correction, no added include or weakened config."),
    store_original_red=dict(tests=65, failures=65, errors=0, skipped=0, evidence_guards_passed=True,
        existing_deadlocks=2, missing_feature_cases=63, not_65_product_defects=True),
    store_v2_additional_trace_probe=dict(tests=5, failures=2, passed=3, errors=0, skipped=0,
        evidence_guards_passed=True, actual_transaction_ended_and_rebegun=True,
        candidate_v3_source_review_pending=True, original_65_tests_unchanged=True),
    joint_launcher_revision3_source_review_passed=True, joint_launcher_installed_inert=True,
    joint_launcher_actual_execution=False, readiness_receipt_exists=False,
    store_failed_deliveries=0, job_failed_deliveries=0,
    cost_historical_failed_deliveries=1, s01_historical_failed_deliveries=3,
    new_independent_acceptance=False, new_stage_intake=False, root_intake=False,
    stage_full_joint_passed=False, root_joint_passed=False,
    bridge_restarted=False, archived_s06_r02_touched=False,
    whole_packages_complete=False, real_project_effect_acceptance=False,
    reference_sha256={str(p.relative_to(ROOT)): sha(p) for p in refs},
)
assert not (ROOT / "artifacts/stage-shared-intake-r35-20261017/receipt.json").exists()
if OUT.exists():
    raise RuntimeError("Preserve prior checkpoint")
OUT.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
tasks = read(HERE / "tasks.json")
for task in tasks["tasks"]:
    if task.get("id") == "JOB-RUNTIME-FOOTPRINT-REPAIR-R34":
        task.update(status="actual_native_build_zero_python_wiring_and_valid_red_fixture_correction_running", execution_confirmed=True,
            native_build_execution_confirmed=True, native_build_receipt=str((job / "native-build-v4/receipt.json").relative_to(ROOT)),
            test_execution_confirmed=True, actual_collection_accepted=True, actual_collection_count=53,
            red_v6_accepted=False, red_v6_invalid_guard_count=2,
            product_edits_confirmed=True, product_edits_location="artifact candidate source only; original red tree remains frozen",
            independent_acceptance=False, checked_at=when)
    elif task.get("id") == "STORE-ACTIVE-TRANSACTION-SEAM-R35":
        task.update(status="valid_original_red65_and_trace_reentry2of5_reproduced_candidate_v3_review_pending", execution_confirmed=True,
            original_red_evidence_accepted=True, original_red_tests=65, original_red_existing_deadlocks=2,
            trace_probe_tests=5, trace_probe_failures=2, trace_probe_evidence_accepted=True,
            artifact_candidate_v3=str((store / "candidate-v3/receipt.json").relative_to(ROOT)),
            test_execution_accepted=False, independent_acceptance=False, checked_at=when)
    elif task.get("id") == "STAGE-JOINT-LAUNCHER-DRAFT-R35":
        task.update(status="revision3_source_review_passed_installed_inert_concrete_readiness_pending",
            source_review_passed=True, installed=True, execution_confirmed=False, independent_acceptance=False)
tasks.update(updated_at=when, latest_phase9_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / "tasks.json").write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
paragraph = f"\n\n---\n\n### {when} · native真实构建完成，Store事务重入探针确证，旧Job红不接纳\n\n14:18公开Bridge复查原两任务仍unknown，当前scope仅dead/turns0旧ZCode；现有隔离续任务继续，无重复派单/服务重启。实际/root/stage_cost_repair_r33的native V4于{build['finished_at']}真实构建结束，命令0且十项完整材料守卫真；新工具尚未产品行为独验，Python接线仍在artifact候选实现。原53红18P/35F/0Eskip因协调者许可并行复制完整候选导致config/AGENTS两个守卫失真，明确invalid，旧收据保留。六个反例另在strict headercoverage提前失败，改probe-only fixture文件名以保留独立查询，不添加include、不降低门禁，待同Counter有效红。\n\n实际/root/stage_currentness_repair_r33的原65红为2个真实嵌套SQL自锁和63个尚缺接口，不能称65产品缺陷；完整守卫真。额外真实SQLite trace五项2F/3P/0Eskip，确证SQL COMMIT→BEGIN重入后旧generation未撤回，API两项与普通trace对照通过。v3源修已冻待审，65与5原测试保留，未授green/独验/Stage。R35联合启动器rev3源审通过并仅安装，真实新tool/job/Store独验及最终Stage接入未满足，未执行。\n\nStage1082/Root1065全部SHA仍精确，未新增Root产品导入或新联合通过；历史成本失败1/S01失败3及全部失效证据保留，不把静态修正和无效探针计为新开发失败。完整工作包、真实项目/LLM效果、formal/portable分别未验。证据 {OUT.relative_to(ROOT).as_posix()}。\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R33.md"):
    path = HERE / name
    path.write_text(path.read_text(encoding="utf-8").rstrip() + paragraph, encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(latest_phase9_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when,
    current_stage_inputs=1082, current_stage_joint_validation_passed=False, next_root_intake_performed=False)
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=when, stage_root_exact=True, native_actual_build=0, invalid_red_preserved=True, joint_passed=False)))
