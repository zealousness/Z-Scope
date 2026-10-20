"""Persist actual diagnostics and authorized successor tasks without promoting pending gates."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/phase4-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
intake = read(ROOT / "artifacts/review-revision-stage-intake-r33-20261017/receipt.json")
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert len(intake["complete_inputs_after"]) == 1078
assert all(sha(stage / p) == v for p, v in intake["complete_inputs_after"].items())
assert len(intake["root_inputs"]) == 1065
assert all(sha(ROOT / p) == v for p, v in intake["root_inputs"].items())
combined = read(ROOT / "artifacts/coordinator-final-composite-r33-20261017/independent/review.json")
assert combined["junit"] == dict(tests=148, failures=0, errors=0, skipped=0)
assert [v["returncode"] for v in combined["commands"]] == [0, 0, 0, 0, 0, 1, 0]
assert not combined["bounded_combined_repair_independent_and_full_quality_passed"]
probe = ROOT / ".coordination/20261014/workspaces/shared-job-probes-r34/artifacts/shared_job_probes_r34"
for part in ("currentness", "checkpoint"):
    tree = ET.parse(probe / f"v2/{part}/pytest.xml").getroot()
    assert len(list(tree.iter("testcase"))) == len(list(tree.iter("failure"))) == 1
    assert not list(tree.iter("error")) and not list(tree.iter("skipped"))
context = ROOT / ".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33"
jobprep = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/preparation.json"
refs = [ROOT / "artifacts/coordinator-final-composite-r33-20261017/independent/review.json", context / "freeze.json", probe / "final-freeze.json", probe / "currentness-cause.json", probe / "checkpoint-interpretation.json", ROOT / "artifacts/shared-job-probe-observer-source-review-r34-20261017/cause-review.json", ROOT / "artifacts/shared-job-probe-observer-source-review-r34-20261017/footprint-constraints.json", ROOT / "artifacts/coordinator-shared-style-r34-20261017/input-freeze.json", jobprep]
checkpoint = dict(actual_task="/root", checked_at=when, root1065_unchanged=True, stage1078_unchanged=True, stage_review_slice_integrated=True, stage_other_r33_core_slices_integrated=False, root_intake=False, stage_joint_validation_passed=False, root_new_joint_validation_passed=False, currentness_producer_focused755_and_full_quality_passed=True, currentness_independent_final_acceptance_pending=True, combined148_tests_passed=True, combined148_full_quality_passed=False, combined148_black_failed_path="zscope/core/analysis/analyzer.py", style_retry1082_prepared=True, style_retry150_executed=False, currentness_original_case=dict(tests=1, failures=1, errors=0, skipped=0, cause="freeze_then_mkdir_job_inst_changes_include_search_namespace", cause_independently_reviewed=True), checkpoint_original_case=dict(tests=1, failures=1, errors=0, skipped=0, cause="old_E2_expectation_conflicts_with_valid_per_instance_R2_E0_and_one_fresh_validation", cause_independently_reviewed=True), original_failures_preserved=True, job_repair_actual_task="/root/stage_cost_repair_r33", job_repair_logical_task="JOB-RUNTIME-FOOTPRINT-REPAIR-R34", job_repair_dispatched=True, job_repair_tests_executed=False, job_repair_delivered=False, checkpoint_contract_candidate_actual_task="/root/stage_currentness_repair_r33", checkpoint_contract_candidate_logical_task="CHECKPOINT-TEST-CONTRACT-R34", checkpoint_contract_tests_executed=False, bridge_public_readonly_observation=dict(scope="current_instance", other_live_instances=5, current_session="sess_99a5552202", proc_state="dead", turns=0, original_access_restored=False, restarted=False), cost_failed_deliveries_preserved=1, s01_historical_failed_deliveries_preserved=3, new_job_repair_failed_deliveries=0, whole_package_complete=False, real_project_effect_accepted=False, reference_sha256={str(p.relative_to(ROOT)): sha(p) for p in refs})
assert not OUT.exists()
OUT.write_text(json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
tasks = read(HERE / "tasks.json")
records = tasks["tasks"]
for task in records:
    if task.get("id") == "STAGE-CURRENTNESS-REPAIR-R33":
        task.update(status="producer755_and_full_quality_passed_final_combination_independent_pending", artifact_delivered=True, producer_validation_passed=True, independent_acceptance=False, stage_intake=False, integrated=False, joint_validation_passed=False, actual_failed_deliveries=0)
    elif task.get("id") == "SHARED-JOB-PROBES-R34":
        task.update(status="two_original_failed_cases_executed_diagnostic_causes_independently_reviewed", execution_confirmed=True, artifact_delivered=True, diagnostic_independent_review=True, original_junit_failures_preserved=2, independent_acceptance=False, stage_intake=False, root_intake=False, integrated=False, joint_validation_passed=False, actual_failed_deliveries=0, delivery=str((probe / "DELIVERY.md").relative_to(ROOT)))
for ident, actual, workspace, scope in (("JOB-RUNTIME-FOOTPRINT-REPAIR-R34", "/root/stage_cost_repair_r33", read(jobprep)["workspace"], "isolated product repair; exact write ownership in preparation.json; original jobs tests readonly"), ("CHECKPOINT-TEST-CONTRACT-R34", "/root/stage_currentness_repair_r33", "artifacts/checkpoint-test-contract-r34-20261017", "artifact-only candidate for coordinator test adaptation; all existing source/tests readonly"), ("COORD-SHARED-STYLE-RETRY-R34", "/root", ".coordination/20261014/workspaces/coordinator-shared-style-r34", "two whole-AST-identical format changes; 150-case/full-quality launcher source review pending")):
    assert not any(t.get("id") == ident for t in records)
    records.append(dict(id=ident, actual_task_id=actual, transport="native_collaboration_followup" if actual != "/root" else "coordinator", bridge_task_id=None, model="gpt-6.1-sol", reasoning_effort="xhigh", workspace=workspace, scope=scope, status="dispatched_prepared_execution_acceptance_pending", dispatched=True, execution_confirmed=False, artifact_delivered=False, independent_acceptance=False, stage_intake=False, root_intake=False, integrated=False, joint_validation_passed=False, actual_failed_deliveries=0, checked_at=when, latest_phase4_checkpoint=str(OUT.relative_to(ROOT))))
tasks.update(updated_at=when, latest_phase4_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / "tasks.json").write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
paragraph = f"\n\n---\n\n### {when} · 两个原失败的因果已独审，隔离续任务继续\n\n原Bridge公开scope只读仍见dead/turns0、其他实例5；未恢复原访问，未重启。用户授权阻塞时新任务接续，实际/root/stage_cost_repair_r33承接JOB-RUNTIME-FOOTPRINT-REPAIR-R34，唯一隔离1082目录及显式ownership；/root/stage_currentness_repair_r33新artifact-only任务准备checkpoint测试契约候选，原P1交付保持。两个原单例均1F/0E/0skip/rc1保留：job_inst目录创建发生于freeze之后，是当前快照include-search失效首因；checkpoint实际R2/E0+freshvalidation1，旧整体checkpoint未消费，旧E2期望过时。普通#include与HasInclude分别保持shadow/否定查询保护，不能盲排除run_dir。\n\nP1生产者755及完整质量通过；协调者组合148测试通过但Black拒绝analyzer，整体未通过。已在全新1082目录仅格式化两文件并核wholeAST相等，150组合与七质量命令待源审后执行。Stage仅既有Review6路径接入，1078输入未变；Root1065未变，无新联合通过。成本候选未完整接纳累计1与S01历史3保留，探针失败不新增失败交付。证据 {OUT.relative_to(ROOT).as_posix()}。无完整工作包/真实项目/formal结论。\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R33.md"):
    p = HERE / name
    p.write_text(p.read_text(encoding="utf-8").rstrip() + paragraph, encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(latest_phase4_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when, current_shared_blockers=["job runtime namespace changes after semantic freeze", "coordinator combination full quality pending Black fix retry", "checkpoint legacy contract test adaptation pending actual validation", "Stage and Root fresh complete joint pending"], current_stage_joint_running=False, current_stage_joint_validation_passed=False)
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=when, stage1078_unchanged=True, root1065_unchanged=True, diagnostic_causes_reviewed=True)))
