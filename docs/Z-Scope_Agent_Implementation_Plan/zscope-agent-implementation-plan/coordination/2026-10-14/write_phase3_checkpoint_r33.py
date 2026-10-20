"""Persist completed Stage intake, real failed delivery and separate probe continuation."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
OUT=ROOT/"artifacts/coordinator-stage-repairs-r33-20261017/phase3-checkpoint.json"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
when=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
intake=ROOT/"artifacts/review-revision-stage-intake-r33-20261017/receipt.json"
stage=ROOT/".coordination/20261014/workspaces/coordinator-instance-integration-r24"
idata=read(intake)
assert idata["stage_intake"] and all(sha(stage/p)==digest for p,digest in idata["complete_inputs_after"].items())
assert all(sha(ROOT/p)==digest for p,digest in idata["root_inputs"].items())
cost=ROOT/".coordination/20261014/workspaces/stage-cost-repair-r33"
tree=ET.parse(cost/"artifacts/stage-cost-r33/regression-usage/pytest.xml").getroot()
failed=[dict(classname=n.get("classname"),name=n.get("name")) for n in tree.iter("testcase") if n.find("failure") is not None]
assert len(list(tree.iter("testcase")))==308 and len(failed)==12
session=ROOT/"artifacts/coordinator-session-cost-r33-20261017/regression/review.json"
assert read(session)["bounded_session_regression_and_full_quality_passed"] and read(session)["junit"]==dict(tests=89,failures=0,errors=0,skipped=0)
refs=[intake,session,cost/"DELIVERY.md",cost/"artifacts/stage-cost-r33/final-freeze.json",cost/"artifacts/stage-cost-r33/regression-classification.json",cost/"artifacts/stage-cost-r33/regression-usage/pytest.xml",ROOT/"artifacts/shared-job-probes-r34-20261017/preparation.json",ROOT/"artifacts/coordinator-stage-repairs-r33-20261017/bridge-readonly-followup-1219.json",ROOT/"artifacts/stage-final-repair-source-review-r33-20261017/shared-five-module-boundary-review.json"]
checkpoint=dict(actual_task="/root",checked_at=when,root1065_unchanged=True,stage_complete_inputs=1078,stage_review_slice_integrated_at=idata["integrated_at"],stage_review_slice_paths=6,stage_full_quality_passed=False,stage_joint_validation_passed=False,root_intake=False,session_independent89_and_five_quality_commands_passed=True,session_stage_intake=False,cost_delivery_status="delivery_acceptance_pending_shared_dependencies",cost_actual_regression=dict(tests=308,passed=296,failed=12,errors=0,skipped=0),cost_failed_ids=failed,cost_returned_candidates=1,cost_returned_candidates_not_fully_accepted=1,cost_cumulative_failed_deliveries=1,cost_all12_attributed_to_owned_code=False,historical_s01_failed_deliveries=3,currentness_full755_and_quality_rerun_pending=True,composite148_independent_and_quality_actual_running=True,job_probe_owner_task="/root/stage_cost_repair_r33",job_probe_logical_task="SHARED-JOB-PROBES-R34",job_probe_prepared1082=True,job_probe_execution_confirmed=False,job_probe_original_tests_readonly=True,reference_sha256={str(p.relative_to(ROOT)):sha(p) for p in refs},whole_package_complete=False,real_project_effect_accepted=False)
assert not OUT.exists()
OUT.write_text(json.dumps(checkpoint,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"tasks.json"
tasks=read(path)
records=next(v for v in tasks.values() if isinstance(v,list) and any(isinstance(t,dict) and t.get("id")=="STAGE-COST-REPAIR-R33" for t in v))
for task in records:
    if task.get("id")=="STAGE-COST-REPAIR-R33":
        task.update(status=checkpoint["cost_delivery_status"],artifact_delivered=True,actual_failed_deliveries=1,cumulative_returned_candidates_not_fully_accepted=1,failed_delivery_scope="Full declared broader regression remains unclosed; 12 failures are not all attributed to owned cost code",delivery=str((cost/"DELIVERY.md").relative_to(ROOT)),latest_phase3_checkpoint=str(OUT.relative_to(ROOT)))
    elif task.get("id")=="COORD-REVIEW-REVISION-REPAIR-R33":
        task.update(status="bounded_independent271_and_target_quality_passed_stage_intaken_full_joint_pending",independent_acceptance=True,stage_intake=True,integrated=True,stage_intake_at=idata["integrated_at"],stage_intake_receipt=str(intake.relative_to(ROOT)),full_stage_quality_passed=False,joint_validation_passed=False)
    elif task.get("id")=="COORD-SESSION-HANDOFF-R33":
        task.update(status="bounded_independent89_and_full_isolated_quality_passed_shared_dependencies_pending",artifact_delivered=True,independent_acceptance=True,independent_receipt=str(session.relative_to(ROOT)),stage_intake=False,integrated=False,joint_validation_passed=False)
assert not any(t.get("id")=="SHARED-JOB-PROBES-R34" for t in records)
records.append(dict(id="SHARED-JOB-PROBES-R34",owner="existing native 6.1-sol/xhigh worker, diagnostic artifacts only",actual_task_id="/root/stage_cost_repair_r33",transport="native_collaboration_followup",bridge_task_id=None,workspace=".coordination/20261014/workspaces/shared-job-probes-r34",write_paths=["own diagnostic artifacts only"],product_and_original_tests_readonly=True,logical_scope_new=True,duplicate_old_package_dispatch=False,status="prepared1082_observer_and_launcher_source_review_pending",dispatched=True,execution_confirmed=False,artifact_delivered=False,independent_acceptance=False,stage_intake=False,root_intake=False,integrated=False,joint_validation_passed=False,actual_failed_deliveries=0,latest_phase3_checkpoint=str(OUT.relative_to(ROOT)),checked_at=when))
tasks["updated_at"]=when
path.write_text(json.dumps(tasks,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
text=f"\n\n---\n\n### {when} · 独立89通过、Review切片已Stage接入，扩大回归12F保留\n\n协调者Review兼容修复及四处旧测试适配共6路径已于{idata['integrated_at']}接入Stage，实际完整输入1077→1078；依据271项回归、目标质量及独立源审，仅授该切片接入，Stage完整质量与联合仍未通过。Root1065未变。Session交接修复独验9文件89项/0F/E/skip，compileall、normal/fresh完整mypy与Black五命令全0，尚未Stage接入。\n\n/root/stage_cost_repair_r33 已返回冻结候选f0/52ca，16项有界green与质量0保留；18文件实际308=296pass/12F/0E/0skip，所有材料守卫真。12F为旧policy1、旧整体checkpoint篡改断言1、SessionJobs当前性拒绝8及相关未开始2，不能全归成本逻辑。记本轮返回但未完整接纳候选交付1次，旧S01失败3不增不清，累计历史保留。\n\n新逻辑 SHARED-JOB-PROBES-R34 沿用实际/root/stage_cost_repair_r33，仅拥有新隔离1082材料下诊断artifact；产品与原测试只读，观察器源审后才运行两个原最小case，尚无因果确证。当前性完整755重跑与协调者148组合独验仍实际运行。Bridge只读当前scope仍dead ZCode/turns0、其他实例5；未重启/恢复/重复派单。证据 {OUT.relative_to(ROOT).as_posix()}。未授Root导入/新联合/完整工作包/真实项目或formal结论。\n"
for name in ("DAG.md","PROGRESS.md","CURRENT_STATE_R33.md"):
    p=HERE/name
    p.write_text(p.read_text(encoding="utf-8").rstrip()+text+"\n",encoding="utf-8",newline="\n")
continuation=read(HERE/"continuation-r6.json")
continuation.update(latest_phase3_checkpoint=str(OUT.relative_to(ROOT)),latest_checked_at=when)
(HERE/"continuation-r6.json").write_text(json.dumps(continuation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(checked_at=when,stage_review_intaken=True,session89_pass=True,root_unchanged=True)))
