"""Record actual bounded evidence without converting it into integration claims."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/phase2-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
root = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root) == 1065 and all(sha(ROOT/p)==digest for p,digest in root.items())
evidence = {
    "context50": ".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33/own-20261017T034756.798542Z/receipt.json",
    "cost16": ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/green-usage/receipt.json",
    "cost_quality": ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/quality-usage/receipt.json",
    "review33": "artifacts/coordinator-review-revision-repair-r33-20261017/green/review.json",
    "review271": "artifacts/coordinator-review-revision-repair-r33-20261017/regression/review.json",
    "session_invalid_red": "artifacts/coordinator-session-cost-r33-20261017/red-invalid-causal-audit.json",
    "session_strict_red": "artifacts/coordinator-session-cost-r33-20261017/red2-causal-audit.json",
    "session_green2": "artifacts/coordinator-session-cost-r33-20261017/green2/review.json",
    "policy_override": "artifacts/coordinator-policy-expectation-r33-20261017/context-readonly-override.json",
}
assert all((ROOT/p).is_file() for p in evidence.values())
assert read(ROOT/evidence["session_green2"])["bounded_session_handoff_green_passed"]
checkpoint = dict(actual_task="/root", checked_at=when, actual_tasks=["/root/stage_currentness_repair_r33","/root/stage_cost_repair_r33","/root/consumer_source_review_r28"], evidence={name:dict(path=p,sha256=sha(ROOT/p)) for name,p in evidence.items()}, root1065_unchanged=True, context_status="50 green; focused755/1F stale policy literal; coordinator-only correction copied; strict full rerun pending", cost_status="16 green plus four quality commands0; 18file broader regression still running with F marker, no cause assigned", review_status="33 red-green and 271 focused pass; isolated old Parallel typing still blocks full quality; final composite pending", session_status="initial fixture red rejected, strict actual cost red and same-counter green2 pass; source/focused/full quality integration pending", independent_final_composite_pending=True, stage_intake=False, root_intake=False, joint_validation_passed=False, historical_s01_failed_deliveries=3, new_producer_failed_deliveries=0, whole_package_complete=False, real_project_effect_accepted=False)
assert not OUT.exists()
OUT.write_text(json.dumps(checkpoint,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
tasks_path=HERE/"tasks.json"
tasks=read(tasks_path)
records=next(v for v in tasks.values() if isinstance(v,list) and any(isinstance(t,dict) and t.get("id")=="STAGE-CURRENTNESS-REPAIR-R33" for t in v))
states={"STAGE-CURRENTNESS-REPAIR-R33":checkpoint["context_status"],"STAGE-COST-REPAIR-R33":checkpoint["cost_status"],"COORD-REVIEW-REVISION-REPAIR-R33":checkpoint["review_status"]}
for task in records:
    if task.get("id") in states:
        task.update(status=states[task["id"]],latest_phase2_checkpoint=str(OUT.relative_to(ROOT)),checked_at=when)
assert not any(t.get("id")=="COORD-SESSION-HANDOFF-R33" for t in records)
records.append(dict(id="COORD-SESSION-HANDOFF-R33",owner="coordinator",actual_task_id="/root",workspace=".coordination/20261014/workspaces/coordinator-session-cost-r33",write_paths=["zscope/orchestration/scan_session.py","tests/test_session_preentry_cost_r33.py"],depends_on=["STAGE-COST-REPAIR-R33"],status=checkpoint["session_status"],dispatched=False,execution_confirmed=True,artifact_available=True,independent_acceptance=False,stage_intake=False,root_intake=False,integrated=False,joint_validation_passed=False,whole_package_complete=False,latest_phase2_checkpoint=str(OUT.relative_to(ROOT)),checked_at=when))
tasks["updated_at"]=when
tasks_path.write_text(json.dumps(tasks,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
paragraph=f"\n\n---\n\n### {when} · R33 新候选与严格因果检查\n\n当前性 /root/stage_currentness_repair_r33 新50项green，完整focused755项有1个旧defaults_only元数据断言失败；已核MIN合同由协调者仅修正该字面期望，新全755与质量重跑中。成本 /root/stage_cost_repair_r33 新16项green，Black/compileall/normal与fresh mypy360四命令0；18文件扩大回归尚运行且出现F，未猜测原因。原失败日志与S01历史失败3保留，不把探针算失败交付。\n\nReview当前11条精确版本兼容修复实际33项红绿对照及13文件271项通过；该隔离目录旧Parallel类型错误仍阻断全质量，含新Parallel的协调者组合独验待执行。Session首探针clients空导致StopIteration，旧valid_red标记明确拒绝；修正真实客户端配置后严格2/1F确到0!=24，最小两kwargs修复后同Counter2pass，输入/Root/配置/引用守卫真。仅为离线accounting与真实native构造链路验证，非provider/Wiki或真实项目效果验收。\n\n证据 {OUT.relative_to(ROOT).as_posix()}。本轮修复尚无Stage接入、Root导入或新联合通过；下一步完成候选完整回归、组合独验、共享源审再集成。未重启Bridge、未恢复S06-R02、未重复派单。\n"
for name in ("PROGRESS.md","CURRENT_STATE_R33.md","DAG.md"):
    p=HERE/name
    p.write_text(p.read_text(encoding="utf-8").rstrip()+paragraph+"\n",encoding="utf-8",newline="\n")
continuation=read(HERE/"continuation-r6.json")
continuation["latest_phase2_checkpoint"]=str(OUT.relative_to(ROOT))
continuation["latest_checked_at"]=when
(HERE/"continuation-r6.json").write_text(json.dumps(continuation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(checked_at=when,root_unchanged=True)))
