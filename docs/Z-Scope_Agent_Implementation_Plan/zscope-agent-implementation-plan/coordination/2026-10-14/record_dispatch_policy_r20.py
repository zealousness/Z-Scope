"""Persist the human's project-scoped escalation rule and real cross-ID rounds."""
from pathlib import Path
import datetime as dt
import json

HERE=Path(__file__).resolve().parent
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
policy=ledger.setdefault("current_worker_policy",{})
policy.update(recorded_at=at,scope="current Z-Scope project only",policy_document="DISPATCH_POLICY.md",glm_failed_delivery_threshold=4,track_across_task_ids=True,upgrade_model="gpt-6.1-sol",especially_complex_model="gpt-6-astra",upgrade_reasoning_effort="xhigh",exclude_network_auth_dispatch_failures=True,no_route_change_to_bypass_platform_restrictions=True,keep_current_three_accepted_slices=True)
rounds={"VALIDATION-CONTEXT-R18":[("task_cb7011476d","failed_native_callee_rebind"),("task_bf7efdfce3","failed_parent_call_snapshot"),("task_d4f97ce947","failed_valid_call_value_snapshot"),("task_1ef444cf29","independent_slice_passed1084_four_commands")],"U01-STOP-AT-R18":[("task_5b722e514f","failed_real_shared_token_http_budget"),("task_9565621a54","failed_prior_cancellation_reason"),("task_4e43cb393d","independent_slice_passed532_four_commands")],"S07-NATIVE-HOT-R19":[("task_7118aeca55","independent_bounded_diagnosis_passed175_four_commands_after_coordinator_readonly_test_migration")]}
for row in ledger["tasks"]:
    if row["id"] in rounds:
        row["glm_delivery_rounds"]=[{"round":i+1,"task_id":task,"result":result} for i,(task,result) in enumerate(rounds[row["id"]])]
        row["glm_consecutive_failed_deliveries"]=0
        row["glm_escalation_required"]=False
        row["glm_counter_note"]="Current bounded slice independently accepted; preserve results. Invalid coordinator fixture and obsolete native test baseline are not additional GLM development failures. Parent packages remain open."
ledger["updated_at"]=at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"## {at} · 用户新增项目升级标准\n\n同工作项跨task ID计实际开发/返修交付失败连续轮次；第4轮及以后仍未达验收升级gpt-6.1-sol，特别复杂可Astra，思考xhigh。网络/认证/调度失败不计，不换路由绕过平台限制。当前三已独验切片保持，不重做。完整口径与历史轮次见 DISPATCH_POLICY.md / tasks.json glm_delivery_rounds；Kimi暂停，DSH简单任务，Astra UI分工保持。\n\n---\n\n"
for filename in ("DAG.md","PROGRESS.md"):
    path=HERE/filename
    path.write_text(note+path.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps({"recorded_at":at,"project_scoped":True,"model_escalation_after_consecutive_failed_delivery":4,"current_three_slices_preserved":True}),flush=True)
