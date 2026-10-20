"""Record completed-but-rejected R2 and accepted same-session R3 requests."""
from pathlib import Path
import datetime as dt
import json

HERE=Path(__file__).resolve().parent
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
rows={row["id"]:row for row in ledger["tasks"]}
specs=[("S01-INST-EXEC","s01-analysis-r6","task_09da468c8a","2026-10-14T21:52:20.342253+08:00","coordinator-s01-r2-acceptance-20261014",7,3),
       ("S08-SESSION-SCHEDULER","s08-session-r6","task_c1fb932358","2026-10-14T21:51:54.759436+08:00","coordinator-s08-r2-acceptance-20261014",5,2)]
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for identifier,workspace,previous,finished,artifact,passed,failed in specs:
    row=rows[identifier]
    history=row.setdefault("execution_history",[])
    if not any(item.get("task_id")==previous for item in history):
        history.append({"task_id":previous,"session_id":row["bridge_session_id"],"finished_at":finished,"observed_model":row["requested_model"],
                        "status":"completed_delivery_independent_acceptance_failed","independent_probe_result":{"passed":passed,"failed":failed,"skipped":0},
                        "independent_review":f"artifacts/{artifact}/review.json","independent_acceptance":False,"integrated":False})
    request=json.loads((HERE/f"followups-r6/{workspace}-review3-request.json").read_text(encoding="utf-8"))
    response_path=HERE/f"route-check/bridge-response-{workspace}-review3.json"
    response=json.loads(response_path.read_text(encoding="utf-8"))
    assert response["ok"] and response["session_id"]==row["bridge_session_id"]
    row.update(bridge_task_id=response["task_id"],request_id=request["arguments"]["request_id"],accepted_model=response["model"],observed_model=None,
               status="review3_dispatched_pending_execution_evidence",execution_evidence=None,independent_acceptance=False,integrated=False,
               latest_failed_review=f"artifacts/{artifact}/review.json",checked_at=at,whole_package_complete=False)
ledger["updated_at"]=at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage_path=HERE/"continuation-r6.json"
stage=json.loads(stage_path.read_text(encoding="utf-8"))
stage.update(updated_at=at,next_task_rows=[rows[name] for name in ("S01-INST-EXEC","S08-SESSION-SCHEDULER","U01-ENTRYPOINTS","ASTRA-V3-EDITOR")])
stage_path.write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
entry=f"""## {at[:19]} +08:00 · R2独立验收失败，原会话R3返修

- 原Bridge owner80748保持，公开会话sess_261a55289f/sess_3b6b9a19b2在返修派发前均ready，无活跃同会话任务；未恢复/查询/重派旧S06。根目录985个R8绑定输入仍一致，635项/6质量通过仅覆盖该根版本。
- S01 `task_09da468c8a`21:52:20终态/observed kimi-k3，原7探针通过；补native后独立7pass/3fail/0skip：真实native候选共享验证helper重开未隔离索引、同构建外来USR类型、外层build标签授权无收据宏。首轮漏native env的7pass2fail1skip保留为中间轮，不能代替最终native轮。源码5文件、worker303/JUnit及说明保全于 `artifacts/coordinator-s01-r2-acceptance-20261014/initial-delivery`，验收未通过/未导入；R3 `{rows['S01-INST-EXEC']['bridge_task_id']}`已接受，实际执行/最终模型待新证据。
- S08 `task_c1fb932358`21:51:54终态/observed精确glm-5.3；原5探针通过，新重复children/同输入恢复耗尽blocked父项两反例失败，独立5pass2fail0skip，`artifacts/coordinator-s08-r2-acceptance-20261014/review.json`。7源码稳定且未越权；旧交付说明仍R1，副本159项JUnit另有1失败且时间晚于Bridge终态，启动来源未确认为最终worker轮，不能宣称R2通过。均已归档，未导入；R3 `{rows['S08-SESSION-SCHEDULER']['bridge_task_id']}`已接受，保持原7文件所有权。
- 后续按同标准复验→只导入通过字节→当前根联合/全部质量；共享ScanSession/完整scanner接线仍单独，原阶段切片不关闭S01/S08主包。真实LLM/项目效果/formal/portable实物与条件S10/Q仍未验收，外部等待单列。

---

"""
for name in ("PROGRESS.md","DAG.md"):
    target=HERE/name
    target.write_text(entry+target.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"s01":rows['S01-INST-EXEC']['bridge_task_id'],"s08":rows['S08-SESSION-SCHEDULER']['bridge_task_id']}))
