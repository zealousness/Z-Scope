"""Archive the MCP quality/boundary failures and resume its original session once."""
from pathlib import Path
import datetime as dt
import json
from uuid import uuid4
from audit_followup_r10 import audit, ROOT, HERE

policy=json.loads((HERE/"route-check/bridge-response-r11-preflight-agents.json").read_text(encoding="utf-8"))
assert policy["coordinator"]["dispatch_enabled"]
branch=ROOT/".coordination/20261014/workspaces/u01-mcp-r10"
out=ROOT/"artifacts/coordinator-mcp-strict-probe-r10-20261015"
ownership=audit(branch.name)
assert not ownership["nonowned_changes"]
for row in ownership["changes"]:
    target=out/"initial-delivery"/row["path"]
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((branch/row["path"]).read_bytes())
probe=HERE/"followups-r10/test_mcp_strict_boundary.py"
(out/"failed-probe.py").write_bytes(probe.read_bytes())
review={"task_id":"task_2f3f99db9b","observed_model":"97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",
        "bridge_finished_at":"2026-10-14T23:12:53.487416+08:00","checked_at":dt.datetime.now(dt.timezone.utc).isoformat(),
        "ownership":ownership,"independent_acceptance_passed":False,"source_unchanged":True,
        "probe_result":{"passed":0,"failed":4,"skipped":0},"integrated":False,"whole_package_complete":False,
        "related_suite":"artifacts/coordinator-mcp-r10-acceptance2-20261015/review.json",
        "related_suite_result":"257 pass / 0skip; compileall pass; mypy no-any-return failure provider.py:738; Black not reached"}
(out/"review.json").write_text(json.dumps(review,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
message="""U01-MCP-JOBS R11独立验收返修，继续原sess_a0adb99b15、u01-mcp-r10、原7文件所有权。task_2f3f99db9b已10月14日23:12:53 completed/observed精确glm-5.3/get_result完整但正文止于开始实现，没有最终交付总结；当前4源码有产物、没有DELIVERY.md，根未导入。实际native写入在Bridge终态之后还有run.sh(23:19)，所以终态不等于稳定验收。
协调者已在Linux login shell独立跑11文件257pass/0fail/0skip、compileall0；mypy失败 zscope/mcp/provider.py:738 Returning Any from function declared dict[str,Any] (no-any-return,353源码)，Black未到。冻结4源码、全部命令和JUnit：根artifacts/coordinator-mcp-r10-acceptance2-20261015/{review.json,source-before,results.xml,command-*.log}。不要用宽泛ignore/降低mypy来规避，typed dispatch或实际验证返回映射均可。
新增真实MCP provider+ScanJobService/SQLite/owner探针 followups-r10/test_mcp_strict_boundary.py 四项全失败/0skip（根artifacts/coordinator-mcp-strict-probe-r10-20261015/results.xml，源码/探针已归档）。默认ToolPolicy.strict_schema=False，故adapter必须独立执行公开schema：job_id:null虽最终400但已创建.zscope_jobs；after_seq:null被当作0而读取DB返回404；stop_at:null、scan_depth:null被当成省略值且实际创建job并启动owner。公开schema这些字段都不允许null，Web边界也不把显式null当省略。_check当前value is not None条件使这些非法请求越过边界。
修复：已出现字段必须按string/int/enum严格检查，null、bool-as-int、空/超长/未知键等在_engine定位store或任何写入/启动owner之前400 invalid_request；真正省略可选字段继续合法。不得把schema放宽为nullable、设置全局strict_schema或更改服务来让反例变绿。保留所有已有幂等/revision/cancel/resume/输入失效/结果绑定/两个provider状态共享与read_only/candidate_blind禁控测试。
原相关257+新4探针全部0skip，compileall/mypy/所有已改文件Black经WSL Ubuntu zeal bash -lc、根test_slot两槽/ext4/PYTHONPATH本副本，完整最终日志/时间/稳定逐文件SHA、未测与完整DELIVERY.md后停写。scanner/reports仍明确受控合成，完整ScanSession队列/JOB04/JOB06、MCP findings投影或真实项目效果不升级宣称。既有工具描述失败在根和S01已证实同baseline，与你MCP改动分开记录；不改只读工具测试。
根/其他副本/共享jobs service/config/Web/CLI/全局Scanner/native/规则/共享文档/权限/provider配置/旧S06只读，不commit/push/reset/clean，不绕审核换模型；只修本任务已有授权范围。无活跃重复任务，沿原会话一次续接。"""
request={"id":"u01-mcp-r10-review1","branch":"u01-mcp-r10-review1","tool":"dispatch_task","arguments":{
    "agent":"zcode","session_id":"sess_a0adb99b15","cwd":str(ROOT),"model":"97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",
    "title":"U01-MCP-JOBS-R11","message":message,"request_id":str(uuid4()),"user_requested":True}}
(HERE/"followups-r10/u01-mcp-r10-review1-request.json").write_text(json.dumps(request,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
with (HERE/"route-check/bridge-queue/100-u01-mcp-r10-review1.request.json").open("x",encoding="utf-8",newline="\n") as stream:
    stream.write(json.dumps(request,ensure_ascii=False)+"\n")
print(json.dumps({"request":request["id"],"failed_review":str(out/"review.json")}))
