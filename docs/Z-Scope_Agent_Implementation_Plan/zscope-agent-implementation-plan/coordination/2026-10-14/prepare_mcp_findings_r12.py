"""Assign the independent MCP findings consumer from accepted current R12 bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
follow = HERE / "followups-r12"
accepted = ROOT / "artifacts/coordinator-r12-remaining-intaken-20261015"
review = json.loads((accepted / "review.json").read_text(encoding="utf-8"))
source = json.loads((accepted / "source-evidence.json").read_text(encoding="utf-8"))["after"]
assert review["passed"] == 1132 and review["quality_commands_passed"] == 6 and review["current_bytes_match"]
preflight = json.loads((HERE / "route-check/bridge-response-r12-mcp-findings-preflight.json").read_text(encoding="utf-8"))
assert next(row for row in preflight["sessions"] if row["session_id"] == "sess_3b6b9a19b2")["proc_state"] == "idle_unloaded"
workspace_name = "mcp-findings-r12"
workspace = ROOT / ".coordination/20261014/workspaces" / workspace_name
workspace.mkdir(exist_ok=False)
for name, sha in source.items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha
    target = workspace / name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT / name,target)
task = {"id":"MCP-FINDINGS-R12","workspace":workspace_name,"isolated_workspace":str(workspace),"isolated_workspace_linux":"/mnt/c/" + workspace.as_posix()[3:],"agent":"zcode","model":"97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3","session_id":"sess_3b6b9a19b2","depends_on":["CURRENT-JOINT-R12"],"owns":["zscope/mcp/provider.py","zscope/mcp/jobs_adapter.py","zscope/reporting/job_result_projection.py","tests/test_mcp_jobs.py","tests/test_job_result_projection.py"]}
message = f"""继续 U01 剩余 MCP findings 消费，ZCode glm-5.3，本任务MCP-FINDINGS-R12。前轮7个MCP job工具经task_feb229984d返修独验262并集成，当前根目录加owner真实remaining修复后联合1132、六命令通过（02:30:31+08）。但jobs.result仍findings=None，不能算完整消费。不是重复实现持久service，不恢复旧S06。
唯一写副本 {workspace}；WSL {task['isolated_workspace_linux']}，共{len(source)}输入逐字节来自 artifacts/coordinator-r12-remaining-intaken-20261015/source-evidence.json。Bridge cwd根目录只定位会话，根/旧副本不写。独占上述MCP provider/jobs_adapter、新reporting/job_result_projection.py、test_mcp_jobs.py、新test_job_result_projection.py；其他全部只读，尤其jobs service/store/owner/queue、Web服务、Analyzer/Validator/contracts、ScanSession/ParallelAnalyzer、静态UI/锁/docs/native/规则。Kimi task_1cee9c8e9d 负责完整ScanSession，另一ZCode task_315195c1a1负责契约/验证，Astra负责UI；不碰其文件/副本或启动新Bridge/代理。
复用真实ScanJobService.load_bound_report及正式shared-json读取器，把默认MCP jobs.result接到既有ReportFeedbackService.project_report的轻量finding/acceptance投影；不要另造近似字段/证明逻辑，不能只返回空列表。仅从当前job绑定的不可变attempt报告取finding，不能把项目当前报告替换成历史结果。外层report_id仍原字节hash，内层report_id为复核范围，保留build/issue/context/acceptance身份及unknown覆盖。核对与Web ScanJobsHttpService._result真实行为：逻辑报告与当前报告完全相等才可共享当前复核scope；内容不同必保留独立snapshot scope。定位saved config的project.root，不能依赖Bridge cwd/用户传路径；当前报告缺失/损坏不能吞掉已有效绑定的历史报告。只读profile/candidate_blind无job工具不构造service，原strict null/路径/SQL/输出权限边界不放宽。
可以提供新的纯投影辅助模块供协调者随后复用到Web，但你不改Web/shared service；给出精确接口和最小接线建议。只读复用现有纯project_report可合理import，不能HTTP自调用Web或启动别的数据库/线程。重复加载中的文件损坏/替换、当前job resume导致run/input变化均不可把旧结果标为新attempt；需明确绑定job/run/input/revision/report并在发表前核验。现service result envelope若缺必要字段请用实际detail绑定或交共享修改建议，不靠仅hash相同推断同attempt。返回如需新增绑定字段保持明确合同，不伪造fixture成功。
验收必须实际MCP provider/JSONRPC→adapter→真实SQLite/ScanJobService/detached owner，只有scanner/report/模型边界允许明确受控，不能mock service成功。产出至少含一个实际finding的plain及shared-json报告，核对Web已有纯投影同值、相同/不同current报告复核scope、服务/provider重建、报告丢失/篡改/损坏对象图、读取间换attempt（即使报告bytes相同）、未知覆盖/null及旧权限/幂等/输入变化/取消恢复全部原回归。旧assert findings=None需改成新真实投影契约，不删测试/skip/xfail或降低标准；受控报告不是项目扫描效果。
先读本副本AGENTS、architecture、interfaces-reporting模块与实施11/16/20/21以及实际调用链。所有测试/质量仅WSL Ubuntu zeal login shell bash -lc、/home/zeal/venv313/bin/python，根{HERE}/test_slot.py --workspace <本副本绝对Linux路径> -- <argv>，两槽、独立ext4TMPDIR和本副本PYTHONPATH，默认fd捕获不变。compileall -f -q zscope scripts test tests、mypy zscope、必要变更Black；不运行Windows测试结论、不重建native、不抓新资源、不commit/push/reset/clean、不碰凭据/provider/审批。结束给DELIVERY.md/真实时间/JUnit/各命令/稳定逐文件SHA/所有未测和共享接线建议，先停写后报终态，协调者独验、共享集成及当前字节联合。不把这一切片当完整U01/主包完成，普通API失败保存，不能通过模型转交绕审核。
"""
task["message"] = message
at = dt.datetime.now(dt.timezone.utc).isoformat()
baseline = {"captured_at":at,"task":task,"files":[{"path":name,"sha256":sha} for name,sha in source.items()],"joint_evidence":str(accepted.relative_to(ROOT)),"dispatched":False}
(follow / (workspace_name + "-baseline.json")).write_text(json.dumps(baseline,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
(follow / (workspace_name + "-prompt.txt")).write_text(message,encoding="utf-8",newline="\n")
request = {"id":workspace_name,"branch":workspace_name,"tool":"dispatch_task","arguments":{"agent":task["agent"],"model":task["model"],"session_id":task["session_id"],"cwd":str(ROOT),"title":task["id"],"message":message,"request_id":str(uuid4()),"user_requested":True}}
(follow / (workspace_name + "-request.json")).write_text(json.dumps(request,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"prepared":task["id"],"files":len(source),"dispatched":False}))
