"""Continue only after the original premature-end producer and tests are quiescent."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
identity = "r12-mcp-continuation-preflight"
request_path = route / "bridge-queue" / ("080-" + identity + ".request.json")
response_path = route / ("bridge-response-" + identity + ".json")
if not response_path.exists():
    assert not request_path.exists()
    request_path.write_text(json.dumps({"id":identity,"tool":"list_sessions","arguments":{"active_only":False}})+"\n",encoding="utf-8",newline="\n")
until = time.monotonic() + 40
while not response_path.exists() and time.monotonic() < until:
    time.sleep(.25)
value = json.loads(response_path.read_text(encoding="utf-8"))
session = next(row for row in value["sessions"] if row["session_id"] == "sess_3b6b9a19b2")
assert session["proc_state"] in {"ready", "idle_unloaded"}, session["proc_state"]
original = json.loads((HERE / "followups-r12/mcp-findings-r12-request.json").read_text(encoding="utf-8"))
arguments = dict(original["arguments"])
arguments.update(title="MCP-FINDINGS-R12-FINALIZE", request_id=str(uuid4()))
arguments["message"] = """继续原MCP-FINDINGS-R12未完成交付，不另起实现。原task_a3a56d31b4 Bridge于02:38:01标completed、observed GLM5.3，公开get_result仅到“实现”，无最终DELIVERY。协调者实际观察到02:38之后继续写5个owned文件、WSL检查进程存在到02:47；02:51:32 Linux工作目录进程清单为空，Windows同目录命令进程也已为空，原会话最新inventory为ready且无原任务运行，才发这次同会话普通续接。不是API超时/审核绕过或已独验通过，不启动任何重复服务，不重做他人任务。
请先核对当前5个owned文件与实际已执行检查，原样保留已有输出，继续补齐真实MCP/provider/JSONRPC→SQLite/service/owner的finding投影正反例、全部原权限/null/幂等/取消恢复回归、完整质量检查与最终收据。当前只有源码增量，没有协调者认可的最终测试结论；未保存可核验结果的检查必须实际执行并捕获本轮日志/JUnit/时间/SHA，不能推断成功。当前既有代码应复用；仅修实测问题、完善未完成点及交付。后台命令全部结束/源码停写后才发最终说明，DELIVERY.md必须包含精确SHA/UTC+8时间/命令/JUnit/真实与受控边界、共享Web接线建议。原完整约束及目录/所有权/运行要求如下：

""" + original["arguments"]["message"]
request = {"id":"mcp-findings-r12-finalize","branch":"mcp-findings-r12","tool":"dispatch_task","arguments":arguments}
assert not (HERE / "followups-r12/mcp-findings-r12-finalize-request.json").exists()
(HERE / "followups-r12/mcp-findings-r12-finalize-request.json").write_text(json.dumps(request,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"prepared":True,"session_state":session["proc_state"],"at":dt.datetime.now(dt.timezone.utc).isoformat(),"dispatched":False}))
