"""Send a concrete actual-owner concurrency defect to its original developer."""
from pathlib import Path
import hashlib
import json
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
proof = json.loads((HERE / "review-repro/job-request-atomicity/review.json").read_text(encoding="utf-8"))
assert proof["scanner_invocations"] == 2 and len(proof["job_ids"]) == 2
terminal = json.loads((HERE / "route-check/bridge-response-s08-current-delivery.json").read_text(encoding="utf-8"))
assert terminal["task_id"] == "task_1e2a609d1d" and terminal["status"] == "completed"
source = ROOT / ".coordination/20261014/workspaces/s08-owner"
for name in ("service.py", "store.py"):
    path = Path("zscope/orchestration/jobs") / name
    assert hashlib.sha256((source / path).read_bytes()).digest() == hashlib.sha256((ROOT / path).read_bytes()).digest()
message = """原S08 owner/store修复已独立69passed并导入，当前真实HTTP/browser同源519passed仍不能掩盖新的R5实际并发缺陷。请在原sess_b2d3c1d8e8内对自己原隔离目录 .coordination/20261014/workspaces/s08-owner 接续验收修复，只改jobs自有模块与tests/test_scan_jobs.py、test_scan_job_execution.py/DELIVERY/artifacts；其它931输入保留，不改root/shared scan_session/Web/UI/静态/锁/文档，不重编native/读凭据/改权限/provider/commit。
证据绝对路径：""" + str(HERE / "review-repro/job-request-atomicity/review.json") + "\n复現脚本：" + str(HERE / "probe_job_request_atomicity.py") + """
R5：start在实际owner启动之后才_record_request，paused第一handler后等真实owner完成，再以同一request_id POST，会启动第二个真实owner/scanner；B202、A409，DB两个completed job、scanner_invocations=2。DB/project active互斥不能保证幂等：第一job已结束时第二仍可创建。不要仅加进程内Lock或固定sleep，Web重启/多service/多客户端必须一份SQLite事务的request marker+job/attempt状态原子绑定，在任何启动副作用前有唯一且可重读的持久reservation。相同endpoint+payload返回唯一原job/attempt，不再启动；不同endpoint/body同key409且不启动/取消任何额外工作。真实spawn失败/owner完成/handler断开/重开服务/重复并发也要保持身份和原因。检查resume/cancel相同的动作后登记窗口，有同类缺口一并在自有模块修复；不能用旧base_revision二次启动新attempt。store NOT NULL、真实503、PID/owner token/current run/input重新核验和共享report解码都保留。request复用不能当成新输入授权；清楚区分replay和新attempt。
把当前脚本的pause模式变为稳定回归，真实HTTP/DB/detached owner、受控scanner+真实writer，无DB/status/process mock。至少两个service/reopen/concurrent相同key/冲突key、快速终态前请求登记延迟、实际spawn失败重发；只有扫描器/调度暂停是标注的故障注入，不能用sleep碰运气或弱化断言。未解决必须明报，无ignore，进程内锁不代替跨进程事务。测试仅WSL /home/zeal/venv313/bin/python，绝对隔离PYTHONPATH，相关集合稳定最终字节下跑，不与旧69/519相加；compileall/mypy/必要Black，最多同轮两个pytest，自己的单pytest。只产修复，root受控导入由协调者；JOB04/06/fair队列和全部前端仍不是本分支范围。
严禁读取/操作/派发/续发/重试/代做task_0947f2854f及旧被拦caller分支，native/async_paths/lifecycle/protocol/rules/catalog不改。用户已确认旧观察线程完成归档，无需操作；不是内容/权限拒绝重试。发现新真实拒绝则停准确报告，不换模型/会话绕过。默认实验不变，未知计数/未测不提升状态。
"""
request = {"id": "s08-atomic-request-fix", "branch": "S08-OWNER", "tool": "dispatch_task", "arguments": {"agent": "zcode", "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "cwd": str(ROOT), "session_id": "sess_b2d3c1d8e8", "title": "S08 R5真实owner请求原子性修复", "user_requested": True, "request_id": str(uuid.uuid4()), "message": message}}
with (HERE / "route-check/bridge-queue/047-s08-atomic-request-fix.request.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"branch": request["branch"], "prior_terminal": terminal["task_id"], "request_id": request["arguments"]["request_id"], "confirmed_duplicate_scanners": 2}))
