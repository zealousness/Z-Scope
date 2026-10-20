"""Reconcile the exact completed receipt, then prepare one original-session review."""

from pathlib import Path
import json
import uuid

from dispatch_safety import DispatchJournal

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
state = json.loads((HERE / "bridge-response-s08-latest-terminal.json").read_text(encoding="utf-8"))
assert state["task_id"] == "task_24c156da37"
assert state["status"] == "completed"
assert state["observed_model"] == "volceapi/kimi-k3"
journal = DispatchJournal(HERE / "dispatch-journal.sqlite")
try:
    old_id = "7bc00df0-5f0e-498d-995f-891faf125caa"
    old = journal.db.execute("SELECT state,task_id FROM requests WHERE id=?", (old_id,)).fetchone()
    if old and old[0] in {"queued", "pending"}:
        journal.accepted(old_id, state["task_id"])
        old = ("accepted", state["task_id"])
    if old and old == ("accepted", state["task_id"]):
        journal.terminal(state["task_id"], "completed")
    elif not old or old != ("completed", state["task_id"]):
        raise RuntimeError("completed receipt does not reconcile exact prior request")
finally:
    journal.close()

message = """同一 S08 原会话的正常验收修复，前轮 task_24c156da37 已公开 completed，实际 volceapi/kimi-k3。不要另起会话、改 provider/model/权限，遇到新的真实平台或内容拒绝停止并准确报告。用户要求原验收标准不降低。
重要纠正：前轮为了接续已有成果说‘不要重写8个模块’，意思是保留增量，绝不是冻结必要修复。8个新 jobs 模块仍在你自己的允许所有权范围；你被明确授权按本反馈作最小必要修复。共享 API 契约冻结仅防并发冲突，不禁止修 jobs 实现。DELIVERY 列出的 F1/F2/F3/F4 必须修，不能通过把 owner lost/spawn failure 的断言改为500取得通过。请恢复 lost/503 合同断言；NOT NULL input_revision 不能删除，实际终态不能伪造成功。
所有开发仍仅 .coordination/20261014/workspaces/s08-owner 内的 zscope/orchestration/jobs/**、tests/test_scan_jobs.py、tests/test_scan_job_execution.py、本分支证据和DELIVERY。根 backend/共享docs/CLI/Web/static/前端均不改。严禁操作、读取、派发、续发、重试、代做用户保留 task_0947f2854f 调用方一次无通知/受限超时分支；native/async_paths/协议/规则/catalog不动。
请读根 coordination/2026-10-14/S08_REVIEW_PENDING.md（下方也是完整反馈）。依次修 F1 缺input_revision的finish_attempt路径；F2三个mypy错误；F3 zombie/PID身份失效安全判定；F4同一service省略scan_depth时源/头/构建改变必须fresh fingerprint，不可仅config stat缓存授权。追加正反例，保留对新attempt/旧snapshot和幂等的验证。
另修真实当前产品报告格式：write_report_atomic写的是zscope.shared-json.v1对象图，owner._bind_report/service.load_bound_report直接json.loads会把storage envelope当报告并丢questions/coverage/findings。复用正式 read_report/decode_storage，完整拒绝缺引用/错误对象摘要，raw artifact SHA仍是实际文件字节SHA；不要用plain JSON fixture代替当前writer。至少当前writer生成的逻辑报告在owner绑定、result读取后仍保留questions/metadata.build_coverage/coverage_gaps/issues，以及损坏对象图被拒绝。
测试全部WSL Ubuntu /home/zeal/venv313/bin/python，隔离cwd/PYTHONPATH，最多一个pytest，不pip/sharednative/真实LLM/formal，不读凭据。不要把controlled scanner的process测试当完整JOB04/JOB06；session真实stop-new-work/fair remaining-work若尚未接线继续明示pending。本轮优先修可独立交付的owner/store/input/report闭环，提供稳定最终集合JUnit与源码SHA前后、compileall/mypy/Black结论和未跑项。不把原53与新集合累加，不接受以改断言降低原标准。"""
message += "\n\n" + (HERE / "S08_REVIEW_PENDING.md").read_text(encoding="utf-8")
request = {
    "id": "s08-acceptance-repair",
    "branch": "S08-OWNER",
    "tool": "dispatch_task",
    "arguments": {
        "agent": "kimi", "model": "volceapi/kimi-k3", "cwd": str(ROOT),
        "session_id": "sess_4b386346c6", "title": "S08 原会话验收缺陷修复",
        "user_requested": True, "request_id": str(uuid.uuid4()), "message": message,
    },
}
target = HERE / "request-s08-acceptance-repair.json"
with target.open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"request_id": request["arguments"]["request_id"], "request": str(target)}))
