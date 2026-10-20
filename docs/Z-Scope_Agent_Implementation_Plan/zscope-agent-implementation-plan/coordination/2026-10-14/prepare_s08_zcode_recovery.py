"""Transfer only after exact cancellation and stable preserved S08 bytes."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import uuid

from dispatch_safety import DispatchJournal

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
state = json.loads((HERE / "bridge-response-s08-api-stop-state.json").read_text(encoding="utf-8"))
assert state["task_id"] == "task_f2a4721a58" and state["status"] == "cancelled"
assert state.get("error") is None and state.get("failure") is None
checkpoint = json.loads((HERE / "s08-api-failure-checkpoint.json").read_text(encoding="utf-8"))
source = ROOT / ".coordination/20261014/workspaces/s08-owner"
for item in checkpoint["files"]:
    path = source / item["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], "post-stop partial change: " + item["path"]
    assert path.stat().st_mtime_ns == item["mtime_ns"], "post-stop write observed: " + item["path"]
stable = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "prior_task": state["task_id"],
          "prior_status": state["status"], "checkpoint_files": len(checkpoint["files"]),
          "post_stop_bytes_and_mtimes_unchanged": True, "no_new_dispatch_before_this_check": True}
with (HERE / "s08-post-stop-stability.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(stable, indent=2) + "\n")
journal = DispatchJournal(HERE / "dispatch-journal.sqlite")
try:
    prior_id = "be60bf21-c103-4977-bc8a-9626f43a47cb"
    old = journal.db.execute("SELECT state,task_id FROM requests WHERE id=?", (prior_id,)).fetchone()
    if old and old[0] in {"queued", "pending"}:
        journal.accepted(prior_id, state["task_id"])
        old = ("accepted", state["task_id"])
    if old == ("accepted", state["task_id"]):
        journal.terminal(state["task_id"], "cancelled")
    elif old != ("cancelled", state["task_id"]):
        raise RuntimeError("prior cancellation does not release exact owned request")
finally:
    journal.close()

message = """用户明确要求Kimi反复API故障时普通恢复转交ZCode，父任务允许S08保全修改、正常停止旧任务后接续。旧首次task_24c156da37虽completed却有已确认F1/F2/F3/F4缺陷和降级断言，未验收；修复turn task_f2a4721a58两次APIEmptyResponseError（06:41:22Z/06:52:50Z，区别于此前APITimeoutError），无修复落盘，已公开cancelled/error=null。13个code/tests/DELIVERY保全，终态后SHA+mtime完全不变，无活动写入。本恢复不是内容/权限拒绝后重试，不改provider/model配置、权限、Bridge或旧Kimi进程；发现新的真实拒绝即停准确报告，不能换会话规避。
你的Bridge cwd原根；实际只写 .coordination/20261014/workspaces/s08-owner 的 zscope/orchestration/jobs/**、tests/test_scan_jobs.py、tests/test_scan_job_execution.py、本分支DELIVERY/artifacts。复用全部10个现有jobs模块与两个测试，8模块不冻结，最小必要增量修复授权明确。不要重写根checkout/backend/Web/CLI/shared docs或其他隔离目录；所有前端/用户体验和Astra测试只能Astra亲自开发，你不能实施。严禁读取/操作/派发/续发/重试/改写/代做task_0947f2854f及同一用户保留caller一次无通知/受限超时分支；native、async_paths、lifecycle/protocol、规则/catalog和它们的测试不动。不reset/clean/stash/commit/push，不改工作区外文件或访问凭据。
读隔离AGENTS、原DELIVERY和根coordination/2026-10-14/API_CONTRACT、S08_REVIEW_PENDING.md，先直接修确认缺陷，不重新大盘点。必修：F1 store.finish_attempt在lost/PID失效/spawn失败路径缺input_revision造成NOT NULL IntegrityError/500，保留约束并持久化真实lost状态，启动失败遵守503；恢复此前被改为接受500的原验收断言。F2三个mypy类型错误，不能用宽泛ignore。F3 zombie和精确PID启动身份失效判定，不误杀PID重用进程。F4同一ScanJobService省略scan_depth时源/头/构建变化要fresh fingerprint，不能用config stat缓存授予attempt输入。真实write_report_atomic始终shared-json.v1对象图，owner._bind_report/load_bound_report必须正式read_report/decode_storage全校验，保留questions/coverage_gaps/metadata.build_coverage/issues，原始工件SHA不变，缺引用/错误对象摘要拒绝。每项实际正反例，不能plain JSON假writer掩盖现格式。
ScanJobService start/list/detail/events/cancel/resume/result遵守冻结envelope，一份SQLite状态真源、revision/request_id幂等、同工程互斥、own进程组/身份/attempt输入、崩溃lost而非伪完成、当前attempt报告绑定；未知计数null、真实缺口与pending明确。JOB04 stop-new-work/有限收尾、JOB06公平remaining队列尚未接scan_session，保留pending，kill scanner不冒充完整时窗验收；session接线由协调owner后续负责。
测试仅WSL Ubuntu /home/zeal/venv313/bin/python，隔离cwd/PYTHONPATH，最多一pytest；不用Windows形成结论，不pip改共享venv、不重编native、不真实LLM/formal/Range，不改共享测试状态。两类测试合并在稳定最终字节下跑，报告JUnit/SHA/compileall/mypy/必要Black及未跑项，不与旧53/36累加，不降低原验收标准。先交可独立验证的修复完成的owner/store/input/report闭环，root真实HTTP/浏览器由协调者/Astra后续接线，不自行改他们的文件。
"""
message += "\n\n" + (HERE / "S08_REVIEW_PENDING.md").read_text(encoding="utf-8")
request = {"id": "s08-zcode-api-recovery", "branch": "S08-OWNER", "tool": "dispatch_task", "arguments": {
    "agent": "zcode", "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",
    "cwd": str(ROOT), "title": "S08 API故障后原产物验收修复", "user_requested": True,
    "request_id": str(uuid.uuid4()), "message": message,
}}
with (HERE / "route-check/bridge-queue/031-s08-zcode-api-recovery.request.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"request_id": request["arguments"]["request_id"], "prior_task": state["task_id"], "checkpoint_files": len(checkpoint["files"])}))
