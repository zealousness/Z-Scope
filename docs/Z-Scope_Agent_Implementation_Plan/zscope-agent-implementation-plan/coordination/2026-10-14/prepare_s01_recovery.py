"""Preserve a failed independent branch and prepare explicitly authorized recovery."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import uuid

from dispatch_safety import DispatchJournal

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
isolate = ROOT / ".coordination/20261014/workspaces/s01-instances"
state = json.loads((HERE / "bridge-response-now-s01.json").read_text(encoding="utf-8"))
assert state["task_id"] == "task_f709895aa3"
assert state["status"] == "failed" and state["stop_reason"] == "stalled"
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
changes = []
fingerprints = []
for item in baseline["files"]:
    path = isolate / item["path"]
    if not path.is_file():
        changes.append({"path": item["path"], "missing": True})
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != item["sha256"]:
        changes.append({"path": item["path"], "sha256": digest})
    fingerprints.append({"path": item["path"], "sha256": digest, "mtime_ns": path.stat().st_mtime_ns})
if changes:
    raise RuntimeError("isolated partial changes require manual review before transfer: " + repr(changes))
owned = ["zscope/orchestration/scan_session.py", "zscope/orchestration/global_modeler.py",
         "zscope/retrieval/code_index.py", "zscope/retrieval/indexing_inventory.py"]
preserve = HERE / "s01-failure-checkpoint"
preserve.mkdir(exist_ok=True)
for name in owned:
    target = preserve / name
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = (isolate / name).read_bytes()
    if target.exists() and target.read_bytes() != raw:
        raise RuntimeError("checkpoint already contains different bytes")
    if not target.exists():
        target.write_bytes(raw)
evidence = {
    "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "prior_task": state["task_id"], "prior_session": state["session_id"],
    "status": state["status"], "stop_reason": state["stop_reason"], "error": state["error"],
    "all_baseline_files_unchanged": True, "baseline_file_count": len(fingerprints),
    "owned_checkpoint": owned, "new_all_variant_test_exists": (isolate / "tests/test_all_variant_scan.py").exists(),
    "process_evidence": "Diagnostic formal host readonly check: old S01 PID99896 absent; no coordinator cancel/restart; exact public terminal receipt retained.",
    "authorization": "Parent 01a11e1c 2026-10-14: preserve products, verify no active writes, assess ordinary Kimi retry or independent ZCode same-route recovery; no permissions or reserved branch changes.",
    "files": fingerprints,
}
checkpoint = HERE / "s01-failure-checkpoint.json"
with checkpoint.open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
journal = DispatchJournal(HERE / "dispatch-journal.sqlite")
try:
    prior_id = "f1a6d415-565d-4701-9272-dc0681b10a28"
    old = journal.db.execute("SELECT state,task_id FROM requests WHERE id=?", (prior_id,)).fetchone()
    if old and old[0] in {"queued", "pending"}:
        journal.accepted(prior_id, state["task_id"])
        old = ("accepted", state["task_id"])
    if old == ("accepted", state["task_id"]):
        journal.terminal(state["task_id"], "failed")
    elif old != ("failed", state["task_id"]):
        raise RuntimeError("prior task release does not match exact failed receipt")
finally:
    journal.close()

message = """用户父任务本次明确授权 S01 独立开发的普通故障恢复：Kimi task_f709895aa3 已公开failed/stop_reason=stalled（1800秒无ACP输出，Bridge自动取消turn），旧PID99896已由正式宿主只读核实不存在。原native证据含API超时重试，不是内容/权限拒绝。协调者保全了产物与回执，931隔离继承文件仍逐字节等于dirty基线，没有test_all_variant_scan.py，没有活动写入。选择你原hw/glm-5.3正常路由接续该独立分支，不改任何权限/配置/provider，不操作旧Kimi/session，不处理任何保留分支。出现新平台/权限/内容拒绝即停报告，不能换会话或模型绕过。
Bridge cwd 为原项目根；实际所有开发仅 .coordination/20261014/workspaces/s01-instances（Linux /mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/.coordination/20261014/workspaces/s01-instances）。它是当前dirty基线快照不是HEAD，SHA41d9c25a0e259457164b68191ed6d797b5d7e1e5a8b748b501fd79df37deabd1。不要改根checkout或其他隔离目录。先读隔离AGENTS、architecture、计划11/16/21/22与根coordination API_CONTRACT，用最新验收覆盖旧待办。不要重复全仓盘点，先落小可执行切片。
所有权仅 zscope/orchestration/scan_session.py、global_modeler.py、zscope/retrieval/code_index.py、indexing_inventory.py、tests/test_all_variant_scan.py、必要的极小新内部instance helper（先在DELIVERY记录所有权）和本分支DELIVERY/artifacts。不能改Web/static、任何前端/UX/Astra测试（全部Astra亲自开发），也不能改native/async_paths/lifecycle/protocol/规则/catalog或相应测试、README/模块/21共享文档。严禁读取/派发/续发/改写/重试/代做用户保留 task_0947f2854f 的调用方一次无通知/受限超时分支；完整同一受限分支都排除。
优先实现入口显式编译实例枚举与真正调度边界：复用 CodeIndex.get_build_contexts + get_function_program_facts(..., build_context_id=...)，每个精确BuildContext/USR为独立实例，未知不是通配符，不允许首命令/首context回落。相同源不同宏变体分别查询事实/独立分析调度，完全相同实例才去重；单变体失败/无entry/未知必须coverage gap，不授予其他变体也不显示覆盖完成。若完整Analyzer scope贯穿无法本切片闭合，明确剩余接线，不用枚举测试冒充完整S01。不要降低原验收标准以方便交付。
正反例至少两宏变体分别且仅一次事实查询/调度，相同实例去重，单变体失败保持精确缺口与未完成。优先生产真实调用路径，test double只代外部native/模型，不把控制fixture宣称全量native扫描通过。必要最小参数接线，保留用户所有未提交修改，不reset/clean/stash/commit/push，不访问凭据或改项目外文件。
测试和质量仅WSL Ubuntu /home/zeal/venv313/bin/python，隔离cwd和PYTHONPATH，不pip改共享venv安装，不重编任何native、不formal/真实LLM/Range、不并发大回归，最多一个pytest。定向测试并给JUnit、稳定源码SHA、compileall/mypy/必要Black和DELIVERY，清楚pass/fail/skip与未跑项。首个小切片完成即可结束，协调者验收后再解锁后续。
"""
request = {"id": "s01-zcode-recovery", "branch": "S01-INST", "tool": "dispatch_task", "arguments": {
    "agent": "zcode", "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",
    "cwd": str(ROOT), "title": "S01 独立编译实例切片故障接续", "user_requested": True,
    "request_id": str(uuid.uuid4()), "message": message,
}}
target = HERE / "route-check/bridge-queue/026-s01-zcode-recovery.request.json"
with target.open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"request_id": request["arguments"]["request_id"], "checkpoint": str(checkpoint), "request": str(target)}))
