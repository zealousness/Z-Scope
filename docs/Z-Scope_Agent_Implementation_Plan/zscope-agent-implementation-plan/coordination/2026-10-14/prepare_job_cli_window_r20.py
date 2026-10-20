"""Freeze the additional Job-to-CLI window obligation and use the existing owner."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys
import time
from uuid import uuid4

sys.stdout.reconfigure(encoding="utf-8")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
name = "job-cli-window-r20"
identity = "U01-JOB-CLI-WINDOW-R20"
model = "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def call(payload):
    request = route / "bridge-queue" / ("080-" + payload["id"] + ".request.json")
    response = route / ("bridge-response-" + payload["id"] + ".json")
    assert not request.exists() and not response.exists()
    write(request, payload)
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists(), "unknown outcome; inspect the same request receipt before retry"
    return json.loads(response.read_text(encoding="utf-8")), response

agents, agents_path = call({"id": name + "-agents-preflight", "tool": "list_agents", "arguments": {}})
assert agents["ok"] and agents["coordinator"]["dispatch_enabled"]
sessions, sessions_path = call({"id": name + "-sessions-preflight", "tool": "list_sessions", "arguments": {"active_only": False}})
assert sessions["ok"]
session = next(r for r in sessions["sessions"] if r["session_id"] == "sess_b91680bb39")
assert session["proc_state"] in {"ready", "idle_unloaded"} and session["model"] == model
assert not any(r.get("proc_state") in {"busy", "running"} and str(ROOT).lower() in str(r.get("cwd", "")).lower() for r in sessions["sessions"])

review_path = ROOT / "artifacts/coordinator-current-job-cli-window-r20-corrected-probes-20261015/review.json"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert review["source_unchanged"] and review["junit"]["tests"] == review["junit"]["failures"] == "2"
source = review["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in source.items())
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
assert not any(r["id"] == identity for r in ledger["tasks"])
assert all(next(r for r in ledger["tasks"] if r["id"] == p)["independent_acceptance"] for p in ("VALIDATION-CONTEXT-R18", "U01-STOP-AT-R18", "S07-NATIVE-HOT-R19"))
workspace = ROOT / ".coordination/20261014/workspaces" / name
workspace.mkdir(exist_ok=False)
for p, sha in source.items():
    target = workspace / p
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / p, target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
owns = ["zscope/cli/cli.py", "zscope/orchestration/execution_profile.py", "tests/test_job_cli_stop_window.py"]
task = {"id": identity, "workspace": name, "owner": "zcode", "write_paths": owns, "owns": owns, "depends_on": ["U01-STOP-AT-R18"], "parent_work_item": "U01-STOP-AT-R18", "scope": "Additional real persisted owner/CLI effective-window consumption; retain the accepted parent slice", "requested_model": model, "isolated_workspace": str(workspace), "isolated_workspace_linux": "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/.coordination/20261014/workspaces/" + name}
baseline = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task": task, "files": [{"path": p, "sha256": sha} for p, sha in sorted(source.items())], "root_changed": False, "failing_probe": review_path.relative_to(ROOT).as_posix(), "agent_preflight": agents_path.relative_to(HERE).as_posix(), "session_preflight": sessions_path.relative_to(HERE).as_posix()}
write(HERE / "followups-r12" / (name + "-baseline.json"), baseline)
message = f"""ZCode glm-5.3，新增实际消费端集成义务 {identity}，保持已独验并导入的三个切片，不重做其开发。沿用当前空闲 sess_b91680bb39，工作目录只在隔离副本 {workspace}，Linux {task['isolated_workspace_linux']}。Root 当前联合回归仍在运行，绝对不能改 Root 或其他副本。

协调者21:21:38真实执行的两探针均失败，源码1035项前后一致：{review_path.parent}。显式请求已正确落SQL epoch，但真实CLI共享token预算却取配置00:00下次午夜；resume真实失败attempt后SQL清空stop_at_epoch，CLI仍再次套配置窗口。探针 followups-r12/test_job_cli_effective_window_boundary.py 在Root协调目录只读，原文件在失败artifact冻结，只控制分析run体，service/detached owner/CLI/真实ScanSessionRunner与token不替换。第一版探针原第二项exit1是成功finding导致resume409，已明确无效fixture；不要计作产品失败。以corrected两项为原样回放基准。原00:00并非过期，初次HHMM解析会取下次发生；已经解析的绝对窗口过期才不得roll。

只允许写这3路径：{owns}；DELIVERY.md和本副本artifacts可写。owner/store/service/scheduler_hook/scan_session/其它源码/旧tests/文档/native/工具只读；确需额外产品路径先提出具体契约与理由，协调者审查后才扩权。可读现有jobs/scheduler_hook.py session_job_context_from_env与真实SQL绑定接口，复用当前job/run/owner/input/run_dir校验。有效owner绑定时，SQL持久窗口是唯一有效预算来源，包括合法None（resume清空后不fallback配置）。不能通过自报JSON/env时间当权威，不能接受错store/job/run/owner/input或不完整伪造环境；无owner的独立CLI继续config一次解析预算。过期已解析窗口拒绝/结束，不能roll；与已有更早期限/父取消/显式取消保持真实原因及tighten-only共享token。不要更换token、写假flag、隐藏异常、宽松unknown或关掉guard过测。

先原样复现corrected两失败并留不同文件收据；然后修复并增加真实owner显式/config/resume、standalone、身份不匹配/部分env/过期等正反例。保留原35stop消费者、共享预算HTTP2、原因2和相邻jobs/CLI/MCP/v2/v3回归。测试必须WSL Ubuntu zeal /home/zeal/venv313/bin/python，经Root协调目录test_slot.py --workspace <本Linux副本> -- <argv> 两共享槽/default fd/ext4临时目录，不能嵌套槽。native只读SHA d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399。完整compileall -f -q zscope scripts test tests、mypy zscope、所有累计修改Python Black --check，完整退出码/JUnit/源SHA/时间；失败原样保留且每次artifact独立，不能覆盖before/after。协调者后续独验和Root集成。

当前路由政策 DISPATCH_POLICY.md 适用，新增消费义务保留父项与历史，不借ID隐藏同一义务连续失败。不得操作旧S06-R02/创建重复Bridge/更改凭据或服务/commit push reset clean。平台拦截停止并报告，不换路由规避。完成后交付准确范围/未测/路径SHA/真实收据并停止所有后台、停止写入，等待协调者独验。不要宣称全U01/S08或真实项目效果完成。
"""
(HERE / "followups-r12" / (name + "-message.txt")).write_text(message, encoding="utf-8", newline="\n")
payload = {"id": name, "branch": name, "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": str(ROOT), "title": identity, "session_id": session["session_id"], "model": model, "user_requested": True, "request_id": str(uuid4()), "message": message}}
write(HERE / "followups-r12" / (name + "-request.json"), payload)
result, receipt = call(payload)
assert result["ok"] and result["model"] == model
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
ledger["tasks"].append({**task, "bridge_task_id": result["task_id"], "bridge_session_id": result["session_id"], "request_id": payload["arguments"]["request_id"], "dispatch_evidence": receipt.relative_to(HERE).as_posix(), "baseline_receipt": "followups-r12/" + name + "-baseline.json", "status": "dispatched_execution_pending", "independent_acceptance": False, "integrated": False, "joint_verification": False, "artifact_available": False, "whole_package_complete": False, "checked_at": at, "glm_delivery_rounds": [], "consecutive_failed_actual_deliveries": 0})
ledger["updated_at"] = at
write(ledger_path, ledger)
print(json.dumps({"task_id": result["task_id"], "session_id": result["session_id"], "model": result["model"], "workspace": str(workspace), "source_inputs": len(source), "receipt": receipt.relative_to(HERE).as_posix(), "dispatched_at": at}), flush=True)
