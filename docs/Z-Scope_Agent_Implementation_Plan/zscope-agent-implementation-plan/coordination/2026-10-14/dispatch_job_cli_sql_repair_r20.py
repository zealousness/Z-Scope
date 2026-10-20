"""Count the first actual SQL delivery failure and continue the same work item."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
name = "job-cli-window-r20-sql"

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def call(payload):
    target = route / "bridge-queue" / ("080-" + payload["id"] + ".request.json")
    response = route / ("bridge-response-" + payload["id"] + ".json")
    assert not target.exists() and not response.exists()
    write(target, payload)
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists(), "unknown outcome: inspect the same persisted request, no blind retry"
    return json.loads(response.read_text(encoding="utf-8")), response

path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["bridge_task_id"] == "task_492e7a7037" and row["producer_status"] == "completed"
assert not row["independent_acceptance"] and not row["integrated"]
out = ROOT / "artifacts/coordinator-job-cli-delivery-boundary-r20-preflight-20261015"
review = json.loads((out / "review.json").read_text(encoding="utf-8"))
assert review["task_id"] == row["bridge_task_id"] and review["source_unchanged"] and review["independent_probes_unchanged"]
assert review["junit"]["tests"] == "11" and review["junit"]["failures"] == "3"
assert all(review["junit"][k] == "0" for k in ("errors", "skipped"))
workspace = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
for p, sha in review["delivered_hashes"].items():
    assert hashlib.sha256((workspace / p).read_bytes()).hexdigest() == sha
(out / "producer-delivery.md").write_bytes((workspace / "DELIVERY.md").read_bytes())
agents, _ = call({"id": name + "-agents-preflight", "tool": "list_agents", "arguments": {}})
assert agents["ok"] and agents["coordinator"]["dispatch_enabled"]
sessions, _ = call({"id": name + "-sessions-preflight", "tool": "list_sessions", "arguments": {"active_only": False}})
assert sessions["ok"]
session = next(r for r in sessions["sessions"] if r["session_id"] == "sess_b91680bb39")
assert session["proc_state"] in {"ready", "idle_unloaded"} and session["model"] == row["requested_model"]
message = f"""同一 U01-JOB-CLI-WINDOW-R20 / sess_b91680bb39 / job-cli-window-r20 返修第2轮。task_492e7a7037于21:58:47完整交付/get_result已核实，实际glm-5.3；协调者在停写/无后台后独立11边界为8过3败，无error/skip，原3文件SHA稳定，未验收/未集成。收据 {out}/review.json、command-0.log、results.xml、source-before 与已冻结 producer-delivery.md；这计逻辑工作项第1次实际交付失败，保留已验收父项三轮及当前历史，不换ID重置。你原两窗口+六身份8项已通过并保留，只修新增真实SQL权限缺口。

请先读 Root绝对协调目录 {HERE}/DISPATCH_POLICY.md 和 followups-r12/job-cli-window-r20-coordinator-review.txt，不在副本相对目录找后误说policy不存在。Root协调目录的4个只读探针：test_job_cli_effective_window_boundary.py、test_job_cli_window_identity_boundary.py、test_job_cli_window_snapshot_boundary.py、test_job_cli_window_store_binding_boundary.py。按原样11项先复现，单独新artifact，不能覆盖或修改探针/旧失败。

三败明确：
1) stand_down_reason首次SQL读校验旧owner身份，随后第二次get_job却取换代owner清空的窗口，返回合法None。真实service/SQL/fingerprint正前提通过，受控乐观SQL更新在首次get_job返回前发生；身份和窗口必须来自同一被核验行/版本，或重新核验后拒绝换代。不是用env/JSON自报时间。
2) 原合法SQL行stop_at_epoch变为TEXT 'nan'后仍返回NaN权限值；拒绝非有限/损坏窗口值，不能传播至shared token或当None。有限已过窗口保持正常过期拒绝；合法None仍不fallback config。
3) actual SQLite backup复制完整有效行到目标工程外的另一store，env.store/run_dir指向其布局，但SQL row.run_dir仍是原attempt；当前仅校验env路径布局没有核对行本身目录，复制行竟授权另一目录。此case已在复制后再次核实原store正前提与input fingerprint仍有效，不能以工程内新文件导致fingerprint失效蒙混通过。核对真实行的store/run目录合同，仍支持合法store_root_override，不硬编码工程默认store。

严格只写原3文件（CLI、execution_profile、新tests/test_job_cli_stop_window.py）及本副本artifacts/DELIVERY.md，无扩权。公共token首次原因顺序已由原生Astra /root/astra_first_cause_r20 独占common/cancellation.py与新tests/test_cancellation_first_cause.py处理；你不得改token或旧test、不得join watcher/sleep改写测试以隐藏先观察期限后父取消的真实缺陷。Root确定性token2失败在 artifacts/coordinator-current-first-cause-r20-probes-20261015/review.json；协调者会待Astra独验后只读装入你的副本，再跑完整联合独验。你当前专注SQL权限三败并保留其它回归真实结果。MCP旧revisionConflict自测第一轮失败与同字节第二轮通过保留，不擅改只读旧tests，不宣称已排除任何真实问题。

每次pytest必须WSL Ubuntu zeal /home/zeal/venv313/bin/python，经Root协调test_slot.py --workspace <本Linux副本> -- <argv>，两槽/default fd/ext4、不嵌套。显式 Z_SCOPE_TEST_CLANG_INDEXER=/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer，SHA d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399只读；旧D组1skip不能替代本轮零skip验收。保留原完整各批回归及你的8测试，新增三SQL正反例，compileall zscope scripts test tests / mypy zscope / 累计3修改Python Black全部实际退出码。等待token依赖的原消费者如失败按真实状态交付，不假报全通过；协调者负责装入已验收依赖和最后全独验。

不碰Root/其它副本/owner服务/工具/凭据/旧S06，不commit/push/reset/clean，不绕过平台限制。删除/覆盖临时对照或收据会损失证据，请所有失败与中间态用独立路径保留。交付准确源SHA、时间、原失败及修后结果、未测边界并停止所有后台和写入。"""
(HERE / "followups-r12" / (name + "-message.txt")).write_text(message, encoding="utf-8", newline="\n")
payload = {"id": name, "branch": "job-cli-window-r20", "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": str(ROOT), "title": "U01-JOB-CLI-WINDOW-R20-SQL", "session_id": session["session_id"], "model": session["model"], "user_requested": True, "request_id": str(uuid4()), "message": message}}
write(HERE / "followups-r12" / (name + "-request.json"), payload)
result, receipt = call(payload)
assert result["ok"] and result["model"] == session["model"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
history = {"task_id": "task_492e7a7037", "finished_at": "2026-10-15T21:58:47.250693+08:00", "review": (out / "review.json").relative_to(ROOT).as_posix(), "status": "window_identity8_passed_sql_authority3_failed", "actual_development_delivery": True, "independent_acceptance": False, "integrated": False, "counts_as_glm_actual_delivery_failure": True, "failure_streak_after": 1}
row.setdefault("execution_history", []).append(history)
row.setdefault("glm_delivery_rounds", []).append(history)
row.update(bridge_task_id=result["task_id"], bridge_session_id=result["session_id"], request_id=payload["arguments"]["request_id"], dispatch_evidence=receipt.relative_to(HERE).as_posix(), status="sql_authority_repair_dispatched_execution_pending", producer_status="dispatched", worker_finished_at=None, observed_model=None, artifact_available=False, latest_failed_review=history["review"], consecutive_failed_actual_deliveries=1, checked_at=at)
ledger["updated_at"] = at
write(path, ledger)
print(json.dumps({"at": at, "task_id": result["task_id"], "model": result["model"], "same_logical_work_item": True, "failure_streak": 1}), flush=True)
