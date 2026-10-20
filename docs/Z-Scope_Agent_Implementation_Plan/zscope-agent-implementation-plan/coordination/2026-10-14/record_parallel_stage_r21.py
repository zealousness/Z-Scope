"""Record real UI start and preserve the two design deliveries needing correction."""
from pathlib import Path
import datetime as dt
import hashlib
import json
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
def read(p):
    return json.loads(p.read_text(encoding="utf-8"))
def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
root_source = read(ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / p) == h for p, h in root_source.items())
base = read(HERE / "followups-r12/astra-stop-coverage-ux-r21-baseline.json")
dep = read(HERE / "followups-r12/astra-stop-coverage-ux-r21-dependencies.json")
branch = ROOT / ".coordination/20261014/workspaces/astra-stop-coverage-ux-r21"
start_path = branch / "artifacts/stop-coverage-ux-r21/execution-start.json"
start = read(start_path)
assert start["logical_task"] == "ASTRA-STOP-COVERAGE-UX-R21" and start["actual_task"] == "/root/astra_instance_ui_r18"
assert all(sha(branch / r["path"]) == r["sha256"] for r in dep["files"])
assert "ASTRA-STOP-COVERAGE-UX-R21" not in rows
ledger["tasks"].append({**base["task"], "agent_kind": "native_subagent", "agent_task_id": "/root/astra_instance_ui_r18", "accepted_model": "gpt-6-astra", "reasoning_effort": "xhigh", "status": "actual_ui_execution_readonly_dependencies_verified_delivery_pending", "producer_status": "running", "dispatch_recorded_at": at, "actual_execution_at": start["started_at"], "execution_evidence": start_path.relative_to(ROOT).as_posix(), "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "checked_at": at})
base.update(dispatch_state="native_dispatched_actual_execution_observed", actual_task_id="/root/astra_instance_ui_r18", actual_execution_at=start["started_at"], execution_evidence=start_path.relative_to(ROOT).as_posix())
write(HERE / "followups-r12/astra-stop-coverage-ux-r21-baseline.json", base)
out = ROOT / "artifacts/readonly-design-review-r21-20261016"
out.mkdir(exist_ok=False)
specs = [
    ("S01-INSTANCE-MODELING-DESIGN-R21", "s01-instance-modeling-design-r21", "instance-modeling-design-r21", [
        "S01-A proposes inferred rows whose build_context_id is empty. Unknown inferred build is not a wildcard; require exact known build/USR and current checked publication/consumer receipts, or conservatively exclude/defer. Manual/builtin name-level rows must be separated from inferred authorization.",
        "F8 cites build_scope.py:570-578, but _in_scope is in contracts.py:570. Correct citations and recheck every claimed call path.",
        "Provide explicit recomputed source_hashes_after rather than only an equality note. The reported started_at precedes actual Bridge dispatch; use public worker/tool observation times and distinguish the revision audit interval."
    ]),
    ("S08-PARTIAL-RECOVERY-DESIGN-R21", "s08-partial-recovery-design-r21", "partial-recovery-design-r21", [
        "N4 must not claim absence of starvation from per-queue bounded attempts. Fresh per-run queues and repeated stop/reanalysis can leave late instances unserved across runs; distinguish finite one-queue retries from unverified cross-run/continuous-batch fairness. This is a design boundary, not a newly reproduced product bug.",
        "started_at and finished_at are both 01:20:01 although the public worker ran 01:13:43 through 01:22:27. Correct timestamp meaning and retain public worker execution evidence; do not fabricate an analysis start time."
    ])
]
summaries = []
for identity, name, artifact, findings in specs:
    row = rows[identity]
    assert row["producer_status"] == "completed" and not row["independent_acceptance"]
    ws = ROOT / ".coordination/20261014/workspaces" / name
    baseline = read(HERE / "followups-r12" / (name + "-baseline.json"))
    assert all(sha(ws / r["path"]) == r["sha256"] for r in baseline["files"])
    frozen = out / name
    frozen.mkdir()
    source_paths = {"DELIVERY.md": ws / "DELIVERY.md", "audit.json": ws / "artifacts" / artifact / "audit.json"}
    original_hashes = {}
    for label, source_path in source_paths.items():
        original_hashes[label] = sha(source_path)
        (frozen / label).write_bytes(source_path.read_bytes())
        assert sha(frozen / label) == original_hashes[label]
    review = {"logical_task": identity, "actual_bridge_task_id": row["bridge_task_id"], "actual_bridge_session_id": row["bridge_session_id"], "reviewed_at": at, "public_worker_started_at": row["worker_process_started_at"], "first_actual_tool_observed_at": row["actual_tool_execution_observed_at"], "public_worker_finished_at": row["worker_finished_at"], "original_hashes": original_hashes, "source_inputs": len(baseline["files"]), "source_inputs_unchanged": True, "source_review_passed": False, "blocking_findings": findings, "tests_executed": 0, "independent_acceptance": False, "integrated": False, "joint_verification": False, "development_failure_counter_incremented": False, "scope": "Readonly design delivery correction; no product implementation failure or package acceptance"}
    write(frozen / "review.json", review)
    row.update(status="readonly_design_delivery_changes_requested_original_frozen", artifact_available=True, design_review_status="changes_requested", design_review_evidence=(frozen / "review.json").relative_to(ROOT).as_posix(), design_review_blocking_findings=findings, checked_at=at)
    row.setdefault("design_delivery_history", []).append({"task_id": row["bridge_task_id"], "session_id": row["bridge_session_id"], "finished_at": row["worker_finished_at"], "original_hashes": original_hashes, "review": row["design_review_evidence"]})
    message = f"同一逻辑只读设计任务 {identity} 的第1次审查修订，保留原 task/session 与全部历史。只在原隔离副本 {ws} 工作，模型仍固定 glm-5.3。原 DELIVERY.md 和 artifacts/{artifact}/audit.json 已冻结，不得覆盖；只可新增 artifacts/{artifact}/revision-1/DELIVERY.md 与 audit.json。所有产品/旧测试/文档/native/配置/Root仍只读，不运行测试、扫描、服务、Bridge或native，不改平台/凭据/环境/时钟，不操作旧S06、不reset/clean/commit/push。初版审查收据 {frozen / 'review.json'}，请完整读取并逐项修正以下设计/证据问题：\n" + "\n".join(findings) + "\n保留所有已确认能力/缺口/非缺陷和未完成范围；更正设计不能通过删除保护或把未知构建当通配符解决。逐项给源码路径/实际行/SHA/调用与消费链，重新计算显式before/after SHA，记录真实本修订起止时间。原任务公开进程开始/结束与首次工具观测见审查收据，不能把snapshot捕获时间冒充实际开始；未知准确时间标unknown。这是只读设计修订，不是功能实现/整包/真实项目验收，不冒记产品开发失败。完成停止写入。"
    payload = {"id": name + "-revision-1", "branch": name, "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": r"C:\Users\10273\home\work\Z-Scope_1.31\Z-Scope", "title": identity + " revision-1", "session_id": row["bridge_session_id"], "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "user_requested": True, "request_id": str(uuid4()), "message": message}}
    write(HERE / "followups-r12" / (name + "-revision-1-request.json"), payload)
    summaries.append({"logical_task": identity, "original_task_id": row["bridge_task_id"], "producer_finished_at": row["worker_finished_at"], "artifact_available": True, "independent_acceptance": False, "review_status": "changes_requested", "revision_dispatched": False})
rows = {r["id"]: r for r in ledger["tasks"]}
pending, done, layers = set(rows), set(), []
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
ledger.update(updated_at=at, topological_layers=layers)
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase="R22 selected union passed and Root unchanged; Astra UI actual execution; two readonly design originals completed and frozen with corrections requested", native_active_ui={"logical_task": "ASTRA-STOP-COVERAGE-UX-R21", "actual_task_id": "/root/astra_instance_ui_r18", "actual_execution_at": start["started_at"], "execution_evidence": start_path.relative_to(ROOT).as_posix()}, readonly_design_reviews=summaries)
write(HERE / "continuation-r6.json", continuation)
print(json.dumps({"at": at, "ui_actual_start": start["started_at"], "root_1056_unchanged": True, "design_reviews": summaries}), flush=True)
