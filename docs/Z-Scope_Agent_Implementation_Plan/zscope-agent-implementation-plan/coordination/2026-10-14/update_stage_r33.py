"""Record actual isolated repair dispatches without resetting prior histories."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

now = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
prep = read(OUT / "preparation.json")
specs = [
    ("STAGE-CURRENTNESS-REPAIR-R33", "/root/stage_currentness_repair_r33", "stage-currentness-repair-r33", "STAGE-R32-P1-01"),
    ("STAGE-COST-REPAIR-R33", "/root/stage_cost_repair_r33", "stage-cost-repair-r33", "STAGE-R32-P2-02 and parallel_analyzer:492 no-any-return"),
]
rows = []
for logical, actual, workspace, finding in specs:
    row = dict(id=logical, owner="Codex native 6.1-sol/xhigh", actual_task_id=actual, requested_model="gpt-6.1-sol", requested_effort="xhigh", transport="native_collaboration", bridge_task_id=None, status="dispatched_isolated_probe_before_repair_execution_not_yet_confirmed", depends_on=["COORD-INSTANCE-INTEGRATION-R24"], superseding_shared_finding=finding, workspace=prep["candidates"][workspace]["workspace"], write_paths=prep["candidates"][workspace]["owned_paths"], dispatched=True, execution_confirmed=False, artifact_delivered=False, independent_acceptance=False, stage_intake=False, integrated=False, joint_validation_passed=False, dispatched_at=now, actual_failed_deliveries=0, prior_s01_failed_deliveries_unchanged=3, prior_s01_bounded_module_acceptance_unchanged=True, root_intake=False)
    rows.append(row)
    write(HERE / "followups-r12" / (workspace + "-ownership.json"), row | dict(baseline_receipt="artifacts/coordinator-stage-repairs-r33-20261017/preparation.json", readonly_baseline=prep["candidates"][workspace], root_and_stage_coordinator_only=True))
dispatch = dict(observed_at=now, actual_task="/root", public_bridge_readonly="artifacts/coordinator-stage-repairs-r33-20261017/bridge-readonly.json", public_bridge_current_session_dead=True, no_services_started=True, no_private_rpc_or_direct_worker_cli=True, no_platform_denial_in_current_dispatch=True, preparations_sha256=sha(OUT / "preparation.json"), source_review_blocked="artifacts/stage-integration-source-review-r32-20261017/review.json", source_review_sha256=sha(ROOT / "artifacts/stage-integration-source-review-r32-20261017/review.json"), active_repairs=rows, root_intake=False)
write(OUT / "dispatch-receipt.json", dispatch)
task_path = HERE / "tasks.json"
tasks = read(task_path)
by_id = {row["id"]: row for row in tasks["tasks"]}
for row in rows:
    assert row["id"] not in by_id
    tasks["tasks"].append(row)
coordinator = by_id["COORD-INSTANCE-INTEGRATION-R24"]
coordinator.update(status="stage_r32_shared_source_review_blocked_two_findings_full_mypy_one_error_joint_execution_pending_isolated_repairs_dispatched_r33", current_stage_revalidation_required=True, full_stage_quality_passed=False, bounded_stage_regression_passed=False, shared_stage_source_review_passed=False, current_shared_blockers=[spec[3] for spec in specs], current_stage_joint_receipt="artifacts/coordinator-stage-joint-r32-20261017/review.json", current_stage_joint_receipt_pending=True, latest_parallel_dispatch="artifacts/coordinator-stage-repairs-r33-20261017/dispatch-receipt.json", integrated=False, independent_acceptance=False, joint_validation_passed=False)
tasks["updated_at"] = now
write(task_path, tasks)
continuation_path = HERE / "continuation-r6.json"
continuation = read(continuation_path)
continuation.update(updated_at=now, current_round="R33", active_phase="isolated_shared_currentness_and_cost_probes_repairs_while_r32_union_finishes", latest_observation=dispatch, active_tasks=[row["actual_task_id"] for row in rows], original_bridge_owner_available=False, service_restart_forbidden=True, next_root_intake_performed=False, whole_packages_complete=False, current_state_note="CURRENT_STATE_R33.md", latest_handoff="artifacts/coordinator-stage-repairs-r33-20261017/dispatch-receipt.json")
write(continuation_path, continuation)
note = f"""## {now} · R32 Stage 待修与 R33 隔离并行

用户已授权原 Bridge 公开访问阻塞时新开任务接续未完成范围。原第四轮接续实际任务 /root/s01_origin_repair_r31 已冻结；协调者 R32 独验209项、独立进程R24四项及六命令均通过，有界S01模块已于10:26:18+08接入Stage，未接入Root。历史S01三次失败原样保留，有界模块接纳后的连续失败归零只适用于该模块。

Stage当前969输入的198文件联合回归正在执行，normal/fresh完整mypy各有同一处parallel_analyzer.py:492 no-any-return，原4项import-untyped消失。共享源审R32（实际/root/consumer_source_review_r28，10:39:06+08冻结）提出P1工具/loader/物理标准安装可信状态消费时未复核、P2恢复历史cost混入本轮。源审阻断收据与初始收据保留；这些属于共享Stage新缺口，不回撤S01有界模块接纳。当前不能宣布Stage或Root联合通过。

实际新隔离任务 /root/stage_currentness_repair_r33 与 /root/stage_cost_repair_r33 均指定gpt-6.1-sol/xhigh，先真实native失败探针再修复；分别拥有Context文件及新测试、ParallelAnalyzer文件及新测试，无共享产品写入。969输入从冻结40差异与929 Root不变文件重建，不从正在测试的Stage复制产品。派发不等于已执行/交付/独验/集成，详见dispatch-receipt.json与两份ownership。当前public Bridge只读会话sess_99a5552202为dead/turns0，未启动任何服务、未恢复旧S06-R02。

Root1065输入与最后Root R23 2551项/sixcommands0的原结论保留；新Stage实际结果不能由旧结果替代。S08 codec、Store和消费端既有接纳切片未重派；Astra前端/UI分工及已有收据保留。完整S01/S08/U01、真实项目/LLM效果、跨TU/其他协议、formal及条件扩展/外部等待仍分别未完成。

证据：artifacts/coordinator-s01-independent-r32-20261017/review.json；artifacts/s01-stage-intake-r32-20261017/receipt.json；artifacts/stage-integration-source-review-r32-20261017/review.json；artifacts/coordinator-stage-joint-r32-20261017/；artifacts/coordinator-stage-repairs-r33-20261017/dispatch-receipt.json。
"""
(HERE / "CURRENT_STATE_R33.md").write_text(note, encoding="utf-8", newline="\n")
for path in (HERE / "PROGRESS.md", HERE / "DAG.md"):
    old = path.read_text(encoding="utf-8")
    path.write_text(note + "\n---\n\n" + old, encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "dispatch-receipt.json").relative_to(ROOT).as_posix(), updated_at=now, root_intake=False)))
