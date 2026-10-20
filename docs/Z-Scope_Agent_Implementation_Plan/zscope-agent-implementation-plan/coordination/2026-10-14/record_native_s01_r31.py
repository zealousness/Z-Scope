"""Bind the actual native task and preserve non-product transport failures."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-s01-replacement-r31-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


receipt = read(OUT / "native-dispatch-receipt.json")
assert receipt["actual_producer_task"] == "/root/s01_origin_repair_r31"
assert all(not item["counted_development_failure"] for item in receipt["transport_attempts"])
assert read(OUT / "zcode-session-ended.json")["proc_state"] == "dead"
reconciliation = read(OUT / "protocol-second-workspace-reconciliation.json")
assert reconciliation["all_source_inputs_unchanged"] and reconciliation["no_new_files"]
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == receipt["logical_task"])
assert row["consecutive_failed_actual_deliveries"] == 3 and len(row["glm_delivery_rounds"]) == 3
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row.update(status="native_6_1_xhigh_continuation_spawned_after_two_zcode_protocol_failures_and_bridge_effort_validation_failure_no_product_delivery_yet", owner="Codex native 6.1-sol/xhigh", agent_kind="native_collaboration", actual_task=receipt["actual_producer_task"], requested_model="gpt-6.1-sol", requested_effort="xhigh", bridge_task_id=None, bridge_session_id=None, last_zcode_transport_task_id="task_1948d656f1", last_zcode_transport_session_id="sess_99a5552202", transport_attempts=receipt["transport_attempts"], active_continuation=receipt, dispatch_evidence="artifacts/coordinator-s01-replacement-r31-20261017/native-dispatch-receipt.json", producer_status="spawned_execution_pending", producer_status_source="native_collaboration_spawn_agent", artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, fourth_dispatched=True, fourth_actual_development_delivery_complete=False, new_public_task_interface_available=False, native_task_interface_available=True, checked_at=at)
next_actions = read(OUT / "next-actions.json")
next_actions.update(recorded_at=at, active_new_task_id=receipt["actual_producer_task"], active_new_session_id=None, agent_kind="native_collaboration", old_replacement_zcode_session_dead=True, non_product_transport_errors_retained=3, actual_failed_delivery_count=3, fourth_actual_development_delivery_complete=False)
write(OUT / "next-actions.json", next_actions)
ledger.update(updated_at=at, latest_handoff="artifacts/coordinator-s01-replacement-r31-20261017/native-dispatch-receipt.json", current_root_status="RootR23/StageR30 unchanged; Stage bounded1147 passed/fullmypy4errors remain; native/root/s01_origin_repair_r31 gpt6.1sol/xhigh spawned after two public ZCodeprotocolerrors and Bridge xhighprevalidationerror; old newZCodesessiondead; S01 actualfailure3 retained, no fourth product delivery yet")
for entry in ledger["next_module_tasks"]:
    if entry["id"] == row["id"]:
        entry.update({key: row.get(key) for key in entry})
        entry.update(actual_task=row["actual_task"], agent_kind=row["agent_kind"])
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], next_module_tasks=ledger["next_module_tasks"], latest_next_actions=ledger["latest_next_actions"], whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R31 实际接续入口与调度错误收据

新ZCode公开任务task_09f2148b87于09:40:25终止，核对公开终态、ready/turns0会话、0tools及所有文件后，同会话一次重试task_1948d656f1于09:42:08仍session/prompt Internal protocol_error、0tools/0files。两次完整get_result/transcript和新1072/原1072/Root1065/Stage967摘要及无新增文件证明分开保留。该新会话sess_99a5552202已通过公开end_session标记dead，未重启Bridge。

公开Bridge Codex入口在task创建前拒绝effort=xhigh（ValueError，允许off/low/medium/high/max），未产生Codex task/session。未将参数错误或两次协议错误计为第四次开发交付失败；未宣称质量升级阈值达到。公开回执未报告平台审批拒绝，若后续出现审批拒绝仍立即停止受影响操作，不换路由规避。

按用户既有复杂任务6.1-sol/xhigh与当前新开接续任务授权，实际新任务为 /root/s01_origin_repair_r31（native_collaboration，gpt-6.1-sol/xhigh）。独占原R31新隔离目录的2个许可源/测试文件与交付产物，1070依赖、原目录、Root、Stage只读；NATIVE_HANDOFF.md覆盖执行入口，原源码/验证义务全部保留。当前只记已派发，尚未确认产品执行、交付、独验、集成或联合通过；S01真实失败计数3和原两个P1仍保留，不因入口/ID改变而归零。

RootR23与StageR30没有本轮产品集成，Stage原1147有界回归与完整mypy4错误/退出1保持原范围。S08、消费端和Store已验收切片未重派；完整工作包、真实项目效果、条件扩展和外部等待未完成。最终入口收据 artifacts/coordinator-s01-replacement-r31-20261017/native-dispatch-receipt.json；全部原始请求、响应、终态、重试决策、workspace核对、source-review与入口交接文件同目录保留。

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R31.md").write_text(note, encoding="utf-8", newline="\n")
print(json.dumps(dict(recorded_at=at, actual_task=row["actual_task"], failed_development_count=3, native_task_spawned=True)))
