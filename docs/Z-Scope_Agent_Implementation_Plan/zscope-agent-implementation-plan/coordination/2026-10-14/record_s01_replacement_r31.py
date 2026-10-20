"""Record the new public task without resetting the original logical history."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-s01-replacement-r31-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


prep = read(OUT / "preparation.json")
dispatch = read(OUT / "dispatch-response.json")
status = read(OUT / "initial-task-status.json")
review_path = ROOT / "artifacts/s01-replacement-launcher-review-r31-20261017/review.json"
review = read(review_path)
assert review["source_review_passed"] and not review["blocking_findings"]
task_id, session_id = dispatch["task_id"], dispatch["session_id"]
assert task_id != prep["original_task_id"] and session_id != prep["original_session_id"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
record = dict(recorded_at=at, actual_coordinator_task="/root", logical_task=prep["logical_task"], original_task_id=prep["original_task_id"], original_session_id=prep["original_session_id"], new_task_id=task_id, new_session_id=session_id, request_id=prep["request_id"], new_workspace=prep["new_workspace"], agent=prep["agent"], requested_model=prep["model"], actual_development_round=4, previous_actual_failed_deliveries=3, prior_failure_history="artifacts/coordinator-s01-replacement-r31-20261017/prior-failure-history.json", user_authorized_replacement_for_public_owner_gap=True, dispatched=True, producer_status=status.get("status"), status_receipt="artifacts/coordinator-s01-replacement-r31-20261017/initial-task-status.json", actual_product_execution_not_inferred_from_dispatch=True, artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, original_public_access_restored=False, services_started_or_restarted=0, archived_s06_operations=0, private_rpc_calls=0, failed_count_reset=False, launcher_source_review=str(review_path.relative_to(ROOT)), launcher_source_review_sha256=hashlib.sha256(review_path.read_bytes()).hexdigest(), root_and_stage_intake=False, full_packages_complete=False)
write(OUT / "dispatch-receipt.json", record)
write(OUT / "next-actions.json", dict(recorded_at=at, active_new_task_id=task_id, active_new_session_id=session_id, logical_task=prep["logical_task"], original_public_owner_gap_does_not_block_authorized_replacement=True, old_owner_recovery_not_required_for_this_replacement=True, prior_actual_failed_delivery_count=3, fourth_delivery_not_yet_accepted=True, after_delivery=["Read complete public get_result and verify exact ownership/source diff", "Coordinator independent six-command native/authority/regression/quality checks plus source review", "If actual fourth delivery still fails original obligation, preserve fourth failure and apply existing upgrade policy", "Only if independently accepted, coordinator imports exact S01 module into Stage", "Run real S01 advisory/context/native recovery/PRE/current Validator integration and full Stage quality", "Only after exact current acceptance, controlled Root intake and fresh Root union checks"], already_accepted_scopes_not_redispatched=["S08 MIN codec", "consumer exact repair", "Store receipt bound repair"], remaining_real_blockers=["S01 original native-origin two P1 until independently repaired", "Current Stage full standard/fresh mypy4 errors", "Full native instance/currentness/recovery/PRE/current Validator not accepted"], separate_unaccepted=["WholeS01/S08/U01 and downstream packages", "Real-project/LLM scan effects", "ConditionalS10/Q01/Q02", "Formal/portable and external waits"], platform_bypass=False, services_started_or_restarted=0, archived_s06_operations=0))
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == prep["logical_task"])
assert row["consecutive_failed_actual_deliveries"] == 3 and len(row["glm_delivery_rounds"]) == 3
assert row["bridge_task_id"] == prep["original_task_id"] and not row.get("fourth_dispatched", False), "Another continuation already owns this logical task"
row["prior_actual_task_ids"] = list(dict.fromkeys(row["prior_actual_task_ids"] + [prep["original_task_id"]]))
row["prior_third_delivery_public_binding"] = {key: row.get(key) for key in ("bridge_task_id", "bridge_session_id", "request_id", "dispatched_at", "worker_finished_at", "producer_status", "producer_status_source", "producer_completed_binding", "workspace")}
for key in ("worker_finished_at", "worker_process_started_at", "execution_evidence"):
    row.pop(key, None)
row.update(status="fourth_round_dispatched_new_public_task_user_authorized_owner_gap_prior_failure3_preserved", workspace=Path(prep["new_workspace"]).name, bridge_task_id=task_id, bridge_session_id=session_id, request_id=prep["request_id"], dispatched_at=at, producer_status=status.get("status", "dispatched"), producer_status_source="new_public_Bridge_dispatch_and_check", original_owner_public_interface_available=False, new_public_task_interface_available=True, active_continuation=record, dispatch_evidence="artifacts/coordinator-s01-replacement-r31-20261017/dispatch-response.json", artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, fourth_dispatched=True, checked_at=at)
row["current_fourth_round_delivery_counted_as_failure"] = False
ledger.update(updated_at=at, latest_handoff="artifacts/coordinator-s01-replacement-r31-20261017/dispatch-receipt.json", latest_next_actions="artifacts/coordinator-s01-replacement-r31-20261017/next-actions.json", bridge_public_access_observation="artifacts/coordinator-s01-replacement-r31-20261017/public-preflight.json", current_root_status="RootR23 and StageR30 unchanged; Stage bounded1147 passed/fullmypy4S01errors remain; user-authorized new public S01 fourth task dispatched, prior3failures retained, delivery/independent acceptance/integration pending")
for entry in ledger["next_module_tasks"]:
    if entry["id"] == row["id"]:
        entry.update({key: row.get(key) for key in entry})
        entry.update(bridge_task_id=task_id, bridge_session_id=session_id, fourth_dispatched=True)
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], latest_next_actions=ledger["latest_next_actions"], next_module_tasks=ledger["next_module_tasks"], bridge_public_access_observation=ledger["bridge_public_access_observation"], whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R31 用户授权原 Bridge 阻塞时新建公开任务接续

用户直接授权“Bridge阻塞就新开任务继续原任务未完成的工作”，已替代“必须等待旧owner恢复”的调度前提，未改变源码/验收/失败计数与平台边界。当前正常公开Bridge dispatch_enabled=true，原task_f702313db8仍unknown；80748为复用PID、17892不存在，当前实例无旧活跃会话、另6个存活实例。其他实例的全量任务不可由此推断；新隔离目录及Root/Stage只读所有权避免共享写入冲突。

同一逻辑S01-INSTANCE-SEMANTICS-MIN-R23第四轮已通过公开Bridge派发：新任务 {task_id}，新会话 {session_id}，request_id {prep['request_id']}，ZCode/GLM沿用原路线。原第三轮task_f702313db8/sess_6ecde27723和前两轮共3次实际开发失败及两个P1全部保留；新ID不归零。第四轮当前只记已派发/公开状态，尚无交付与独验，不能提前记第四次失败或通过。

新目录 {prep['new_workspace']} 从冻结第三轮复制1070只读依赖及2个待修文件，原目录、Root与Stage只读。仅2个源/测试文件及新交付目录归新worker；已有S08、消费端、Store不重复派发。协调者未启动/重启服务、未用私有RPC、未恢复旧S06-R02。启动器独立复审初始发现新增配置可改变验证的缺口，已补全配置集合/SHA前后核对；初始block与最终复审收据分开保留，不计S01开发失败。WSL/Linux/defaultfd/ext4/单outer_slot/零跳过不变，固定六命令保留原160+3Counter并另进程执行R24探针。

RootR23的1065输入与StageR30的967输入保持当前冻结基线；本轮无产品集成、无新联合通过结论。Stage原1147有界回归通过和完整mypy4S01错误/退出1仍各自保留。后续须新任务真实交付、协调者独立源码/native验收后才能集成Stage并推进完整质量及Root联合回归；真实项目效果、完整S01/S08/U01、条件性扩展与外部等待仍未验收。

派发收据 artifacts/coordinator-s01-replacement-r31-20261017/dispatch-receipt.json；请求、公开preflight、所有权、历史和响应均在同目录，原R30收据未覆盖。

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R31.md").write_text(note, encoding="utf-8", newline="\n")
print(json.dumps(dict(recorded_at=at, task_id=task_id, session_id=session_id, failed_count_preserved=3, independent_acceptance=False)))
