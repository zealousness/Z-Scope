"""Publish actual R18 dispatch receipts without claiming execution or intake."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
for name, identity, response_name in (("validation-context-r18", "VALIDATION-CONTEXT-R18", "validation-context-r18-routed"), ("config-stop-at-r18", "U01-STOP-AT-R18", "config-stop-at-r18")):
    response_path = HERE / "route-check" / ("bridge-response-" + response_name + ".json")
    result = json.loads(response_path.read_text(encoding="utf-8"))
    assert result["ok"] and not result["reused"]
    baseline = json.loads((HERE / "followups-r12" / (name + "-baseline.json")).read_text(encoding="utf-8"))
    assert not any(r["id"] == identity for r in ledger["tasks"])
    ledger["tasks"].append({**baseline["task"], "agent": "zcode", "owner": "zcode", "bridge_task_id": result["task_id"], "bridge_session_id": result["session_id"], "accepted_model": result["model"], "observed_model": None, "request_id": result["request_id"], "dispatch_evidence": response_path.relative_to(HERE).as_posix(), "baseline_receipt": "followups-r12/" + name + "-baseline.json", "status": "dispatched_execution_pending", "actual_execution_at": None, "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "checked_at": at})
name = "astra-instance-ui-r18"
baseline = json.loads((HERE / "followups-r12" / (name + "-baseline.json")).read_text(encoding="utf-8"))
assert not any(r["id"] == "ASTRA-INSTANCE-UI-R18" for r in ledger["tasks"])
evidence = {"recorded_at": at, "native_agent_id": "/root/astra_instance_ui_r18", "model": "gpt-6-astra", "first_execution": "Astra reported actual reads of the R18 full task, baseline hashes, AGENTS.md, architecture and interfaces-reporting; later implemented UI and ran one WSL state-contract test.", "first_execution_timestamp": "not independently timestamped; observed before this receipt", "dependency": "Bound lightweight report omits metadata.entry_instances and metadata.job; coordinator preparing additive readonly backend dependency.", "independent_acceptance": False, "integrated": False}
(HERE / "followups-r12/astra-instance-ui-r18-execution.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
ledger["tasks"].append({**baseline["task"], "native_agent_id": evidence["native_agent_id"], "accepted_model": "gpt-6-astra", "observed_model": "gpt-6-astra", "status": "actual_execution_dependency_pending", "actual_execution_evidence": "followups-r12/astra-instance-ui-r18-execution.json", "artifact_available": True, "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "checked_at": at})
contract = next(r for r in ledger["tasks"] if r["id"] == "CONTRACT-VALIDATION-R12")
proof = json.loads((ROOT / "artifacts/coordinator-contract-r12-r5-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert proof["independent_acceptance_passed"]
contract.update(status="independent_accepted_intake_pending", independent_acceptance=True, integrated=False, joint_verification=False, independent_acceptance_evidence="artifacts/coordinator-contract-r12-r5-acceptance-20261015/review.json", whole_package_complete=False, checked_at=at)
checkpoint = next(r for r in ledger["tasks"] if r["id"] == "SCAN-CHECKPOINT-R17")
terminal = json.loads((HERE / "route-check/bridge-response-r18-terminal-checkpoint.json").read_text(encoding="utf-8"))
assert terminal["status"] == "completed"
checkpoint.update(status="delivered_independent_acceptance_running", producer_bridge_status="completed", observed_model=terminal["observed_model"], bridge_finished_at=terminal["finished_at"], artifact_available=True, independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
ledger["updated_at"] = at
ledger["current_worker_policy"].update(simple_deterministic_work="DeepSeek Harness deepseek/deepseek-v4.1-flash only after public route verification; pending", parallel_isolated_same_agent_allowed=True, kimi_new_dispatch=False)
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"""# R18 并行状态（{at}）

- 根目录当前仍为 R16：1207 项、六条命令通过；新批未导入。默认 fd capture 的 ext4 启动器已通过，未降低标准。
- CONTRACT-VALIDATION-R12：task_0dc5e073f3，16:25:36 交付；独立 1016/0 和四命令 0，证据 artifacts/coordinator-contract-r12-r5-acceptance-20261015/review.json；待批量集成。
- SCAN-CHECKPOINT-R17：现由 ZCode task_280df74eca 承接，16:55:37 完成，glm-5.3 已观察；独立验收进行中，旧 433 仅切片且三例依赖失败历史保留。
- VALIDATION-CONTEXT-R18：task_cb7011476d / sess_a0adb99b15，独占内层 Validator/事实工作者文件；已接收，首次执行待核对。
- U01-STOP-AT-R18：task_5b722e514f / sess_b91680bb39，独占配置/CLI/job service，已接收，首次执行待核对。
- ASTRA-INSTANCE-UI-R18：/root/astra_instance_ui_r18，已实际读源码、实现 UI 并自测；协调者补充绑定轻量报告只读元数据依赖后验收 HTTP/native/浏览器链。
- DOC-IDENTITY-R18：准备完成未派发。原 owner 的 DSH 公开 model 未确认、旧 session 不在列表；继续只读核对既有 native owner，不安装、不改入口或凭据。
- Kimi 停止新派单，已有目录冻结。旧 S06-R02 不恢复、不查询。父包未全部完成不阻断已固定接口的隔离并行。
- 真实项目/LLM 效果、全 SVF/link/逐实例 durable 恢复及 U01 其他未消费字段仍未验收；S10/Q 为未启用条件扩展。
"""
(HERE / "CHECKPOINT-R18-PARALLEL.md").write_text(note, encoding="utf-8", newline="\n")
for filename in ("PROGRESS.md", "DAG.md"):
    target = HERE / filename
    old = target.read_text(encoding="utf-8")
    target.write_text("<!-- R18 current checkpoint -->\n" + note + "\n---\n\n" + old, encoding="utf-8", newline="\n")
print(json.dumps({"recorded_at": at, "dispatch_task_ids": ["task_cb7011476d", "task_5b722e514f"], "root_product_changed": False}))
