"""Reconcile actual receipts into the ledger; preserve all historical evidence."""
from pathlib import Path
import datetime as dt
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {row["id"]: row for row in ledger["tasks"]}
specs = [
    ("S01-INST-EXEC", "s01-analysis-r6", "task_9e8e7e3dc4", "2026-10-14T21:31:10.016698+08:00", 292,
     "artifacts/coordinator-s01-r1-consumers-20261014/review.json", 2, 5),
    ("S08-SESSION-SCHEDULER", "s08-session-r6", "task_b41bc0eb99", "2026-10-14T21:22:55.397455+08:00", None,
     "artifacts/coordinator-s08-r1-durability-20261014/review.json", 3, 2),
]
for identifier, workspace, old_task, finished, worker_tests, review, passed, failed in specs:
    row = rows[identifier]
    history = row.setdefault("execution_history", [])
    if not any(item.get("task_id") == old_task for item in history):
        history.append({"task_id": old_task, "session_id": row["bridge_session_id"], "finished_at": finished,
                        "status": "completed_delivery_independent_probes_failed", "observed_model": row["requested_model"],
                        "worker_tests": worker_tests, "independent_probe_result": {"passed": passed, "failed": failed},
                        "independent_review": review, "independent_acceptance": False, "integrated": False})
    request = json.loads((HERE / f"followups-r6/{workspace}-review2-request.json").read_text(encoding="utf-8"))
    accepted_path = HERE / f"route-check/bridge-response-{workspace}-review2.json"
    accepted = json.loads(accepted_path.read_text(encoding="utf-8"))
    assert accepted["ok"]
    row.update(bridge_task_id=accepted["task_id"], request_id=request["arguments"]["request_id"],
               accepted_model=accepted["model"], observed_model=None, execution_evidence=None,
               checked_at=at, status="review2_dispatched_pending_execution_evidence", independent_acceptance=False,
               integrated=False, whole_package_complete=False, latest_failed_review=review)
    extension = HERE / f"followups-r6/{workspace}-ownership-extension.json"
    if extension.exists():
        extra = json.loads(extension.read_text(encoding="utf-8"))
        row["write_paths"] = list(dict.fromkeys(row["write_paths"] + extra["added_owned_paths"]))
        row["ownership_extension"] = str(extension.relative_to(HERE))
astra = rows["ASTRA-V3-EDITOR"]
astra.update(status="phase2_independent_passed_intaken_joint_failed_phase3_repair_running", independent_acceptance=True,
             integrated=True, whole_package_complete=False, acceptance_scope="phase2 real all-target HTTP/browser editing; 409 contract fixture; scanner/report controlled",
             acceptance_evidence="artifacts/coordinator-astra-r6-phase2-retry1-20261014/review.json",
             intake_evidence="artifacts/intake-astra-phase2-r6-20261014/receipt.json",
             incremental_baseline="followups-r6/astra-config-r6-review-baseline.json", phase3_acceptance="pending")
rows["HTTP-INTEGRATION"]["status"] = "accepted_http_slice_integrated_current_root_joint_pending"
joint_id = "CURRENT-JOINT-R7"
if joint_id not in rows:
    row = {"id": joint_id, "packages": ["S09", "U01"], "title": "U01 CLI/editor/HTTP 与 Astra 同版本联合验证",
           "depends_on": ["CURRENT-JOINT-R6", "U01-ENTRYPOINTS", "ASTRA-V3-EDITOR"], "owner": "coordinator"}
    ledger["tasks"].append(row)
    rows[joint_id] = row
rows[joint_id].update(status="failed_browser_datetime_zero_seconds_repair_pending", evidence="artifacts/coordinator-r7-u01-ui-integrated-20261014/source-evidence.json",
                      result={"passed": 634, "failed": 1, "errors": 0, "skipped": 0}, quality_checks="not run after failing pytest",
                      whole_package_complete=False)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
stage_path = HERE / "continuation-r6.json"
stage = json.loads(stage_path.read_text(encoding="utf-8"))
stage.update(updated_at=at, current_joint="artifacts/coordinator-r7-u01-ui-integrated-20261014",
             current_joint_status="failed_634_pass_1_browser_datetime_failure_quality_not_run",
             current_joint_result={"passed":634,"failed":1,"errors":0,"skipped":0,"quality_commands_passed":0},
             next_task_rows=[rows[name] for name in ("S01-INST-EXEC", "S08-SESSION-SCHEDULER", "U01-ENTRYPOINTS", "ASTRA-V3-EDITOR")])
stage_path.write_text(json.dumps(stage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
text = f"""## {at[:19]} +08:00 · R7 当前事实（覆盖下方历史状态）

- 原 Bridge owner PID80748复用，无新服务或重复派单。旧S06-R02已由用户确认完成归档，本轮不恢复、不查询、不派发，不再作为外部等待。
- 启动器已实际探明DrvFS匿名临时文件ftruncate的ENOENT，改独立ext4 /tmp，保留default fd捕获/原测试标准。修复后基线583/0fail/0skip及6质量通过仅属于导入前字节。
- U01 ZCode `task_8e1ce5c8cc`于21:08:12完成，独立201通过，21:13:35导入8文件；共享HTTP22通过。Astra `/root/astra_v3_editor_r6` phase2独立10通过，21:28:55导入6文件；多目标真实保存200/完整GET回读/prepare禁启，409仅合同fixture。收据分别 `artifacts/coordinator-u01-review1-r6-20261014/review.json`、`artifacts/intake-u01-review1-r6-20261014/receipt.json`、`artifacts/coordinator-astra-r6-phase2-retry1-20261014/review.json`、`artifacts/intake-astra-phase2-r6-20261014/receipt.json`，集合不累加。
- 导入后同根联合 `artifacts/coordinator-r7-u01-ui-integrated-20261014` 为634通过/1失败/0跳过，源码前后SHA一致；质量未继续。真实Chromium已复现datetime-local零秒值被省略`:00`、Playwright严格赋值比较抛Malformed value；Astra phase3修fixture原生格式并保留12秒真实owner截止/partial/resume断言，尚待独立复验与联合重跑。
- S01 R1 `task_9e8e7e3dc4`21:31:10完成/observed kimi-k3，worker292不替代验收。独立原2守卫通过，新增5消费边界失败（真实SymbolCatalog读裸函数cache、显式file/重载metadata、类型/宏投影）。未导入；同sess R2 `{rows['S01-INST-EXEC']['bridge_task_id']}`已接受。证据 `artifacts/coordinator-s01-r1-consumers-20261014/review.json`。
- S08 R1 `task_b41bc0eb99`21:22:55完成/observed精确glm-5.3；独立原3守卫通过、新2耐久性反例失败（batch上限和真实进程退出丢子发现）。未导入；同sess R2 `{rows['S08-SESSION-SCHEDULER']['bridge_task_id']}`已接受，副本独占扩展到7文件，根/shared集成仍协调者。证据 `artifacts/coordinator-s08-r1-durability-20261014/review.json`。
- 剩余主链：S01实例消费者/符号图→链接及S02领域→S03内存/生命周期→S04统一义务→S05/S06广域能力与S07完整需求对照；S08完整扫描接线/窗口与remaining，U01其余MCP/消费端/画像，U02跨问题回答及UX，S09同版本质量/真实项目效果。当前切片不关闭整包。真实模型/项目扫描、formal/portable smoke未运行；本进程缺LLM三变量与ijson，外部资料和条件S10/Q01/Q02单列不自动启用。

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    destination = HERE / name
    destination.write_text(text + destination.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"tasks":len(ledger["tasks"]), "s01":rows['S01-INST-EXEC']['bridge_task_id'], "s08":rows['S08-SESSION-SCHEDULER']['bridge_task_id'], "at":at}))
