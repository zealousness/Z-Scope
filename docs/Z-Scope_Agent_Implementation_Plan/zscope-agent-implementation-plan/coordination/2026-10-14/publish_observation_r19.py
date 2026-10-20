"""Record the current unverified root and isolated repair stages once."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
context = rows["VALIDATION-CONTEXT-R18"]
context.update(status="delivered_callee_repair_independent_acceptance_running", artifact_available=True, producer_status="completed", worker_finished_at="2026-10-15T19:01:25.533546+08:00", independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
for identity, filename in (("VALIDATION-CONTEXT-R18", "validation-context-r18-ownership-extension-callee.json"), ("U01-STOP-AT-R18", "config-stop-at-r18-ownership-extension-deadline.json")):
    extension = json.loads((HERE / "followups-r12" / filename).read_text(encoding="utf-8"))
    rows[identity]["write_paths"] = list(dict.fromkeys(rows[identity]["write_paths"] + extension["write_paths"]))
    rows[identity]["ownership_extension_evidence"] = "followups-r12/" + filename
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · 当前 R18 联合重跑与两项独立返修\n\n根目录队列收据测试只读迁移已于19:08:25导入，原生/浏览器/计数断言保留，并增加job/run/input与实际SQL scheduler事件绑定。收据 artifacts/intake-ui-queue-receipt-r19-20261015/receipt.json；迁移独立107/0及四命令0于19:01:44完成。当前132文件联合重跑 artifacts/coordinator-r18-queue-receipt-repaired-20261015 正在执行，已有一处失败标记待完整日志定位；尚无当前根通过结论。R17的2069/六命令0已是历史。\n\n上下文返修task_bf7efdfce3于19:01:25交付、实际glm-5.3，当前协调者保留原集合并加入两原失败native callee探针独验，未集成。stop_at旧task_5b722e514f于18:57:45交付，但真实共享token/本地HTTP两探针均失败（19:13:44，artifacts/coordinator-stop-deadline-r18-probes-20261015/review.json）；同会话ZCode返修task_9565621a54于19:17:03启动，有工具执行，未验收/未集成。两项各自prospective新增一个写路径，见所有权扩展收据，无共享文件并写。\n\n正常Bridge owner80748仍在；两Linux测试槽限制保持，default fd与ext4临时目录不变。Kimi无新派单，Astra本轮已独验/导入但等当前联合结论，旧S06未操作。真实项目/模型效果、全实例durable恢复、SVF/link/full modeling、U01其余未消费字段与多目标执行、条件S10/Q及正式benchmark/portable单列未完成。各范围测试数不相加。\n\n---\n\n"
for filename in ("PROGRESS.md", "DAG.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"published_at": at, "current_root_passed": False, "context_independent_running": True, "deadline_repair": "task_9565621a54"}), flush=True)
