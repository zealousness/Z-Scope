"""Integrate byte-stable queue/Web shared changes after MCP acceptance/intake."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
accepted=ROOT/"artifacts/coordinator-shared-r14-queue-web-20261015"
proof=json.loads((accepted/"review.json").read_text(encoding="utf-8"))
assert proof["passed"] and proof["source_unchanged"]
baseline=json.loads((HERE/"followups-r12/coordinator-shared-r14-baseline.json").read_text(encoding="utf-8"))
mcp_intake=json.loads((ROOT/"artifacts/intake-mcp-findings-r12-20261015/receipt.json").read_text(encoding="utf-8"))
assert mcp_intake["independent_acceptance"] and mcp_intake["integrated"]
assert baseline["staged_mcp_dependencies"]==mcp_intake["accepted_files"]
branch=ROOT/".coordination/20261014/workspaces/coordinator-shared-r14"
out=ROOT/"artifacts/intake-coordinator-queue-web-r14-20261015"
out.mkdir(exist_ok=False)
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for name,sha in proof["changed_files"].items():
    target=ROOT/name
    assert (hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None)==baseline["files"].get(name),name
    frozen=accepted/"source-before"/name
    assert hashlib.sha256(frozen.read_bytes()).hexdigest()==sha==hashlib.sha256((branch/name).read_bytes()).hexdigest()
    if target.exists():
        backup=out/"before"/name
        backup.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(target,backup)
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(frozen,target)
receipt={"at":at,"task_id":"coordinator/shared-queue-web-r14","coordinator_authored":True,"coordinator_validation_passed":True,"independent_worker_acceptance":False,"accepted_files":proof["changed_files"],"verification_evidence":str((accepted/"review.json").relative_to(ROOT)).replace("\\","/"),"junit":proof["junit"],"dependency_task_id":"task_e4ab0da557","dependency_intake":"artifacts/intake-mcp-findings-r12-20261015/receipt.json","integrated":True,"joint_verification":False,"whole_package_complete":False,"scope":proof["scope"]}
(out/"receipt.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
assert "COORD-QUEUE-RECEIPTS-R14" not in {row["id"] for row in ledger["tasks"]}
ledger["tasks"].append({"id":"COORD-QUEUE-RECEIPTS-R14","title":"Bound active queue receipts and shared Web job findings","owner":"coordinator","depends_on":["COORD-SOURCE-ROOT-R13","MCP-FINDINGS-R12"],"packages":["S08","U01","U02"],"write_paths":list(proof["changed_files"]),"status":"coordinator_validated_intaken_joint_pending","actual_execution_at":proof["commands"][0]["started_at"],"artifact_available":True,"independent_acceptance":False,"coordinator_validation":True,"integrated":True,"integrated_at":at,"intake_evidence":str((out/"receipt.json").relative_to(ROOT)).replace("\\","/"),"joint_verification":False,"whole_package_complete":False})
ledger["updated_at"]=at
ledger["current_accepted_stage"]["current_root_status"]="MCP and shared queue/Web changes intaken; current complete joint pending; old R14 failed attempt retained"
left={row["id"] for row in ledger["tasks"]};done=set();layers=[]
while left:
    ready=[row["id"] for row in ledger["tasks"] if row["id"] in left and set(row["depends_on"])<=done]
    assert ready
    layers.append(ready);left.difference_update(ready);done.update(ready)
ledger["topological_layers"]=layers
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
doc=ROOT/"docs/modules/execution-orchestration.md"
text=doc.read_text(encoding="utf-8")
text=text.replace("tests:\n","tests:\n  - tests/test_job_queue_receipts.py\n",1)
text+="\n### 本轮队列收据与 remaining\n\nowner 按当前 job/run 的 `session_scheduler_started` SQL 事件选择实际队列，核对事件的 input revision、队列在该 job/当前 run 目录内的解析路径，以及数据库的 job/input 元数据，再只读统计全部状态。它不按文件 glob、业务问题数或 pending JSON 样本推算 remaining；无 scheduler 收据的既有 canonical 队列仍按原 job/input 绑定读取。损坏、跨目录、跨输入、跨 job 或缺失队列保持未测量，不回退另一队列。该接线支持 attempt 队列，不能据此宣称 ScanSession 的完整 checkpoint、在途停止和逐实例恢复已验收。\n"
doc.write_text(text,encoding="utf-8",newline="\n")
doc=ROOT/"docs/modules/interfaces-reporting.md"
text=doc.read_text(encoding="utf-8").replace("  - tests/test_job_result_projection.py\n","  - tests/test_job_result_projection.py\n  - tests/test_job_result_http_binding.py\n",1)
text+="\nWeb jobs result 也复用 `project_job_result` 的同轮绑定核对；它保留 Web 已选择的当前报告文件（包括单入口 `report.json`）作为复核 scope，仅在完整逻辑报告相等时共享。MCP 默认从保存配置定位项目当前批量报告；这不是新增客户端可传入的文件路径参数。HTTP/SQLite/owner 与同 hash 真实 resume 的回归使用明确受控报告，不代表真实项目扫描效果、大报告性能或整个 U01/U02 完成。\n"
doc.write_text(text,encoding="utf-8",newline="\n")
print(json.dumps({"intake":str(out/"receipt.json"),"files":len(proof["changed_files"]),"joint_pending":True}))
