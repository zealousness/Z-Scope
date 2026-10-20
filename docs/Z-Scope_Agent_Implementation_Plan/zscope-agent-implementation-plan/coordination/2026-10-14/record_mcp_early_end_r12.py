"""Preserve the difference between Bridge end metadata and actual producer quiescence."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
branch = ROOT / ".coordination/20261014/workspaces/mcp-findings-r12"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
files = ["zscope/reporting/job_result_projection.py","zscope/mcp/jobs_adapter.py","tests/test_job_result_projection.py"]
observations = [{"path":name,"sha256":hashlib.sha256((branch/name).read_bytes()).hexdigest(),"mtime":dt.datetime.fromtimestamp((branch/name).stat().st_mtime,dt.timezone(dt.timedelta(hours=8))).isoformat()} for name in files]
record = {"at":at,"task_id":"task_a3a56d31b4","bridge_status":"completed","bridge_finished_at":"2026-10-15T02:38:01.543167+08:00","public_result":"route-check/bridge-response-r6-public-2f02fab73f.json","result_ends_mid_implementation":True,"delivery_exists":(branch/"DELIVERY.md").exists(),"observed_post_bridge_writes":observations,"native_process_inventory_at":"2026-10-15T02:41:13+08:00","observed_native_processes":[{"pid":94668,"parent":36260,"name":"bash.exe"},{"pid":41612,"parent":94668,"name":"bash.exe"},{"pid":96596,"parent":41612,"name":"bash.exe"},{"pid":98288,"parent":96596,"name":"wsl.exe"},{"pid":92384,"parent":98288,"name":"wsl.exe"}],"action":"Do not duplicate/resume while native tool processes are still active. Await stable final delivery, then independent verification.","independent_acceptance":False,"integrated":False,"whole_package_complete":False}
(HERE/"followups-r12/mcp-early-end.json").write_text(json.dumps(record,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(row for row in ledger["tasks"] if row["id"] == "MCP-FINDINGS-R12")
row.update(status="native_execution_observed_after_bridge_end_delivery_pending",producer_bridge_status="completed",observed_model="97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",bridge_finished_at=record["bridge_finished_at"],source_artifacts_available=True,artifact_available=False,producer_observation_evidence="followups-r12/mcp-early-end.json",checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"task_id":record["task_id"],"status":row["status"],"delivery_exists":record["delivery_exists"]}))
