"""Persist actual producer activity and current accepted root separately."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
ledger_path=HERE/"tasks.json"
ledger=json.loads(ledger_path.read_text(encoding="utf-8"))
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
observations=[]
for label,identifier in (("kimi","SCAN-SESSION-R12"),("zcode","CONTRACT-VALIDATION-R12"),("mcp","MCP-FINDINGS-R12")):
    row=next(row for row in ledger["tasks"] if row["id"]==identifier)
    receipt=max((HERE/"route-check").glob("bridge-response-r12-current-"+label+"-*.json"),key=lambda p:p.stat().st_mtime_ns)
    public=json.loads(receipt.read_text(encoding="utf-8"))
    assert public["task_id"]==row["bridge_task_id"]
    linux_here="/mnt/c/"+HERE.as_posix()[3:]
    processes=json.loads(subprocess.check_output(["wsl","-d","Ubuntu","--","bash","-lc",f"/home/zeal/venv313/bin/python {linux_here}/inspect_workspace_processes.py {row['workspace']}"],text=True))
    workspace=ROOT/".coordination/20261014/workspaces"/row["workspace"]
    deliveries={str(p.relative_to(workspace)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (workspace/"DELIVERY.md",workspace/"DELIVERY/DELIVERY.md") if p.exists()}
    status="repair_executing" if public["status"]=="running" else "bridge_ended_delivery_review_pending"
    producer_processes=[p for p in processes["processes"] if p.get("origin")!="coordinator_verification"]
    if public["status"]=="completed" and producer_processes:
        status="native_verification_observed_after_bridge_end"
    if label=="mcp" and public["status"]=="completed" and not producer_processes:
        assert "R12B" in (workspace/"DELIVERY/DELIVERY.md").read_text(encoding="utf-8")
        status="producer_delivery_available_independent_verification_pending"
        row["artifact_available"]=True
    observation={"at":at,"id":identifier,"task_id":public["task_id"],"public_evidence":str(receipt.relative_to(HERE)).replace("\\","/"),"processes":processes,"delivery_hashes":deliveries,"status":status}
    observations.append(observation)
    row.update(status=status,checked_at=at,actual_execution_at=public["started_at"],observed_model=public.get("observed_model"),producer_bridge_status=public["status"],source_artifacts_available=True,execution_evidence=observation["public_evidence"])
    if public.get("finished_at"):
        row["bridge_finished_at"]=public["finished_at"]
ledger["updated_at"]=at
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
proof_path=HERE/"followups-r12"/("producer-observation-"+dt.datetime.now().strftime("%H%M%S")+".json")
proof_path.write_text(json.dumps(observations,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
continuation_path=HERE/"continuation-r6.json"
continuation=json.loads(continuation_path.read_text(encoding="utf-8"))
continuation.update(current_joint="artifacts/coordinator-r13-astra-intaken-20261015",current_joint_finished_at="2026-10-15T02:44:46.414370+08:00",current_joint_result={"passed":1132,"failed":0,"errors":0,"skipped":0,"quality_commands_passed":6,"source_inputs":1003},current_round={item["id"]:{"task_id":item["task_id"],"status":item["status"]} for item in observations},latest_observation=str(proof_path.relative_to(HERE)).replace("\\","/"),whole_packages_complete=False,updated_at=at)
continuation_path.write_text(json.dumps(continuation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"observations":[{k:r[k] for k in ("id","task_id","status")} for r in observations],"receipt":str(proof_path)}))
