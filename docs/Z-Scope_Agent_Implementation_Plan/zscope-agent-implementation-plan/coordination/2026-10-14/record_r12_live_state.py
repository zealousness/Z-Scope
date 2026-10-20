"""Record public completion separately from delivery and observed processes."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for label, identity in (("mcp", "MCP-FINDINGS-R12"), ("zcode", "CONTRACT-VALIDATION-R12"), ("kimi", "SCAN-SESSION-R12")):
    row = next(row for row in ledger["tasks"] if row["id"] == identity)
    receipt = max(route.glob("bridge-response-r12-current-"+label+"-*.json"), key=lambda p:p.stat().st_mtime_ns)
    public = json.loads(receipt.read_text(encoding="utf-8"))
    if label == "mcp" and row["bridge_task_id"] != public["task_id"]:
        row.setdefault("execution_history", []).append({key:row.get(key) for key in ("bridge_task_id","actual_execution_at","bridge_finished_at","observed_model","producer_bridge_status","producer_observation_evidence","dispatch_evidence","request_id")})
        dispatch = json.loads((route / "bridge-response-mcp-findings-r12-finalize.json").read_text(encoding="utf-8"))
        assert dispatch["ok"] and dispatch["task_id"] == public["task_id"]
        row.update(bridge_task_id=public["task_id"], request_id=dispatch["request_id"], dispatch_evidence="route-check/bridge-response-mcp-findings-r12-finalize.json")
        row.pop("bridge_finished_at", None)
        row.update(status="same_session_finalization_executing", source_artifacts_available=True)
    elif label == "zcode" and public["status"] == "completed":
        row.update(status="native_execution_observed_after_bridge_end_delivery_pending",source_artifacts_available=True)
    row.update(checked_at=at,actual_execution_at=public["started_at"],observed_model=public.get("observed_model"),producer_bridge_status=public["status"],execution_evidence="route-check/"+receipt.name)
    if public.get("finished_at"):
        row["bridge_finished_at"] = public["finished_at"]
ledger["updated_at"] = at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"recorded_at":at,"mcp_finalization":"task_abdc75ecbf","contract_final_delivery":False}))
