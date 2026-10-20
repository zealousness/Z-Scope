"""Dispatch once on the existing idle Kimi owner, preserving all old artifacts."""
from pathlib import Path
import datetime as dt
import json
import subprocess
import time
from uuid import uuid4

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
route=HERE/"route-check";label="scan-checkpoint-r17"
preflight=label+"-preflight"
request=route/"bridge-queue"/("080-"+preflight+".request.json")
response=route/("bridge-response-"+preflight+".json")
assert not request.exists() and not response.exists()
request.write_text(json.dumps({"id":preflight,"tool":"list_sessions","arguments":{"active_only":False}})+"\n",encoding="utf-8",newline="\n")
until=time.monotonic()+40
while not response.exists() and time.monotonic()<until:time.sleep(.25)
sessions=json.loads(response.read_text(encoding="utf-8"))["sessions"]
session=next(row for row in sessions if row["session_id"]=="sess_261a55289f")
assert session["proc_state"] in {"ready","idle_unloaded"}
linux_here="/mnt/c/"+HERE.as_posix()[3:]
for name in ("scan-session-r12","scan-checkpoint-r17"):
    current=json.loads(subprocess.check_output(["wsl","-d","Ubuntu","--","bash","-lc",f"/home/zeal/venv313/bin/python {linux_here}/inspect_workspace_processes.py {name}"],text=True))
    assert not current["processes"],current
original=json.loads((HERE/"followups-r12/scan-session-r12-request.json").read_text(encoding="utf-8"))
arguments=dict(original["arguments"])
arguments.update(title="SCAN-CHECKPOINT-R17",request_id=str(uuid4()),message=(HERE/"followups-r12/scan-checkpoint-r17-message.txt").read_text(encoding="utf-8"))
assert arguments["session_id"]=="sess_261a55289f" and arguments["model"]=="volceapi/kimi-k3"
dispatch={"id":label,"branch":label,"tool":"dispatch_task","arguments":arguments}
archive=HERE/"followups-r12/scan-checkpoint-r17-request.json"
target=route/"bridge-queue"/("080-"+label+".request.json")
assert not archive.exists() and not target.exists()
archive.write_text(json.dumps(dispatch,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n");target.write_bytes(archive.read_bytes())
response=route/("bridge-response-"+label+".json")
until=time.monotonic()+40
while not response.exists() and time.monotonic()<until:time.sleep(.25)
if not response.exists():
    print(json.dumps({"queued_once":True,"response_pending":str(response)}));raise SystemExit(0)
data=json.loads(response.read_text(encoding="utf-8"));assert data["ok"]
p=HERE/"tasks.json";d=json.loads(p.read_text(encoding="utf-8"));row=next(r for r in d["tasks"] if r["id"]=="SCAN-CHECKPOINT-R17")
row.update(status="dispatched_execution_pending",bridge_task_id=data["task_id"],request_id=data["request_id"],dispatch_evidence=response.relative_to(ROOT).as_posix(),accepted_model=arguments["model"],observed_model=None)
d["updated_at"]=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat();p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"task_id":data["task_id"],"session_id":data["session_id"],"queued_once":True,"response":str(response)}))
