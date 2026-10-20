"""Same-session bounded repair after fresh idle/process/hash checks."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import time
from uuid import uuid4

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
kind,label,feedback_name,proof_label=sys.argv[1:5]
name={"contract":"contract-validation-r12","main":"scan-session-r12","checkpoint":"scan-checkpoint-r17","mcp":"mcp-findings-r12"}[kind]
if kind=="checkpoint":
    name=next(row["workspace"] for row in json.loads((HERE/"tasks.json").read_text(encoding="utf-8"))["tasks"] if row["id"]=="SCAN-CHECKPOINT-R17")
route=HERE/"route-check"
baseline=json.loads((HERE/"followups-r12"/(name+"-baseline.json")).read_text(encoding="utf-8"))
task=baseline["task"]
producer=ROOT/".coordination/20261014/workspaces"/name
proof=json.loads((ROOT/"artifacts"/proof_label/"review.json").read_text(encoding="utf-8"))
assert proof["returncode"]!=0 and proof["stable_frozen_inputs"]
assert all(hashlib.sha256((producer/p).read_bytes()).hexdigest()==sha for p,sha in proof["before"].items()), "source moved after diagnostic"
identity=label+"-preflight"
request=route/"bridge-queue"/("080-"+identity+".request.json")
response=route/("bridge-response-"+identity+".json")
assert not request.exists() and not response.exists()
request.write_text(json.dumps({"id":identity,"tool":"list_sessions","arguments":{"active_only":False}})+"\n",encoding="utf-8",newline="\n")
deadline=time.monotonic()+40
while not response.exists() and time.monotonic()<deadline:
    time.sleep(.25)
public=json.loads(response.read_text(encoding="utf-8"))
session=next(row for row in public["sessions"] if row["session_id"]==task["session_id"])
assert session["proc_state"] in {"ready","idle_unloaded"},session["proc_state"]
linux_here="/mnt/c/"+HERE.as_posix()[3:]
inspection=subprocess.check_output(["wsl","-d","Ubuntu","--","bash","-lc",f"/home/zeal/venv313/bin/python {linux_here}/inspect_workspace_processes.py {name}"],text=True)
processes=json.loads(inspection)
assert not processes["processes"],processes
original=json.loads((HERE/"followups-r12"/(name+"-request.json")).read_text(encoding="utf-8"))
arguments=dict(original["arguments"])
arguments.update(title=label.upper(),request_id=str(uuid4()))
arguments["message"]=(HERE/"followups-r12"/feedback_name).read_text(encoding="utf-8")+"\n\n原完整任务和所有权约束仍生效：\n"+arguments["message"]
dispatch={"id":label,"branch":name,"tool":"dispatch_task","arguments":arguments}
archive=HERE/"followups-r12"/(label+"-request.json")
target=route/"bridge-queue"/("080-"+label+".request.json")
assert not archive.exists() and not target.exists()
archive.write_text(json.dumps(dispatch,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
target.write_bytes(archive.read_bytes())
(HERE/"followups-r12"/(label+"-preflight.json")).write_text(json.dumps({"at":dt.datetime.now(dt.timezone.utc).isoformat(),"session_state":session["proc_state"],"processes":processes,"source_matches_diagnostic":True,"diagnostic":proof_label},indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"queued_once":True,"id":label,"session":task["session_id"],"response":str(route/("bridge-response-"+label+".json"))}))
