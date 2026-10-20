"""Restore authorized parallel development using the original Bridge owner."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];route=HERE/"route-check"
def call(identity,tool,arguments):
    request=route/"bridge-queue"/("080-"+identity+".request.json");response=route/("bridge-response-"+identity+".json")
    if response.exists() and tool in {"list_agents","list_sessions"}:
        return json.loads(response.read_text(encoding="utf-8")),response
    assert not request.exists() and not response.exists()
    payload={"id":identity,"tool":tool,"arguments":arguments}
    request.write_text(json.dumps(payload,ensure_ascii=False)+"\n",encoding="utf-8",newline="\n")
    deadline=time.monotonic()+40
    while not response.exists() and time.monotonic()<deadline:time.sleep(.25)
    assert response.exists(),response
    return json.loads(response.read_text(encoding="utf-8")),response
agents,agent_path=call("parallel-r18-agents","list_agents",{})
assert agents["ok"] and agents["coordinator"]["dispatch_enabled"]
dsh=next(r for r in agents["agents"] if r["agent"]=="dsh")
sessions,session_path=call("parallel-r18-sessions","list_sessions",{"active_only":False})
known={r["session_id"]:r for r in sessions["sessions"]}
assert known["sess_a0adb99b15"]["proc_state"] in {"ready","idle_unloaded"}
dsh_session=known.get("sess_bdab8c13fb",{})
deepseek_ready=bool(dsh["available"] and dsh_session.get("proc_state") in {"ready","idle_unloaded"} and dsh_session.get("model")=="deepseek/deepseek-v4.1-flash")
print(json.dumps({"dsh_available":dsh["available"],"dsh_version":dsh.get("version"),"dsh_session_model":dsh_session.get("model"),"dsh_route_ready":deepseek_ready,"historical_dsh_session_present":bool(dsh_session),"agent_receipt":str(agent_path),"session_receipt":str(session_path)}),flush=True)
specs=[("validation-context-r18","VALIDATION-CONTEXT-R18","zcode","sess_a0adb99b15","97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"), ("config-stop-at-r18","U01-STOP-AT-R18","zcode",None,"97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3")]
if deepseek_ready:specs.append(("doc-identity-r18","DOC-IDENTITY-R18","dsh","sess_bdab8c13fb","deepseek/deepseek-v4.1-flash"))
for name,identity,agent,session,model in specs:
    baseline=json.loads((HERE/"followups-r12"/(name+"-baseline.json")).read_text(encoding="utf-8"))
    arguments={"agent":agent,"cwd":str(ROOT),"title":identity,"message":(HERE/"followups-r12"/(name+"-message.txt")).read_text(encoding="utf-8"),"model":model,"request_id":str(uuid4()),"user_requested":True}
    if session:arguments["session_id"]=session
    archive=HERE/"followups-r12"/(name+"-request.json");assert not archive.exists()
    archive.write_text(json.dumps({"id":name,"tool":"dispatch_task","arguments":arguments},ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    result,response=call(name,"dispatch_task",arguments)
    print(json.dumps({"task":identity,"response":str(response),"ok":result.get("ok"),"task_id":result.get("task_id"),"session_id":result.get("session_id"),"error":result.get("error")}),flush=True)
    if not result.get("ok"):continue
    if identity=="U01-STOP-AT-R18":assert result["session_id"] not in {"sess_a0adb99b15","sess_3b6b9a19b2"},"unexpected busy-session reuse"
    path=HERE/"tasks.json";ledger=json.loads(path.read_text(encoding="utf-8"))
    assert not any(r["id"]==identity for r in ledger["tasks"])
    row={**baseline["task"],"agent":agent,"owner":"deepseek_harness" if agent=="dsh" else "zcode","bridge_task_id":result["task_id"],"bridge_session_id":result["session_id"],"accepted_model":model,"requested_model":model,"observed_model":None,"request_id":result["request_id"],"dispatch_evidence":response.relative_to(HERE).as_posix(),"baseline_receipt":"followups-r12/"+name+"-baseline.json","status":"dispatched_execution_pending","artifact_available":False,"independent_acceptance":False,"integrated":False,"joint_verification":False,"whole_package_complete":False,"checked_at":dt.datetime.now(dt.timezone.utc).isoformat()}
    ledger["tasks"].append(row);ledger["updated_at"]=row["checked_at"]
    path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
