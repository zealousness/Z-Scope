"""Read current R10 public statuses through the existing MCP owner only."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
for label, task in (("kimi","task_9579265ee7"),("zcode","task_2f3f99db9b")):
    identity = "r10-current-" + label + "-" + uuid4().hex[:10]
    request = {"id":identity,"tool":"check_task","arguments":{"task_id":task}}
    (route/"bridge-queue"/("080-"+identity+".request.json")).write_text(json.dumps(request)+"\n",encoding="utf-8",newline="\n")
    response = route / ("bridge-response-"+identity+".json")
    deadline = time.monotonic()+40
    while not response.exists() and time.monotonic()<deadline:
        time.sleep(.25)
    if not response.exists():
        print(json.dumps({"label":label,"task_id":task,"state":"public_response_pending","receipt":str(response)}))
        continue
    value = json.loads(response.read_text(encoding="utf-8"))
    value["recent_activity"] = [item for item in value.get("recent_activity", [])
                                if item.startswith(("tool_call", "plan", "raw", "turn_end"))]
    fields = ("ok","task_id","session_id","status","model","observed_model","started_at","finished_at","silent_for_sec","failure","warnings","recent_activity")
    print(json.dumps({"label":label,"checked_at":dt.datetime.now(dt.timezone.utc).isoformat(),
                      "receipt":str(response),"response":{k:value.get(k) for k in fields}},ensure_ascii=False))
