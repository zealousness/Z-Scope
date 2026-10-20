"""Bounded public wait through the existing owner; no dispatch or cancellation."""
from pathlib import Path
import json
import sys
import time
from uuid import uuid4

HERE=Path(__file__).resolve().parent
task={"kimi":"task_6e14411a6c","s08":"task_a110e5866a"}[sys.argv[1]]
identifier="r9-wait-"+uuid4().hex[:10]
route=HERE/"route-check"
request={"id":identifier,"tool":"wait_task","arguments":{"task_id":task,"timeout_sec":35}}
with (route/"bridge-queue"/("080-"+identifier+".request.json")).open("x",encoding="utf-8",newline="\n") as stream:
    stream.write(json.dumps(request)+"\n")
response=route/("bridge-response-"+identifier+".json")
deadline=time.monotonic()+45
while not response.exists() and time.monotonic()<deadline:
    time.sleep(1)
data=json.loads(response.read_text(encoding="utf-8")) if response.exists() else {}
compact={key:data.get(key) for key in ("ok","task_id","status","stop_reason","failure","warnings","finished_at","observed_model","recent_activity")}
compact["receipt"]=str(response)
print(json.dumps(compact,ensure_ascii=True))
