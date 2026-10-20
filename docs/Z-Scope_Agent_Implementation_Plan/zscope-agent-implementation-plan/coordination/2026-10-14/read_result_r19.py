"""Fetch one completed public Bridge result without dumping recent thoughts."""
from pathlib import Path
import json
import sys
import time
from uuid import uuid4
sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
task_id = sys.argv[1]
assert task_id in {r.get("bridge_task_id") for r in json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))["tasks"] if r["id"] in {"VALIDATION-CONTEXT-R18", "U01-STOP-AT-R18", "S07-NATIVE-HOT-R19", "U01-JOB-CLI-WINDOW-R20"}}
route = HERE / "route-check"
identity = "r19-result-" + task_id + "-" + uuid4().hex[:10]
request = {"id": identity, "tool": "get_result", "arguments": {"task_id": task_id, "max_chars": 18000}}
(route / "bridge-queue" / ("080-" + identity + ".request.json")).write_text(json.dumps(request) + "\n", encoding="utf-8", newline="\n")
response = route / ("bridge-response-" + identity + ".json")
until = time.monotonic() + 40
while not response.exists() and time.monotonic() < until:
    time.sleep(.25)
assert response.exists()
raw = json.loads(response.read_text(encoding="utf-8"))
safe = {k: raw.get(k) for k in ("ok", "task_id", "status", "model", "observed_model", "started_at", "finished_at", "failure", "warnings", "result_complete", "result_truncated", "has_more", "next_cursor")}
print(json.dumps({"receipt": response.relative_to(HERE).as_posix(), **safe}, ensure_ascii=False), flush=True)
