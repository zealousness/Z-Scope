"""Fetch the completed public result once through the existing owner."""
from pathlib import Path
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
name = "r19-context-repair-result-" + uuid4().hex[:10]
route = HERE / "route-check"
request = {"id": name, "tool": "get_result", "arguments": {"task_id": "task_bf7efdfce3", "max_chars": 18000}}
(route / "bridge-queue" / ("080-" + name + ".request.json")).write_text(json.dumps(request) + "\n", encoding="utf-8", newline="\n")
response = route / ("bridge-response-" + name + ".json")
deadline = time.monotonic() + 40
while not response.exists() and time.monotonic() < deadline:
    time.sleep(.25)
assert response.exists()
value = json.loads(response.read_text(encoding="utf-8"))
print(json.dumps({"receipt": str(response), "public_fields": list(value), "result": value.get("result")}, ensure_ascii=False), flush=True)
