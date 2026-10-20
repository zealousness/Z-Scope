from pathlib import Path
import json
import time
from uuid import uuid4
from bridge_queue_publish_r23 import publish_request

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
name = "r25-s08-repair-result-" + uuid4().hex[:12]
response = route / ("bridge-response-" + name + ".json")
publish_request(route / "bridge-queue", dict(id=name, tool="get_result", arguments=dict(task_id="task_8886dcf232", max_chars=60000)))
until = time.monotonic() + 40
while time.monotonic() < until:
    if response.exists():
        try:
            value = json.loads(response.read_text(encoding="utf-8"))
            break
        except json.JSONDecodeError:
            pass
    time.sleep(.25)
else:
    raise RuntimeError("Unknown owner response; inspect persisted request only")
assert value.get("task_id") == "task_8886dcf232" and value.get("status") == "completed"
print(json.dumps({k: value.get(k) for k in ("task_id", "session_id", "status", "observed_model", "finished_at", "has_more", "next_cursor", "error", "failure", "warnings")}, ensure_ascii=False))
print(response.relative_to(HERE).as_posix())
