"""Read current R1 tasks through the existing owner, without dispatching."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROUTE = HERE / "route-check"
pending = []
for label, task_id in (("kimi", "task_6e14411a6c"), ("s08", "task_a110e5866a")):
    identifier = f"r6-{label}-current-{uuid4().hex[:10]}"
    request = {"id": identifier, "tool": "check_task", "arguments": {"task_id": task_id}}
    target = ROUTE / "bridge-queue" / f"080-{identifier}.request.json"
    target.write_text(json.dumps(request) + "\n", encoding="utf-8", newline="\n")
    pending.append((label, ROUTE / f"bridge-response-{identifier}.json"))
deadline = time.monotonic() + 45
while any(not path.exists() for _, path in pending) and time.monotonic() < deadline:
    time.sleep(1)
for label, path in pending:
    response = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    compact = {key: response.get(key) for key in ("ok", "task_id", "session_id", "status", "model", "observed_model", "started_at", "finished_at", "silent_for_sec", "failure", "warnings")}
    print(json.dumps({"label": label, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                      "receipt": str(path), "response": compact}, ensure_ascii=True))
