"""Read original Bridge owner state before the human-requested ZCode handover."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
pending = []
for label, tool, arguments in (("agents", "list_agents", {}), ("sessions", "list_sessions", {"active_only": False})):
    identity = "r18-handover-" + label + "-" + uuid4().hex[:10]
    target = route / "bridge-queue" / ("080-" + identity + ".request.json")
    target.write_text(json.dumps({"id": identity, "tool": tool, "arguments": arguments}) + "\n", encoding="utf-8", newline="\n")
    pending.append((label, route / ("bridge-response-" + identity + ".json")))
deadline = time.monotonic() + 40
while not all(path.exists() for _, path in pending) and time.monotonic() < deadline:
    time.sleep(.25)
for label, path in pending:
    assert path.exists(), path
    data = json.loads(path.read_text(encoding="utf-8"))
    if label == "sessions":
        selected = [{key: row.get(key) for key in ("session_id", "agent", "proc_state", "last_task_id", "model")} for row in data["sessions"] if row["session_id"] in {"sess_261a55289f", "sess_3b6b9a19b2", "sess_a0adb99b15"}]
    else:
        selected = {key: data.get(key) for key in ("ok", "coordinator", "dispatch_enabled")}
    print(json.dumps({"checked_at": dt.datetime.now(dt.timezone.utc).isoformat(), "kind": label, "receipt": str(path), "public": selected}, ensure_ascii=True))
