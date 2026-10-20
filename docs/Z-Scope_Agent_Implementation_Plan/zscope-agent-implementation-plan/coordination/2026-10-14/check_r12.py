"""Public R12 status only; never query or resume the archived S06 session."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
ledger = json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))
for label, task_name in (("kimi", "SCAN-SESSION-R12"), ("checkpoint", "SCAN-CHECKPOINT-R17"), ("zcode", "CONTRACT-VALIDATION-R12"), ("mcp", "MCP-FINDINGS-R12")):
    matching = [row for row in ledger["tasks"] if row["id"] == task_name and row.get("bridge_task_id")]
    if not matching:
        continue
    task = matching[0]["bridge_task_id"]
    identity = "r12-current-" + label + "-" + uuid4().hex[:10]
    request = {"id": identity, "tool": "check_task", "arguments": {"task_id": task}}
    (route / "bridge-queue" / ("080-" + identity + ".request.json")).write_text(json.dumps(request) + "\n", encoding="utf-8", newline="\n")
    response = route / ("bridge-response-" + identity + ".json")
    deadline = time.monotonic() + 40
    while not response.exists() and time.monotonic() < deadline:
        time.sleep(.25)
    if not response.exists():
        print(json.dumps({"label": label, "task_id": task, "state": "public_response_pending", "receipt": str(response)}))
        continue
    value = json.loads(response.read_text(encoding="utf-8"))
    value["recent_activity"] = [item for item in value.get("recent_activity", []) if item.startswith(("tool_call", "plan", "raw", "turn_end"))]
    fields = ("ok", "task_id", "session_id", "status", "model", "observed_model", "started_at", "finished_at", "silent_for_sec", "failure", "warnings", "recent_activity")
    print(json.dumps({"label": label, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(), "receipt": str(response), "response": {key: value.get(key) for key in fields}}, ensure_ascii=False))
