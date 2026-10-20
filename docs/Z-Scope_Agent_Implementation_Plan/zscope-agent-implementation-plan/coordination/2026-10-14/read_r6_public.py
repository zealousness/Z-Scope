"""One read-only result/transcript request to the existing Bridge owner."""
from pathlib import Path
import json
import sys
import time
from uuid import uuid4

sys.stdout.reconfigure(encoding="utf-8")

HERE = Path(__file__).resolve().parent
ROUTE = HERE / "route-check"
tool = sys.argv[1]
assert tool in {"get_result", "get_transcript"}
arguments = json.loads(sys.argv[2])
current_ids = {row.get("bridge_task_id") for row in json.loads((HERE/"tasks.json").read_text(encoding="utf-8"))["tasks"] if row["id"] in {"SCAN-SESSION-R12","SCAN-CHECKPOINT-R17","CONTRACT-VALIDATION-R12","MCP-FINDINGS-R12"}}
if arguments.get("task_id") in current_ids:
    arguments["session_id"] = next(row["bridge_session_id"] for row in json.loads((HERE/"tasks.json").read_text(encoding="utf-8"))["tasks"] if row.get("bridge_task_id") == arguments["task_id"])
assert arguments.get("task_id") in {"task_9e8e7e3dc4", "task_b41bc0eb99", "task_09da468c8a", "task_c1fb932358", "task_8088785d9b", "task_a110e5866a", "task_6e14411a6c", "task_9579265ee7", "task_2f3f99db9b", "task_0afb819799", "task_feb229984d", "task_1cee9c8e9d", "task_315195c1a1", "task_a3a56d31b4", "task_abdc75ecbf"} or arguments.get("session_id") in {"sess_261a55289f", "sess_3b6b9a19b2", "sess_a0adb99b15"}
identifier = f"r6-public-{uuid4().hex[:10]}"
target = ROUTE / "bridge-queue" / f"080-{identifier}.request.json"
target.write_text(json.dumps({"id": identifier, "tool": tool, "arguments": arguments}) + "\n", encoding="utf-8", newline="\n")
response = ROUTE / f"bridge-response-{identifier}.json"
deadline = time.monotonic() + 45
while not response.exists() and time.monotonic() < deadline:
    time.sleep(1)
if not response.exists():
    print(json.dumps({"receipt": str(response), "pending": True}))
    sys.exit(0)
data = json.loads(response.read_text(encoding="utf-8"))
compact = {key: data.get(key) for key in ("ok", "task_id", "status", "observed_model", "failure", "warnings", "result_complete", "has_more", "next_cursor", "total_matching")}
compact["receipt"] = str(response)
if tool == "get_result":
    compact["result_text_tail"] = str(data.get("result_text", ""))[-4000:]
else:
    compact["events"] = [{"ts": event.get("ts"), "type": event.get("type"), "data": {key: event.get("data", {}).get(key) for key in ("status", "title", "tool_call_id")}} for event in data.get("events", [])]
print(json.dumps(compact, ensure_ascii=False))
