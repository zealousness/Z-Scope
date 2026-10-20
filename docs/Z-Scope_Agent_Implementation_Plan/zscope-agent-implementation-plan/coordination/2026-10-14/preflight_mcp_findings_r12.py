"""Fresh public session inventory before assigning the unowned MCP projection gap."""
from pathlib import Path
import json
import time

HERE = Path(__file__).resolve().parent
identity = "r12-mcp-findings-preflight"
route = HERE / "route-check"
request = route / "bridge-queue" / ("080-" + identity + ".request.json")
response = route / ("bridge-response-" + identity + ".json")
assert not request.exists() and not response.exists()
request.write_text(json.dumps({"id":identity,"tool":"list_sessions","arguments":{"active_only":False}})+"\n",encoding="utf-8",newline="\n")
deadline = time.monotonic() + 40
while not response.exists() and time.monotonic() < deadline:
    time.sleep(.25)
if response.exists():
    value = json.loads(response.read_text(encoding="utf-8"))
    sessions = [row for row in value.get("sessions",[]) if row["session_id"] in {"sess_261a55289f","sess_a0adb99b15","sess_3b6b9a19b2"}]
    print(json.dumps({"scope":value.get("scope"),"other_live_instances":value.get("other_live_instances"),"sessions":sessions,"receipt":str(response)},ensure_ascii=False))
