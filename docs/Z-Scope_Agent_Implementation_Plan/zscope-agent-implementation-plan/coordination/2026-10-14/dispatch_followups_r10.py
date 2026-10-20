"""Queue each prepared UUID once on the existing public MCP owner."""
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
policy = json.loads((route / "bridge-response-r10-preflight-agents.json").read_text(encoding="utf-8"))
sessions = json.loads((route / "bridge-response-r10-preflight-sessions.json").read_text(encoding="utf-8"))
assert policy["coordinator"]["dispatch_enabled"] and policy["coordinator"]["runtime_context"] == "coordinator"
states = {row["session_id"]: row["proc_state"] for row in sessions["sessions"]}
prepared = json.loads((HERE / "followups-r10/prepared.json").read_text(encoding="utf-8"))
for task in prepared["tasks"]:
    if task["agent"] == "Astra":
        continue
    assert states[task["session_id"]] in {"idle_unloaded", "ready"}, task
    request_path = HERE / "followups-r10" / (task["workspace"] + "-request.json")
    request = json.loads(request_path.read_text(encoding="utf-8"))
    target = route / "bridge-queue" / ("100-" + task["workspace"] + ".request.json")
    with target.open("x",encoding="utf-8",newline="\n") as stream:
        stream.write(json.dumps(request,ensure_ascii=False)+"\n")
    print(json.dumps({"request":request["id"],"uuid":request["arguments"]["request_id"],"status":"queued_on_existing_owner"}))
