"""Read active state through the original owner with atomic request publication."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4
from bridge_queue_publish_r23 import publish_request

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
stamp = uuid4().hex[:12]
responses = {}
for tool, arguments in (("list_agents", {}), ("list_sessions", {"active_only": True})):
    name = "r23-readonly-" + tool + "-" + stamp
    response = route / ("bridge-response-" + name + ".json")
    assert not response.exists()
    publish_request(route / "bridge-queue", {"id": name, "tool": tool, "arguments": arguments})
    responses[tool] = response
until = time.monotonic() + 40
parsed = {}
while len(parsed) != len(responses) and time.monotonic() < until:
    for tool, path in responses.items():
        if tool not in parsed and path.exists():
            try:
                parsed[tool] = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
    if len(parsed) == len(responses):
        break
    time.sleep(.25)
assert len(parsed) == len(responses), "No original-owner reply: do not start a second owner or blindly retry"
sessions = parsed["list_sessions"]
agents = parsed["list_agents"]
assert sessions["ok"] and agents["ok"]
safe = [{k: s.get(k) for k in ("session_id", "agent", "model", "proc_state", "current_task_id", "last_task_id", "branch")} for s in sessions.get("sessions", [])]
proof = {"at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "existing_owner_only": True, "atomic_request_publication": True, "dispatch_or_session_resume": False, "archived_sessions_requested": False, "active_sessions": safe, "coordinator": agents.get("coordinator"), "response_paths": {k: p.relative_to(HERE).as_posix() for k, p in responses.items()}}
target = HERE / "followups-r12" / ("parallel-preflight-r23-" + stamp + ".json")
target.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({**proof, "receipt": target.relative_to(HERE).as_posix()}, ensure_ascii=False), flush=True)
