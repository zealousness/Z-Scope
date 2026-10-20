"""Read active tasks via the existing Bridge queue; never start or dispatch."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
stamp = uuid4().hex[:12]
responses = {}
for tool, arguments in (("list_sessions", {"active_only": True}), ("list_agents", {})):
    name = "r21-readonly-" + tool + "-" + stamp
    target = route / "bridge-queue" / ("080-" + name + ".request.json")
    response = route / ("bridge-response-" + name + ".json")
    assert not target.exists() and not response.exists()
    target.write_text(json.dumps({"id": name, "tool": tool, "arguments": arguments}) + "\n", encoding="utf-8", newline="\n")
    responses[tool] = response
until = time.monotonic() + 40
while not all(p.exists() for p in responses.values()) and time.monotonic() < until:
    time.sleep(.25)
assert all(p.exists() for p in responses.values()), "No reply from existing owner; do not launch a second owner"
sessions = json.loads(responses["list_sessions"].read_text(encoding="utf-8"))
agents = json.loads(responses["list_agents"].read_text(encoding="utf-8"))
safe_sessions = [{k: s.get(k) for k in ("session_id", "agent", "model", "proc_state", "current_task_id", "last_task_id", "branch")} for s in sessions.get("sessions", [])]
proof = {"at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "existing_owner_only": True, "dispatch_or_session_resume": False, "archived_sessions_requested": False, "active_sessions": safe_sessions, "coordinator": agents.get("coordinator"), "response_paths": {k: p.relative_to(HERE).as_posix() for k, p in responses.items()}}
target = HERE / "followups-r12" / ("parallel-preflight-r21-" + stamp + ".json")
target.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({**proof, "receipt": target.relative_to(HERE).as_posix()}, ensure_ascii=False), flush=True)
