"""Read only the current failed repair and its existing session, no hidden text."""
from pathlib import Path
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
route = HERE / "route-check"
for tool, arguments in (("get_result", {"task_id": "task_14643c6dda", "max_chars": 2000}), ("list_sessions", {"active_only": False})):
    identity = "r20-protocol-" + tool + "-" + uuid4().hex[:10]
    request = route / "bridge-queue" / ("080-" + identity + ".request.json")
    response = route / ("bridge-response-" + identity + ".json")
    request.write_text(json.dumps({"id": identity, "tool": tool, "arguments": arguments}) + "\n", encoding="utf-8", newline="\n")
    until = time.monotonic() + 40
    while not response.exists() and time.monotonic() < until:
        time.sleep(.25)
    assert response.exists()
    raw = json.loads(response.read_text(encoding="utf-8"))
    if tool == "get_result":
        safe = {k: raw.get(k) for k in ("ok", "task_id", "status", "failure", "started_at", "finished_at", "result_complete", "warnings", "observed_model")}
    else:
        session = next(r for r in raw["sessions"] if r["session_id"] == "sess_b91680bb39")
        safe = {"session": session, "other_busy_session_ids": [r["session_id"] for r in raw["sessions"] if r["session_id"] != session["session_id"] and r.get("proc_state") in {"busy", "running"}]}
    print(json.dumps({"receipt": response.relative_to(HERE).as_posix(), **safe}, ensure_ascii=True), flush=True)
