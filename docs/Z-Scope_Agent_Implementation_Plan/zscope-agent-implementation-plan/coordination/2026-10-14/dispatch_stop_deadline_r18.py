"""One native-model same-session repair of the actual shared-token deadline gap."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
name = "config-stop-at-r18-deadline"
identity = name + "-preflight"
target = route / "bridge-queue" / ("080-" + identity + ".request.json")
assert not target.exists()
target.write_text(json.dumps({"id": identity, "tool": "list_sessions", "arguments": {"active_only": False}}) + "\n", encoding="utf-8", newline="\n")
response = route / ("bridge-response-" + identity + ".json")
deadline = time.monotonic() + 40
while not response.exists() and time.monotonic() < deadline: time.sleep(.25)
assert response.exists()
session = next(r for r in json.loads(response.read_text(encoding="utf-8"))["sessions"] if r["session_id"] == "sess_b91680bb39")
assert session["proc_state"] in {"ready", "idle_unloaded"} and session["model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
extension = HERE / "followups-r12/config-stop-at-r18-ownership-extension-deadline.json"
assert not extension.exists()
extension.write_text(json.dumps({"at": dt.datetime.now(dt.timezone.utc).isoformat(), "coordinator_authorized": True, "write_paths": ["zscope/common/cancellation.py"], "reason": "Actual shared session token hides stop budget from HTTP consumers; two independently reproduced failures. Prospective extension only.", "evidence": "artifacts/coordinator-stop-deadline-r18-probes-20261015/review.json"}, indent=2) + "\n", encoding="utf-8", newline="\n")
request = {"id": name, "branch": "config-stop-at-r18", "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": str(ROOT), "title": "U01-STOP-AT-R18-DEADLINE", "session_id": session["session_id"], "model": session["model"], "request_id": str(uuid4()), "user_requested": True, "message": (HERE / "followups-r12/config-stop-at-r18-deadline-message.txt").read_text(encoding="utf-8")}}
archive = HERE / "followups-r12" / (name + "-request.json")
target = route / "bridge-queue" / ("080-" + name + ".request.json")
assert not archive.exists() and not target.exists()
archive.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
target.write_bytes(archive.read_bytes())
print(json.dumps({"queued_once": True, "request_id": request["arguments"]["request_id"], "same_session": session["session_id"]}), flush=True)
