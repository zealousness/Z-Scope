"""One same-session repair after native callee isolation rejects the delivery."""
from pathlib import Path
import datetime as dt
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
name = "validation-context-r18-callee"
identity = name + "-preflight"
target = route / "bridge-queue" / ("080-" + identity + ".request.json")
assert not target.exists()
target.write_text(json.dumps({"id": identity, "tool": "list_sessions", "arguments": {"active_only": False}}) + "\n", encoding="utf-8", newline="\n")
response = route / ("bridge-response-" + identity + ".json")
deadline = time.monotonic() + 40
while not response.exists() and time.monotonic() < deadline: time.sleep(.25)
assert response.exists()
sessions = json.loads(response.read_text(encoding="utf-8"))
session = next(r for r in sessions["sessions"] if r["session_id"] == "sess_a0adb99b15")
assert session["proc_state"] in {"ready", "idle_unloaded"}
assert session["model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
extension = HERE / "followups-r12/validation-context-r18-ownership-extension-callee.json"
assert not extension.exists()
extension.write_text(json.dumps({"at": dt.datetime.now(dt.timezone.utc).isoformat(), "coordinator_authorized": True, "write_paths": ["zscope/semantics/call_context.py"], "reason": "Two actual native callee rebinding failures; prospective extension only. Prior five files remain owned, all other paths readonly.", "evidence": "artifacts/coordinator-validation-callee-r18-probes-20261015/review.json"}, indent=2) + "\n", encoding="utf-8", newline="\n")
message = (HERE / "followups-r12/validation-context-r18-callee-message.txt").read_text(encoding="utf-8").replace("docs/.../coordination", "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination")
request = {"id": name, "branch": "validation-context-r18", "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": str(ROOT), "title": "VALIDATION-CONTEXT-R18-CALLEE", "session_id": session["session_id"], "model": session["model"], "request_id": str(uuid4()), "user_requested": True, "message": message}}
archive = HERE / "followups-r12" / (name + "-request.json")
target = route / "bridge-queue" / ("080-" + name + ".request.json")
assert not archive.exists() and not target.exists()
archive.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
target.write_bytes(archive.read_bytes())
print(json.dumps({"queued_once": True, "request_id": request["arguments"]["request_id"], "same_session": session["session_id"], "branch": request["branch"]}), flush=True)
