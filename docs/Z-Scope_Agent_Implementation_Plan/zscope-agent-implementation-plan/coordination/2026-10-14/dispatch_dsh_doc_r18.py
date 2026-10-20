"""One authorized fixed documentation task on the verified dedicated DSH route."""
from pathlib import Path
import json
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "dsh-native"
agents = json.loads((route / "bridge-response-r18-public-agents.json").read_text(encoding="utf-8"))
assert agents["ok"] and agents["coordinator"]["dispatch_enabled"] and agents["coordinator"]["runtime_context"] == "coordinator"
assert next(r for r in agents["agents"] if r["agent"] == "dsh")["available"]
sessions = json.loads((route / "bridge-response-r18-public-sessions.json").read_text(encoding="utf-8"))
session = next(r for r in sessions["sessions"] if r["session_id"] == "sess_bdab8c13fb")
assert session["proc_state"] in {"idle_unloaded", "ready"} and session["model"] == "deepseek/deepseek-v4.1-flash"
name = "doc-identity-r18"
request = {"id": name, "branch": name, "tool": "dispatch_task", "arguments": {
    "agent": "dsh", "cwd": str(ROOT), "title": "DOC-IDENTITY-R18", "session_id": session["session_id"],
    "model": "deepseek/deepseek-v4.1-flash", "request_id": str(uuid4()), "user_requested": True,
    "message": (HERE / "followups-r12/doc-identity-r18-message.txt").read_text(encoding="utf-8"),
}}
archive = HERE / "followups-r12/doc-identity-r18-request.json"
target = route / "bridge-queue/080-doc-identity-r18.request.json"
assert not archive.exists() and not target.exists()
archive.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
target.write_bytes(archive.read_bytes())
print(json.dumps({"queued_once": True, "request_id": request["arguments"]["request_id"], "route": str(route), "public_dispatch_allowed": True}))
