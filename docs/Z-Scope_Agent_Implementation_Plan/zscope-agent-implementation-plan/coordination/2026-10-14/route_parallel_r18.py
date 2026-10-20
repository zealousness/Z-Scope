"""Submit isolated R18 work through the existing durable Bridge queue."""
from pathlib import Path
import json
from uuid import uuid4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ROUTE = HERE / "route-check"

original = json.loads((HERE / "followups-r12/validation-context-r18-request.json").read_text(encoding="utf-8"))
# The owner explicitly rejected this before journal.claim/public dispatch.
log = (ROUTE / "post-update-owner-stdout.log").read_text(encoding="utf-8")
assert '"request": "validation-context-r18", "ok": false, "error": "durable_request_id_and_branch_required"' in log
assert not (ROUTE / "bridge-response-validation-context-r18.json").exists()
fixed = {**original, "id": "validation-context-r18-routed", "branch": "validation-context-r18"}
stop = {"id": "config-stop-at-r18", "branch": "config-stop-at-r18", "tool": "dispatch_task", "arguments": {
    "agent": "zcode", "cwd": str(ROOT), "title": "U01-STOP-AT-R18",
    "message": (HERE / "followups-r12/config-stop-at-r18-message.txt").read_text(encoding="utf-8"),
    "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "request_id": str(uuid4()), "user_requested": True,
}}
for request in (fixed, stop):
    archive = HERE / "followups-r12" / (request["id"] + "-request.json")
    target = ROUTE / "bridge-queue" / ("080-" + request["id"] + ".request.json")
    assert not archive.exists() and not target.exists()
    archive.write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    target.write_bytes(archive.read_bytes())
    print(json.dumps({"queued": request["id"], "branch": request["branch"], "request_id": request["arguments"]["request_id"], "not_yet_accepted": True}), flush=True)
for label, task in (("checkpoint", "task_280df74eca"), ("contract", "task_0dc5e073f3")):
    identity = "r18-terminal-" + label
    target = ROUTE / "bridge-queue" / ("080-" + identity + ".request.json")
    assert not target.exists()
    target.write_text(json.dumps({"id": identity, "tool": "check_task", "arguments": {"task_id": task}}) + "\n", encoding="utf-8", newline="\n")
