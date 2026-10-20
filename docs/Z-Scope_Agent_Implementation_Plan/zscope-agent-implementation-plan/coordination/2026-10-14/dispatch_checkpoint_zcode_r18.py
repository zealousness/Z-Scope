"""One human-requested ZCode handover; never dispatch to the idle Kimi session."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import time
from uuid import uuid4

HERE = Path(__file__).resolve().parent;ROOT = HERE.parents[4];route = HERE / "route-check"
name = "checkpoint-zcode-r18"
assert (HERE / "followups-r12" / (name + "-baseline.json")).exists()
root = json.loads((ROOT / "artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in root["after"].items())
identity = name + "-preflight"
request = route / "bridge-queue" / ("080-" + identity + ".request.json")
response = route / ("bridge-response-" + identity + ".json")
assert not request.exists() and not response.exists()
request.write_text(json.dumps({"id": identity, "tool": "list_sessions", "arguments": {"active_only": False}}) + "\n", encoding="utf-8", newline="\n")
deadline = time.monotonic() + 40
while not response.exists() and time.monotonic() < deadline:time.sleep(.25)
data = json.loads(response.read_text(encoding="utf-8"))
session = next(row for row in data["sessions"] if row["session_id"] == "sess_3b6b9a19b2")
assert session["proc_state"] in {"ready", "idle_unloaded"}
original = json.loads((HERE / "followups-r12/mcp-findings-r12-request.json").read_text(encoding="utf-8"))
arguments = dict(original["arguments"])
arguments.update(title="CHECKPOINT-ZCODE-R18", request_id=str(uuid4()), message=(HERE / "followups-r12/checkpoint-zcode-r18-message.txt").read_text(encoding="utf-8"), user_requested=True)
assert arguments["session_id"] == "sess_3b6b9a19b2" and arguments["model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
dispatch = {"id": name, "branch": name, "tool": "dispatch_task", "arguments": arguments}
archive = HERE / "followups-r12" / (name + "-request.json")
target = route / "bridge-queue" / ("080-" + name + ".request.json")
assert not archive.exists() and not target.exists()
archive.write_text(json.dumps(dispatch, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n");target.write_bytes(archive.read_bytes())
response = route / ("bridge-response-" + name + ".json")
deadline = time.monotonic() + 40
while not response.exists() and time.monotonic() < deadline:time.sleep(.25)
if not response.exists():
    print(json.dumps({"queued_once": True, "response_pending": str(response)}));raise SystemExit(0)
dispatch_result = json.loads(response.read_text(encoding="utf-8"));assert dispatch_result["ok"]
path = HERE / "tasks.json";ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(row for row in ledger["tasks"] if row["id"] == "SCAN-CHECKPOINT-R17")
assert row["bridge_task_id"] == "task_b21e0df6a7"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row.setdefault("history", []).append({"bridge_task_id": row["bridge_task_id"], "workspace": row["workspace"], "model": row["accepted_model"], "finished_at": "2026-10-15T08:13:47.188658+00:00", "independent_regression_slice": "artifacts/coordinator-checkpoint-r17-fenced-acceptance-20261015/review.json", "slice_tests_passed": 433, "quality_commands_passed": 4, "known_dependency_rejection": "artifacts/coordinator-checkpoint-r17-dependency-uri-probes-20261015/review.json", "dependency_tests_failed": 3, "whole_checkpoint_acceptance": False, "integrated": False, "frozen": True})
baseline = json.loads((HERE / "followups-r12" / (name + "-baseline.json")).read_text(encoding="utf-8"))
row.update({key: value for key, value in baseline["task"].items() if key in {"owner", "agent", "model", "requested_model", "session_id", "bridge_session_id", "workspace", "isolated_workspace", "isolated_workspace_linux"}})
row.update(bridge_task_id=dispatch_result["task_id"], accepted_model=arguments["model"], observed_model=None, request_id=dispatch_result["request_id"], status="dispatched_execution_pending", producer_bridge_status="dispatch_accepted", actual_execution_at=None, bridge_finished_at=None, baseline_receipt="followups-r12/" + name + "-baseline.json", dispatch_evidence=response.relative_to(HERE).as_posix(), current_feedback="followups-r12/checkpoint-zcode-r18-message.txt", artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False, checked_at=at, handover_reason="Human requested subsequent work go to ZCode; not timeout/review bypass.")
ledger["updated_at"] = at
ledger["current_worker_policy"] = {"recorded_at": at, "non_ui_development_and_repairs": "ZCode glm-5.3", "kimi_new_dispatch": False, "ui": "Astra", "evidence": "Trusted source-thread delegation conveying the human's updated assignment instruction."}
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task_id": dispatch_result["task_id"], "session_id": dispatch_result["session_id"], "workspace": name, "old_kimi_frozen": True, "root_changed": False}))
