"""Persist one same-session repair turn and archive the rejected delivery."""
from pathlib import Path
import datetime as dt
import json
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
identity, dispatch_label, proof_label = sys.argv[1:4]
assert identity in {"SCAN-CHECKPOINT-R17", "CONTRACT-VALIDATION-R12"}
label = "checkpoint" if identity == "SCAN-CHECKPOINT-R17" else "zcode"
path = HERE / "tasks.json"
d = json.loads(path.read_text(encoding="utf-8"))
row = next(row for row in d["tasks"] if row["id"] == identity)
public = max((HERE / "route-check").glob("bridge-response-r12-current-" + label + "-*.json"), key=lambda p: p.stat().st_mtime_ns)
previous = json.loads(public.read_text(encoding="utf-8"))
assert previous["task_id"] == row["bridge_task_id"] and previous["status"] == "completed"
dispatch = json.loads((HERE / "route-check" / ("bridge-response-" + dispatch_label + ".json")).read_text(encoding="utf-8"))
assert dispatch["ok"] and dispatch["session_id"] == row["bridge_session_id"]
assert dispatch["model"] == row["accepted_model"] and not dispatch["reused"]
proof = json.loads((ROOT / "artifacts" / proof_label / "review.json").read_text(encoding="utf-8"))
assert proof["returncode"] and proof["stable_frozen_inputs"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row.setdefault("history", []).append({"bridge_task_id": previous["task_id"], "actual_execution_at": previous["started_at"], "finished_at": previous["finished_at"], "observed_model": previous["observed_model"], "status": "delivered_rejected_independent_publication_fence", "independent_diagnostic": "artifacts/" + proof_label + "/review.json", "independent_tests": proof["junit"], "independent_acceptance": False, "integrated": False})
producer = ROOT / ".coordination/20261014/workspaces" / row["workspace"]
out = ROOT / "artifacts" / proof_label
target = out / ("DELIVERY-" + previous["task_id"] + ".md")
assert not target.exists()
shutil.copyfile(producer / "DELIVERY.md", target)
row.update(bridge_task_id=dispatch["task_id"], request_id=dispatch["request_id"], observed_model=None, status="dispatched_execution_pending", producer_bridge_status="dispatch_accepted", actual_execution_at=None, bridge_finished_at=None, checked_at=at, artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False, dispatch_evidence="route-check/bridge-response-" + dispatch_label + ".json")
d["updated_at"] = at
path.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "previous_task_id": previous["task_id"], "new_task_id": dispatch["task_id"], "independent_failed": proof["junit"], "root_changed": False}))
