"""Record actual Kimi repair dispatch and retain the rejected delivery."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
dispatch = json.loads((HERE / "route-check/bridge-response-scan-checkpoint-r17-authority.json").read_text(encoding="utf-8"))
assert dispatch["ok"] and dispatch["task_id"] == "task_85cb7c65cb"
path = HERE / "tasks.json"
d = json.loads(path.read_text(encoding="utf-8"))
row = next(row for row in d["tasks"] if row["id"] == "SCAN-CHECKPOINT-R17")
assert row["bridge_task_id"] == "task_c0099a15bb"
proof = json.loads((ROOT / "artifacts/coordinator-checkpoint-r17-authority-probes-20261015/review.json").read_text(encoding="utf-8"))
row.setdefault("history", []).append({"bridge_task_id": row["bridge_task_id"], "actual_execution_at": "2026-10-15T07:23:04.339572+00:00", "finished_at": "2026-10-15T07:47:57.332766+00:00", "observed_model": dispatch["model"], "status": "delivered_rejected_independent_authority_boundary", "producer_final_tests": {"tests": 119, "failures": 0, "errors": 0, "skipped": 0}, "producer_old_probes": {"tests": 9, "failures": 0, "errors": 0, "skipped": 0}, "independent_diagnostic": "artifacts/coordinator-checkpoint-r17-authority-probes-20261015/review.json", "independent_tests": proof["junit"], "independent_acceptance": False, "integrated": False})
row.update(bridge_task_id=dispatch["task_id"], request_id=dispatch["request_id"], accepted_model=dispatch["model"], observed_model=None, status="dispatched_execution_pending", producer_bridge_status="dispatch_accepted", actual_execution_at=None, bridge_finished_at=None, checked_at=at, artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False, dispatch_evidence="route-check/bridge-response-scan-checkpoint-r17-authority.json", current_feedback="followups-r12/checkpoint-r17-authority-feedback.txt")
d["updated_at"] = at
path.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
out = ROOT / "artifacts/coordinator-checkpoint-r17-delivery-review-20261015"
out.mkdir(exist_ok=False)
producer = ROOT / ".coordination/20261014/workspaces/scan-checkpoint-r17"
copied = {}
for source, destination in ((producer / "DELIVERY.md", "DELIVERY-r1.md"), (producer / "artifacts/r17-owned-suites.xml", "producer-final-owned.xml"), (producer / "artifacts/r17-followups-probes.xml", "producer-final-old-probes.xml")):
    shutil.copyfile(source, out / destination)
    copied[destination] = hashlib.sha256((out / destination).read_bytes()).hexdigest()
evidence = {"recorded_at": at, "task_id": "task_c0099a15bb", "copied": copied, "prior_intermediate_observation": {"observed_at": "2026-10-15T15:45:44+08:00", "tests": 60, "failures": 1, "errors": 0, "skipped": 0, "failure": "test_checkpoint_whose_bytes_do_not_match_its_receipt_is_rejected", "raw_initial_junit_preserved": False, "note": "Observed in coordinator read before producer reused the JUnit path for the final119 collection; raw initial JUnit no longer available. This is an observation receipt, not a reconstructed execution result."}, "independent_acceptance": False, "integrated": False}
(out / "receipt.json").write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
contract = ROOT / ".coordination/20261014/workspaces/contract-validation-r12"
out = ROOT / "artifacts/coordinator-contract-r12-r4-context-probes-20261015"
for source, destination in ((contract / "DELIVERY.md", "DELIVERY-r4.md"), (contract / "artifacts/contract-validation-r12/results-contract-validation-r12-final4.xml", "producer-final4.xml")):
    assert not (out / destination).exists()
    shutil.copyfile(source, out / destination)
print(json.dumps({"at": at, "new_task_id": dispatch["task_id"], "rejected_delivery_archived": True, "root_changed": False}))
