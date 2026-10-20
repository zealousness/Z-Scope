"""Record the actual new dispatch and preserve rejected R4 evidence."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
dispatch = json.loads((HERE / "route-check/bridge-response-contract-validation-r12-context.json").read_text(encoding="utf-8"))
assert dispatch["ok"] and dispatch["task_id"] == "task_0dc5e073f3"
p = HERE / "tasks.json"
d = json.loads(p.read_text(encoding="utf-8"))
row = next(row for row in d["tasks"] if row["id"] == "CONTRACT-VALIDATION-R12")
assert row["bridge_task_id"] == "task_04ef519648"
diagnostic = json.loads((ROOT / "artifacts/coordinator-contract-r12-r4-context-probes-20261015/review.json").read_text(encoding="utf-8"))
row.setdefault("history", []).append({"bridge_task_id": row["bridge_task_id"], "status": "completed_delivery_rejected_independent_context_boundary", "finished_at": "2026-10-15T07:33:22.133369+00:00", "observed_model": dispatch["model"], "producer_tests": {"tests": 947, "passed": 936, "failed": 11, "errors": 0, "skipped": 0}, "independent_original_boundary": {"tests": 16, "passed": 16, "failed": 0}, "independent_extended_boundary": diagnostic["junit"], "independent_diagnostic": "artifacts/coordinator-contract-r12-r4-context-probes-20261015/review.json", "independent_acceptance": False, "integrated": False})
for field in ("owns", "write_paths"):
    assert "zscope/semantics/resource_coverage.py" not in row[field]
    row[field].append("zscope/semantics/resource_coverage.py")
row.update(bridge_task_id=dispatch["task_id"], request_id=dispatch["request_id"], accepted_model=dispatch["model"], observed_model=None, status="dispatched_execution_pending", producer_bridge_status="dispatch_accepted", actual_execution_at=None, bridge_finished_at=None, checked_at=at, artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False, dispatch_evidence="route-check/bridge-response-contract-validation-r12-context.json", current_feedback="followups-r12/contract-r12-context-feedback.txt", current_ownership_extension="followups-r12/contract-validation-r12-ownership-extension-r5.json", readonly_test_migration="followups-r12/contract-test-migration-ready-r17.json")
d["updated_at"] = at
p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
p = HERE / "followups-r12/contract-validation-r12-ownership-extension-r5.json"
e = json.loads(p.read_text(encoding="utf-8"));e["authorization_recorded_at"] = at
p.write_text(json.dumps(e, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task_id": dispatch["task_id"], "r4_rejected": diagnostic["junit"], "root_changed": False}))
