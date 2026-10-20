"""Freeze the third actual S01 delivery without dispatching a fourth turn."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/s01-instance-semantics-min-r23"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

joint = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in joint.items())
dependency = read(ROOT / "artifacts/coordinator-s01-module-dependency-r26-20261016/review.json")
origin = read(ROOT / "artifacts/coordinator-s01-origin-forms-r26-20261016/review.json")
assert dependency["actual_producer_task_id"] == "task_f702313db8"
assert dependency["junit"] == dict(tests=160, failures=0, errors=0, skipped=0) and dependency["module_dependency_checks_passed"]
assert dependency["source_unchanged"] and dependency["root_unchanged"] and dependency["producer_junit_case_identities_preserved"]
assert origin["junit"] == dict(tests=3, failures=2, errors=0, skipped=0)
assert origin["sources_unchanged"] and origin["root_unchanged"]
assert all(sha(BRANCH / path) == digest for path, digest in dependency["source_after"].items())
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "S01-INSTANCE-SEMANTICS-MIN-R23")
assert row["bridge_task_id"] == "task_f702313db8" and row["producer_status"] == "completed"
assert row["consecutive_failed_actual_deliveries"] == 2 and len(row["glm_delivery_rounds"]) == 2
target = ROOT / "artifacts/s01-origin-forms-probe-r26-20261016/failed-candidate"
target.mkdir(exist_ok=False)
for path in row["write_paths"] + ["DELIVERY.md"]:
    (target / path).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(BRANCH / path, target / path)
shutil.copytree(BRANCH / "artifacts/instance-semantics-r23", target / "artifacts/instance-semantics-r23")
frozen = {path.relative_to(target).as_posix(): sha(path) for path in target.rglob("*") if path.is_file()}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
round_two = dict(round=3, task_id="task_f702313db8", producer_finished_at=row["worker_finished_at"], independent_result="160/0/0/0; four commands0. Additional real native same-ABI declaration-source probes:1pass/2fail/0error/0skip. Joined -isystem and a project-relative pragma-system header still mint builtin malloc authority.", evidence="artifacts/coordinator-s01-module-dependency-r26-20261016/review.json", authority_evidence="artifacts/coordinator-s01-origin-forms-r26-20261016/review.json", counted_development_failure=True, ownership_note="The same originally required standard declaration-source authority obligation remains unmet; two probes are one third-delivery failure, not two rounds.", coordinator_errors_excluded=True, public_owner_gap="Original owner exited; current attached public check/get_result return unknown task. Persisted terminal/result/dispatch independently reconciled in coordinator-resume-r26 receipt. No fourth dispatch or service restart.")
row["glm_delivery_rounds"].append(round_two)
row.update(consecutive_failed_actual_deliveries=3, status="third_actual_delivery_failed_standard_origin_source_fourth_not_dispatched_original_owner_unavailable", independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at, module_dependency_review=round_two["evidence"], independent_origin_failure_evidence=round_two["authority_evidence"], frozen_failed_candidate_r26=target.relative_to(ROOT).as_posix())
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
proof = dict(recorded_at=at, task_id="task_f702313db8", logical_task=row["id"], source_after=dependency["source_after"], frozen_files=frozen, frozen_candidate=target.relative_to(ROOT).as_posix(), round=round_two, root_bound_inputs_unchanged=len(joint), independent_acceptance=False, integrated=False, joint_verification=False, fourth_dispatched=False, original_owner_public_interface_available=False)
write(ROOT / "artifacts/s01-origin-forms-probe-r26-20261016/failure-review.json", proof)
assert all(sha(ROOT / path) == digest for path, digest in joint.items())
print(json.dumps(dict(at=at, task_id=row["bridge_task_id"], consecutive_failed_actual_deliveries=3, frozen_candidate=proof["frozen_candidate"], frozen_files=len(frozen), root_bound_inputs_unchanged=len(joint), fourth_dispatched=False)))
