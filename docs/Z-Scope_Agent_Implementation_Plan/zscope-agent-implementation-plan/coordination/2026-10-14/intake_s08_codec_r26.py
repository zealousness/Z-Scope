"""Accept the independently reviewed codec into coordinator isolation only."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys

if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("Only non-optimized Linux Python may perform intake guards")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORKER = ROOT / ".coordination/20261014/workspaces/s08-instance-recovery-min-r23"
OUT = ROOT / "artifacts/s08-codec-stage-intake-r26-20261016"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

owned = {
    "zscope/orchestration/jobs/instance_results.py": "9de13639e71fde76bad742dd3aa90f1cc9fb51b7c37b758291ca504be94b1a80",
    "tests/test_instance_result_recovery.py": "b33dc8a8029456f1fae9261833a967206dc66cead0f26023967be25f7bd47a31",
}
review_path = ROOT / "artifacts/s08-module-source-review-r26-20261016/review.json"
assert sha(review_path) == "289f159174e79b644b64b3280b9f4ee7afe911308743a964c683fc3cc8b0baa8"
review = read(review_path)
assert review["source_review_passed"] and review["blocking_findings"] == []
assert review["candidate"]["actual_task_id"] == "task_0d7256802a"
assert all(sha(ROOT / path) == digest for path, digest in review["evidence_sha256"].items())
execution_path = ROOT / "artifacts/coordinator-s08-module-dependency-r26-20261016/review.json"
execution = read(execution_path)
assert execution["module_dependency_checks_passed"]
assert execution["junit"] == dict(tests=321, failures=0, errors=0, skipped=0)
assert all(result["returncode"] == 0 for result in execution["commands"])
assert execution["source_unchanged"] and execution["root_unchanged"]
assert execution["producer_junit_case_identities_preserved"] and execution["references_unchanged"]
assert all(sha(WORKER / path) == digest for path, digest in execution["source_after"].items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
baseline = read(HERE / "followups-r12/coordinator-instance-integration-r24-baseline.json")
expected = {entry["path"]: entry["sha256"] for entry in baseline["files"]}
allowed = set(baseline["task"]["write_paths"])
for suffix in ("01", "02", "03"):
    allowed.update(read(HERE / "followups-r12" / ("coordinator-instance-integration-r24-ownership-extension-" + suffix + ".json"))["write_paths"])
assert not set(owned) & allowed
assert all(sha(STAGE / path) == digest for path, digest in expected.items() if path not in allowed)
def check_unknown(extra=()):
    for directory in ("zscope", "scripts", "test", "tests", "docs/modules"):
        for path in (STAGE / directory).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                assert path.relative_to(STAGE).as_posix() in set(expected) | allowed | set(extra)

check_unknown()
assert all(not (STAGE / path).exists() and not (ROOT / path).exists() for path in owned)
assert all(sha(WORKER / path) == digest for path, digest in owned.items())
ledger_bytes = (HERE / "tasks.json").read_bytes()
ledger = json.loads(ledger_bytes.decode("utf-8"))
ledger_before = hashlib.sha256(ledger_bytes).hexdigest()
row = next(row for row in ledger["tasks"] if row["id"] == "S08-INSTANCE-RECOVERY-MIN-R23")
assert row["bridge_task_id"] == "task_0d7256802a" and row["producer_status"] == "completed"
assert len(row["glm_delivery_rounds"]) == 2 and row["consecutive_failed_actual_deliveries"] == 2
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
extension_path = HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-04.json"
assert not extension_path.exists()
references = {str(path): sha(path) for path in [Path(__file__), review_path, execution_path, HERE / "followups-r12/coordinator-instance-integration-r24-baseline.json", *[HERE / "followups-r12" / ("coordinator-instance-integration-r24-ownership-extension-" + suffix + ".json") for suffix in ("01", "02", "03")], *[ROOT / relative for relative in review["evidence_sha256"]]]}
OUT.mkdir(exist_ok=False)
write(extension_path, dict(coordinator_authorized=True, write_paths=list(owned), source_sha256=owned, actual_producer_task_id=row["bridge_task_id"], source_review=review_path.relative_to(ROOT).as_posix(), source_review_sha256=sha(review_path), independent_review=execution_path.relative_to(ROOT).as_posix(), independent_review_sha256=sha(execution_path), reason="Copy only the independently accepted MIN codec into coordinator isolation for consumer integration. Root writes forbidden; no failed S01 file copied; producer ownership unchanged."))
references[str(extension_path)] = sha(extension_path)
for path in owned:
    (STAGE / path).parent.mkdir(parents=True, exist_ok=True)
    (STAGE / path).write_bytes((WORKER / path).read_bytes())
assert all(sha(STAGE / path) == digest for path, digest in owned.items())
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert all(not (ROOT / path).exists() for path in owned)
assert all(sha(WORKER / path) == digest for path, digest in execution["source_after"].items())
assert all(sha(STAGE / path) == digest for path, digest in expected.items() if path not in allowed)
assert all(sha(Path(path)) == digest for path, digest in references.items())
check_unknown(owned)
assert sha(HERE / "tasks.json") == ledger_before, "Concurrent task ledger change; do not overwrite it"
row["glm_delivery_rounds"].append(dict(round=3, task_id=row["bridge_task_id"], producer_finished_at=row["worker_finished_at"], independent_result="321/0/0/0; four commands0; source review no codec blockers", evidence=execution_path.relative_to(ROOT).as_posix(), source_review=review_path.relative_to(ROOT).as_posix(), counted_development_failure=False, accepted_scope="isolated MIN codec only", parent_s08_complete=False))
row.update(status="isolated_codec_independently_accepted_copied_to_coordinator_stage_only", independent_acceptance=True, independent_acceptance_scope="isolated MIN codec; excludes current Store/Queue/Ledger consumers, complete S08, Root intake and joint recovery", checked_at=at, prior_failed_actual_deliveries_before_acceptance=2, consecutive_failed_actual_deliveries=0, integrated=False, coordinator_stage_intake=True, joint_verification=False, module_dependency_review=execution_path.relative_to(ROOT).as_posix(), source_review=review_path.relative_to(ROOT).as_posix(), codec_acceptance_receipt=(OUT / "receipt.json").relative_to(ROOT).as_posix())
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
proof = dict(recorded_at=at, actual_producer_task_id=row["bridge_task_id"], actual_coordinator_task="/root", logical_task=row["id"], accepted_scope=row["independent_acceptance_scope"], source_sha256=owned, source_review=review_path.relative_to(ROOT).as_posix(), source_review_sha256=sha(review_path), independent_review=execution_path.relative_to(ROOT).as_posix(), independent_review_sha256=sha(execution_path), junit=execution["junit"], four_commands_zero=True, producer_finished_at=row["worker_finished_at"], independent_finished_at=execution["finished_at"], original_owner_public_interface_available=False, identity_basis="Preserved original-owner terminal/dispatch/result artifact binding; current public interface returns unknown task. No fresh live Bridge confirmation claimed.", destination=STAGE.relative_to(ROOT).as_posix(), stage_intake=True, root_intake=False, parent_s08_independent_acceptance=False, joint_verification=False, whole_packages_complete=False, previous_failed_delivery_history_retained=2, min_codec_consecutive_failed_deliveries_after_independent_acceptance=0, source_unchanged=True, root_bound_inputs_unchanged=len(root_inputs), services_started=0, dispatches=0, tests_executed_by_intake=0)
proof["references_sha256"] = references
proof["references_unchanged"] = True
proof["commit_ledger_sha256_before"] = ledger_before
proof["commit_ledger_sha256_after"] = sha(HERE / "tasks.json")
write(OUT / "receipt.json", proof)
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(dict(at=at, task_id=row["bridge_task_id"], codec_accepted=True, stage_only=True, root_intake=False, receipt=(OUT / "receipt.json").relative_to(ROOT).as_posix())))
