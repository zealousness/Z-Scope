"""Advance only the delivered/independent-execution state, without acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


producer_path = ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29/artifacts/consumer-exact-repair-r29/review.json"
assert sha(producer_path) == "6e59aa5d3119ba21beadecebab746d66e1ed267a800956fcf4f010a36485ea13"
producer = read(producer_path)
assert producer["candidate_repair_complete"] and not producer["independent_acceptance"]
assert producer["final_junit"] == dict(tests=893, failures=0, errors=0, skipped=0)
freeze_path = ROOT / "artifacts/consumer-repair-coordinator-inputs-r29-20261017/frozen-inputs.json"
freeze = read(freeze_path)
assert freeze["producer_frozen"] and len(freeze["source_after"]) == 1071
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
status = dict(recorded_at=at, logical_task="CONSUMER-EXACT-REPAIR-R29", actual_task="/root/consumer_exact_repair_r29", producer_status="completed_frozen", frozen_at=producer["frozen_at"], producer_review=producer_path.relative_to(ROOT).as_posix(), producer_review_sha256=sha(producer_path), producer_junit=producer["final_junit"], producer_quality_completed=True, frozen_inputs=freeze_path.relative_to(ROOT).as_posix(), frozen_inputs_sha256=sha(freeze_path), coordinator_execution="launched through one outer WSL/Linux test_slot, slot0 acquired; receipt pending", independent_source_reviewer="/root/consumer_source_review_r28", independent_acceptance=False, integrated=False, root_joint_verification=False, prior_failed_actual_deliveries_preserved=1, s01_count_unchanged=3)
out = ROOT / "artifacts/coordinator-current-verification-r29-20261017/consumer-repair-frozen-status.json"
assert not out.exists()
write(out, status)
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "CONSUMER-EXACT-REPAIR-R29")
row.update(status="producer_frozen_893_selftests_all_quality_passed_independent_execution_and_source_review_running", producer_status="completed", artifact_available=True, worker_finished_at=producer["frozen_at"], producer_review=status["producer_review"], producer_result=producer["final_junit"], frozen_status_receipt=out.relative_to(ROOT).as_posix(), independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
parent = next(row for row in ledger["tasks"] if row["id"] == "ASTRA-INSTANCE-CONSUMERS-R25")
parent.update(status="original_delivery_rejected_one_failure_r29_repair_frozen_893_pending_independent_acceptance", checked_at=at)
assert parent["consecutive_failed_actual_deliveries"] == 1
ledger["updated_at"] = at
for entry in ledger["next_module_tasks"]:
    if entry["id"] in {row["id"], parent["id"]}:
        source = row if entry["id"] == row["id"] else parent
        entry.update({key: source.get(key) for key in entry})
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, next_module_tasks=ledger["next_module_tasks"], consumer_frozen_status=out.relative_to(ROOT).as_posix())
write(HERE / "continuation-r6.json", continuation)
print(json.dumps(dict(recorded_at=at, receipt=out.relative_to(ROOT).as_posix(), independent_acceptance=False)))
