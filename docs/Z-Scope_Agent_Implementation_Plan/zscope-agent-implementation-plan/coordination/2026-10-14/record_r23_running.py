"""Record actual Root execution separately from pending result publication."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def write(p, v):
    p.write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
out = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016"
runtime = read(out / "runtime-preflight.json")
assert (out / "command-0.log").is_file() and runtime["coordinator_test_slot"]["exclusive_lock_already_held"]
review_path = ROOT / "artifacts/root-launcher-review-r23-20261016/final-review.json"
review = read(review_path)
assert review["source_review_passed"]
launch = ROOT / "artifacts/coordinator-r23-launch-20261016"
launch.mkdir(exist_ok=False)
proof = {"observed_at": at, "logical_task": "CURRENT-JOINT-R23", "actual_coordinator_exec_session": 82911, "actual_execution_observed": True, "evidence": (out / "command-0.log").relative_to(ROOT).as_posix(), "runtime_preflight": runtime, "planned_test_files": 171, "planned_commands": 6, "result_available": False, "joint_verification_passed": False, "root_intake_receipt": "artifacts/intake-ui-projection-r23-20261016/receipt.json", "launcher_review": review_path.relative_to(ROOT).as_posix(), "launcher_review_sha256": hashlib.sha256(review_path.read_bytes()).hexdigest(), "whole_packages_complete": False}
write(launch / "receipt.json", proof)
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
rows["CURRENT-JOINT-R23"].update(status="actual_complete_union_and_six_commands_running_result_pending", execution_evidence=proof["evidence"], execution_observed_at=at, actual_coordinator_exec_session=82911, checked_at=at)
rows["ASTRA-ROOT-LAUNCHER-REVIEW-R23"].update(status="final_corrected_source_independent_review_passed_initial_block_preserved", artifact_available=True, independent_acceptance=True, source_review_passed=True, evidence=proof["launcher_review"], initial_failed_review="artifacts/root-launcher-review-r23-20261016/review.json", checked_at=at)
contract_path = ROOT / "artifacts/design-contract-r23-20261016/contracts.json"
contract = read(contract_path)
rows["ASTRA-DESIGN-CONTRACT-R23"].update(status="completed_readonly_contract_independent_review_pending", artifact_available=True, independent_acceptance=False, evidence=contract_path.relative_to(ROOT).as_posix(), checked_at=at)
assert "ASTRA-DESIGN-CONTRACT-REVIEW-R23" not in rows
ledger["tasks"].append({"id": "ASTRA-DESIGN-CONTRACT-REVIEW-R23", "actual_task": "/root/astra_design_review_r23", "owner": "Astra", "status": "dispatched_actual_readonly_contract_review_in_progress", "artifact_available": False, "tests_executed": 0, "product_changed": False, "checked_at": at})
ledger["current_accepted_stage"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R23", historical_pass_retained=True)
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
note = f"## {at} · R23 Root union actually running\n\n11-file intake finished10:24:34 with backups, exact1059 input equality and originalproducer1059 checks. Initial launcher source review blocked on wrong projection fields and unverified slot; corrected final review passed, initial receipt frozen. Slot probes missing1/held0/released1/nested2 executed zero product tests. Actual coordinator exec session82911 now runs one outer slot, complete171-file union and six preserved quality commands; runtime preflight passed and pytest command log exists. No final result yet. Launch receipt {launch.relative_to(ROOT).as_posix()}/receipt.json; output {out.relative_to(ROOT).as_posix()}. R22 is historical after intake.\n\nAstra /root/astra_design_contract_r23 delivered typed S01/S08 minimum contracts and33 acceptance rows; independent source/contract review /root/astra_design_review_r23 is in progress. Neither new module has been dispatched or implemented. ZCode dispatch is gated on current R23 joint pass and contract acceptance; shared consumers/store/scheduler/Ledger remain coordinator-only.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md"):
    p = HERE / name
    p.write_text(note + p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "actual_exec_session": 82911, "joint_passed": False, "contract_review_pending": True}), flush=True)
