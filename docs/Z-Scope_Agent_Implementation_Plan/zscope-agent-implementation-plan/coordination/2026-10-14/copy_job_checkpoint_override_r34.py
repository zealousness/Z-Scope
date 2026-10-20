"""Copy the independently accepted shared test only at the worker's acknowledged idle boundary."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") or Path.cwd().resolve() != ROOT:
    raise RuntimeError("Dependency integration requires the fixed Linux root and unoptimized Python")
WORK = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
BASE = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017"
OUT = BASE / "checkpoint-readonly-override"
TARGET = "tests/test_scan_checkpoint_resume.py"
NEW_TEST = "tests/test_job_runtime_footprint_r34.py"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot():
    return {p.relative_to(WORK).as_posix(): sha(p) for p in WORK.rglob("*") if p.is_file() and p.relative_to(WORK).parts[0] != "artifacts" and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


prep_path = BASE / "preparation.json"
prep = read(prep_path)
format_path = WORK / "artifacts/job_runtime_footprint_r34/runner-v2/format-ready-v2/receipt.json"
format_receipt = read(format_path)
assert sha(format_path) == "7c46e1457521ad7940aa49bad3dc0a55ca358e29787e9fe1bbaf0c6eb8876954"
assert format_receipt["passed"] and format_receipt["commands_all_passed"] and all(format_receipt["guards"].values())
assert format_receipt["test_started"] is False and format_receipt["command_started"] is True
assert format_receipt["format_new_test_ast_before"] == format_receipt["format_new_test_ast_after"]
before = snapshot()
assert len(before) == 1083 and before == prep["complete_inputs"] | {NEW_TEST: "5b0c9e70b8db81fb9ea73c6984c73dc7957a9f635b05d172e3015100905f0be9"}
intake_path = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
intake = read(intake_path)
assert intake["stage_intake"] and intake["checkpoint_contract_independent10_and_target_black_passed"]
assert all(sha(STAGE / p) == v for p, v in intake["complete_inputs_after"].items())
assert intake["paths"][TARGET] == "2529219a24c6ec53bd19c145cfde7c76ed8e905c66f5cd450713956c330e906c"
assert all(sha(ROOT / p) == v for p, v in prep["root_inputs"].items())
OUT.mkdir(exist_ok=False)
backup = OUT / "before" / TARGET
backup.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(WORK / TARGET, backup)
shutil.copyfile(STAGE / TARGET, WORK / TARGET)
after = snapshot()
assert len(after) == 1083 and after == before | {TARGET: intake["paths"][TARGET]}
assert all(sha(ROOT / p) == v for p, v in prep["root_inputs"].items())
receipt = dict(actual_coordinator_task="/root", actual_worker_task="/root/stage_cost_repair_r33", copied_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), worker_idle_boundary_acknowledged=True, original_preparation_sha256=sha(prep_path), source_format_receipt_sha256=sha(format_path), accepted_shared_test_intake_sha256=sha(intake_path), readonly_override_paths={TARGET: dict(old_sha256=before[TARGET], new_sha256=after[TARGET], old_backup=str(backup), old_backup_sha256=sha(backup))}, complete_inputs_before=before, complete_inputs_after=after, all_other1082_inputs_unchanged=True, all_products_unchanged=True, new_test_formatted34_unchanged=True, root1065_unchanged=True, original_format_freezes_and_receipts_preserved=True, worker_still_cannot_edit_shared_test=True, new_source_freeze_and_counter_required_before_tests=True, root_intake=False, stage_changed_by_this_copy=False)
(OUT / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(copied_at=receipt["copied_at"], override_sha256=sha(OUT / "receipt.json"), inputs=1083, products_unchanged=True, root_unchanged=True)))
