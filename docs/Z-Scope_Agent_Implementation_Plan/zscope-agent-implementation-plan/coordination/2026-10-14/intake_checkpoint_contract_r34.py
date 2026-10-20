"""Integrate one independently executed contract test without changing product code."""
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
    raise RuntimeError("Intake requires the fixed Linux repository root and unoptimized Python")
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-checkpoint-contract-r34"
BASE = ROOT / "artifacts/coordinator-checkpoint-contract-r34-20261017"
OUT = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017"
TARGET = "tests/test_scan_checkpoint_resume.py"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot(directory):
    return {p.relative_to(directory).as_posix(): sha(p) for p in directory.rglob("*") if p.is_file() and p.relative_to(directory).parts[0] != "artifacts" and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


old_path = ROOT / "artifacts/stage-core-intake-r34-20261017/receipt.json"
old = read(old_path)
before = snapshot(STAGE)
assert len(before) == 1082 and before == old["complete_inputs_after"]
review_path = BASE / "independent/review.json"
review = read(review_path)
assert review["bounded_checkpoint_contract_test_independent_passed"]
assert review["junit"] == dict(tests=10, failures=0, errors=0, skipped=0)
assert all(v["returncode"] == 0 for v in review["commands"]) and all(review["gates"].values())
freeze_path = BASE / "formatted-input-freeze.json"
frozen = read(freeze_path)
assert sha(freeze_path) == review["formatted_input_freeze_sha256"]
assert frozen["entire_candidate_AST_identical"] and frozen["only_target_formatting_changed"]
assert sha(WORK / TARGET) == review["formatted_test_sha256"] == frozen["formatted_test_sha256"]
candidate = snapshot(WORK)
assert candidate == frozen["complete_inputs"] and candidate == before | {TARGET: sha(WORK / TARGET)}
assert len(candidate) == 1082 and candidate[TARGET] != before[TARGET]
source_path = ROOT / "artifacts/checkpoint-contract-source-review-r34-20261017/candidate-review.json"
launcher_path = ROOT / "artifacts/checkpoint-contract-source-review-r34-20261017/launcher-review.json"
source, launcher = read(source_path), read(launcher_path)
assert source["source_review_passed"] and not source["blocking_findings"]
assert launcher["source_review_passed"] and not launcher["blocking_findings"]
root_inputs = old["root_inputs"]
assert len(root_inputs) == 1065 and all(sha(ROOT / p) == v for p, v in root_inputs.items())
refs = dict(review["references_sha256"])
for p in (Path(__file__), old_path, review_path, freeze_path, BASE / "independent/results.xml", source_path, launcher_path):
    key, digest = str(p), sha(p)
    assert key not in refs or refs[key] == digest
    refs[key] = digest
assert all(sha(Path(p)) == v for p, v in refs.items())
OUT.mkdir(exist_ok=False)
backup = OUT / "before" / TARGET
backup.parent.mkdir(parents=True, exist_ok=True)
shutil.copyfile(STAGE / TARGET, backup)
shutil.copyfile(WORK / TARGET, STAGE / TARGET)
after = snapshot(STAGE)
assert after == candidate and all(sha(ROOT / p) == v for p, v in root_inputs.items())
assert all(sha(Path(p)) == v for p, v in refs.items())
receipt = dict(actual_task="/root", integrated_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), stage_intake=True, paths={TARGET: after[TARGET]}, complete_inputs_before=before, complete_inputs_after=after, root_inputs=root_inputs, root1065_unchanged=True, reference_sha256=refs, checkpoint_contract_independent10_and_target_black_passed=True, original_case_names_and_counter_preserved=True, all_product_and_other_inputs_unchanged=True, old_checkpoint_failure_preserved=True, stage_full_joint_passed=False, root_intake=False, whole_package_complete=False, cost_failed_deliveries_preserved=1, s01_failed_deliveries_preserved=3)
(OUT / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(integrated_at=receipt["integrated_at"], paths=1, stage_inputs=1082, product_changed=False, root_intake=False, joint_passed=False)))
