"""Freeze formatted tests on the unchanged product for the revision-gate red run."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-contract-tests-r33"
OUT = ROOT / "artifacts/coordinator-review-revision-repair-r33-20261017"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
old = read(ROOT / "artifacts/coordinator-contract-tests-r33-20261017/preparation.json")
base = old["complete_baseline"] | old["candidate_sha256"]
assert len(base) == 1077 and all(sha(WORK / path) == digest for path, digest in base.items())
assert read(ROOT / "artifacts/coordinator-contract-tests-r33-20261017/raii-first-gate-probe.json")["reproduced_first_refusal_gate"]
test = "tests/test_review_current_revisions_r33.py"
assert not (WORK / test).exists() and not (OUT / "test-freeze.json").exists()
shutil.copyfile(OUT / "test_review_current_revisions_r33.py", WORK / test)
candidate = read(OUT / "candidate.json")
assert sha(WORK / candidate["source_path"]) == candidate["before_sha256"]
receipt = dict(actual_task="/root", frozen_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), complete_red_inputs=base | {test: sha(WORK / test)}, product_before_sha256=candidate["before_sha256"], product_candidate_sha256=candidate["candidate_sha256"], fixed_test_sha256=sha(WORK / test), fixed_test_path=test, original_candidate_metadata_sha256=sha(OUT / "candidate.json"), assertions_from_current_catalog_category=True, format_completed=True, expected_cases=33, expected_current_safe_cases=11, expected_unsafe_and_unknown_controls=22, product_changed=False, stage_intake=False, root_intake=False)
(OUT / "test-freeze.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(test_sha256=receipt["fixed_test_sha256"], inputs=len(receipt["complete_red_inputs"]))))
