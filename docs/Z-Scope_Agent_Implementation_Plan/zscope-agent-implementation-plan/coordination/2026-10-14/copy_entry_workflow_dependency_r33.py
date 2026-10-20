"""Apply SHA-reviewed coordinator files to one idle isolated candidate."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-entry-workflow-repair-r33-20261017"
assert len(sys.argv) == 2 and sys.argv[1] in {"stage-currentness-repair-r33", "stage-cost-repair-r33"}
name = sys.argv[1]
work = ROOT / ".coordination/20261014/workspaces" / name

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

candidate = read(OUT / "candidate.json")
review_path = ROOT / "artifacts/stage-repair-product-source-review-r33-20261017/entry-closure-source-review.json"
review = read(review_path)
assert review["bounded_dependency_source_review_passed"] and not review["blocking_findings"]
assert review["candidate_sha256"] == sha(OUT / "candidate.json")
assert review["owned_source_sha256"] == candidate["candidate_sha256"]
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
for path, digest in candidate["before_sha256"].items():
    assert sha(work / path) == digest
for path, digest in candidate["candidate_sha256"].items():
    assert sha(OUT / "candidate" / path) == digest
    shutil.copyfile(OUT / "candidate" / path, work / path)
    assert sha(work / path) == digest
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
base = read(ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/supplemental-inputs.json")["candidates"][name]["complete_candidate_baseline"]
receipt = dict(actual_task="/root", copied_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), workspace=work.relative_to(ROOT).as_posix(), only_while_no_check_running=True, original_baseline_preserved=True, readonly_source_overrides=candidate["candidate_sha256"], previous_readonly_sha256=candidate["before_sha256"], complete_candidate_baseline=base | candidate["candidate_sha256"], readonly_to_producer=True, producer_owned_paths_unchanged=True, source_review=review_path.relative_to(ROOT).as_posix(), source_review_sha256=sha(review_path), behavioral_acceptance=False, stage_intake=False, root_intake=False, root1065_unchanged=True, aff_bridge_intaken=False)
path = OUT / (name + "-override.json")
assert not path.exists()
path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=path.relative_to(ROOT).as_posix(), overrides=candidate["candidate_sha256"])))
