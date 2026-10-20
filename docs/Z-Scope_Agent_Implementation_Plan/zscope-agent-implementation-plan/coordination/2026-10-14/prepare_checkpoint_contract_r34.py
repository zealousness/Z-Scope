"""Clone an immutable core and install only the coordinator's candidate test."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = ROOT / ".coordination/20261014/workspaces/coordinator-shared-style-r34"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-checkpoint-contract-r34"
BASE = ROOT / "artifacts/coordinator-checkpoint-contract-r34-20261017"
PRODUCER = ROOT / "artifacts/checkpoint-test-contract-r34-20261017"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
frozen = read(ROOT / "artifacts/coordinator-shared-style-r34-20261017/input-freeze.json")
prep = read(ROOT / "artifacts/coordinator-shared-style-r34-20261017/preparation.json")
candidate = read(PRODUCER / "receipt.json")
target = "tests/test_scan_checkpoint_resume.py"
assert candidate["all_other_bytes_and_AST_exact"] and candidate["static_test_name_counter_unchanged"]
assert sha(SOURCE / target) == candidate["original_sha256"]
assert sha(PRODUCER / "candidate" / target) == candidate["candidate_sha256"]
assert len(frozen["complete_inputs"]) == 1082 and all(sha(SOURCE / p) == v for p, v in frozen["complete_inputs"].items())
WORK.mkdir(exist_ok=False)
BASE.mkdir(exist_ok=False)
for p in frozen["complete_inputs"]:
    destination = WORK / p
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(SOURCE / p, destination)
shutil.copyfile(PRODUCER / "candidate" / target, WORK / target)
inputs = frozen["complete_inputs"] | {target: candidate["candidate_sha256"]}
assert all(sha(WORK / p) == v for p, v in inputs.items())
refs = dict(prep["source_review_sha256"])
for p in [Path(__file__), ROOT / "artifacts/coordinator-shared-style-r34-20261017/input-freeze.json", PRODUCER / "receipt.json", PRODUCER / "candidate" / target, ROOT / "artifacts/coordinator-stage-joint-r32-20261017/results.xml", ROOT / "artifacts/shared-job-probe-observer-source-review-r34-20261017/cause-review.json"]:
    assert str(p) not in refs or refs[str(p)] == sha(p)
    refs[str(p)] = sha(p)
assert all(sha(Path(p)) == v for p, v in refs.items())
receipt = dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), complete_inputs=inputs, root_inputs=prep["root_inputs"], reference_sha256=refs, only_test_changed=target, original_source_sha256=candidate["original_sha256"], producer_candidate_sha256=candidate["candidate_sha256"], no_new_case=True, stage_intake=False, root_intake=False)
(BASE / "preparation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(inputs=1082, changed=target, original_names=10, executed=False)))
