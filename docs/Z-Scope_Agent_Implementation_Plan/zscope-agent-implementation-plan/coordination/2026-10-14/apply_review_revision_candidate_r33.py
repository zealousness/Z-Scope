"""Apply the bounded explicit revision candidate only after valid red evidence."""
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
candidate, frozen, red = map(read, (OUT / "candidate.json", OUT / "test-freeze.json", OUT / "red/review.json"))
assert red["valid_red_reproduction"] and all(red["gates"].values())
assert all(sha(WORK / path) == digest for path, digest in frozen["complete_red_inputs"].items())
source = candidate["source_path"]
assert sha(OUT / "candidate" / source) == frozen["product_candidate_sha256"] == candidate["candidate_sha256"]
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
target = OUT / "candidate-application.json"
assert not target.exists()
shutil.copyfile(OUT / "candidate" / source, WORK / source)
assert all(sha(WORK / path) == digest for path, digest in (frozen["complete_red_inputs"] | {source: candidate["candidate_sha256"]}).items())
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
receipt = dict(actual_task="/root", applied_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), source_path=source, before_sha256=candidate["before_sha256"], after_sha256=candidate["candidate_sha256"], fixed_test_sha256=frozen["fixed_test_sha256"], red_receipt_sha256=sha(OUT / "red/review.json"), only_isolated_WORK_changed=True, root1065_unchanged=True, stage_intake=False, root_intake=False)
target.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
