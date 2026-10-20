"""Install the reviewed inert candidate; this does not run or authorize the joint."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = ROOT / "artifacts/stage-joint-launcher-draft-r35-20261017/revision-3/verify_stage_joint_r35.py"
REVIEW = ROOT / "artifacts/stage-joint-launcher-source-review-r35-20261017/revision-3-review.json"
TARGET = HERE / "verify_stage_joint_r35.py"
OUT = ROOT / "artifacts/stage-joint-launcher-install-r35-20261017"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use unoptimized Linux Python")
assert sha(SOURCE) == "ec9eb801255e6f3c171be76b4011345c92f25c0f2039e389bbdb22833fb087f1"
assert sha(REVIEW) == "adc0524ba129fed29c9fae710b5118e67c86913944104403b03eda485c0cc819"
review = read(REVIEW)
assert review["launcher_candidate_source_review_passed"] is True and not review["blocking_findings"]
assert review["execution_authorized"] is False
intake = read(ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json")
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert len(intake["complete_inputs_after"]) == 1082 and all(sha(stage / p) == v for p, v in intake["complete_inputs_after"].items())
assert len(intake["root_inputs"]) == 1065 and all(sha(ROOT / p) == v for p, v in intake["root_inputs"].items())
if TARGET.exists() or OUT.exists():
    raise RuntimeError("Preserve the existing installation or receipt")
shutil.copyfile(SOURCE, TARGET)
assert sha(TARGET) == sha(SOURCE)
assert all(sha(stage / p) == v for p, v in intake["complete_inputs_after"].items())
assert all(sha(ROOT / p) == v for p, v in intake["root_inputs"].items())
OUT.mkdir()
receipt = dict(actual_task="/root", installed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), source=str(SOURCE), source_sha256=sha(SOURCE), deployed=str(TARGET), deployed_sha256=sha(TARGET), source_review=str(REVIEW), source_review_sha256=sha(REVIEW), candidate_installed=True, final_intake_dependencies_pending=True, execution_authorized=False, tests_executed=0, builds_executed=0, source_stage1082_root1065_unchanged=True, stage_joint_passed=False, root_joint_passed=False)
(OUT / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
