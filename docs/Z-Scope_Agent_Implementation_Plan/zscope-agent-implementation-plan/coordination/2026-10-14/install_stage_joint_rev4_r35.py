"""Install reviewed rev4 under a new name, preserving the pinned rev3."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCE = ROOT / "artifacts/stage-joint-launcher-draft-r35-20261017/revision-4/verify_stage_joint_r35_rev4.py"
REVIEW = ROOT / "artifacts/stage-joint-launcher-source-review-r35-20261017/revision-4-review.json"
TARGET = HERE / "verify_stage_joint_r35_rev4.py"
OUT = ROOT / "artifacts/stage-joint-launcher-install-r35-20261017/revision-4.json"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Unoptimized Linux Python required")
assert sha(SOURCE) == "dd078e068d91b6e7c5e22a5e0a0824276556b91e47a5b42ff55f8e9e410a0f8f"
assert sha(REVIEW) == "3a74271eb63c1e82539222441259d271d03b23a0ab1067fc9741445880219a1b"
assert sha(HERE / "verify_stage_joint_r35.py") == "ec9eb801255e6f3c171be76b4011345c92f25c0f2039e389bbdb22833fb087f1"
assert not (ROOT / "artifacts/stage-shared-intake-r35-20261017/receipt.json").exists()
if TARGET.exists() or OUT.exists():
    raise RuntimeError("Preserve existing installation/evidence")
TARGET.write_bytes(SOURCE.read_bytes())
record = dict(actual_task="/root", installed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    installed_path=str(TARGET), launcher_sha256=sha(TARGET), review_sha256=sha(REVIEW),
    original_rev3_preserved=True, permanent_trace_gate_added=True,
    execution_confirmed=False, readiness_dependencies_pending=True,
    stage_intake=False, root_intake=False, joint_passed=False)
OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(record))
