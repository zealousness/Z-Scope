"""Preserve an obsolete launcher pin and explicitly authorize its reviewed successor."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017"
PREP = OUT / "preparation.json"
data = json.loads(PREP.read_text(encoding="utf-8"))
helper = HERE / "verify_shared_style_r34.py"
old = ROOT / "artifacts/coordinator-shared-style-source-review-r34-20261017/initial-helper.py"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(old) == data["reference_sha256"][str(helper)]
receipt = dict(actual_task="/root", checked_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), reason="two source-review launcher gate repairs; no job source input change", original_preparation_sha256=sha(PREP), old_reference_sha256={str(helper): sha(old)}, new_reference_sha256={str(helper): sha(helper)}, old_helper_backup_sha256=sha(old), old_helper_backup=str(old), complete_job_inputs_unchanged=all(sha(ROOT / data["workspace"] / p) == v for p, v in data["complete_inputs"].items()), stage_intake=False, root_intake=False)
assert receipt["complete_job_inputs_unchanged"]
target = OUT / "preparation-reference-override.json"
assert not target.exists()
target.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(override_sha256=sha(target), new_helper_sha256=sha(helper))))
