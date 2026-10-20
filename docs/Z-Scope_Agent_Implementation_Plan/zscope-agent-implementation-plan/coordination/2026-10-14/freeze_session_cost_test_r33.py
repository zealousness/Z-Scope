"""Freeze the formatted owned probe while preserving its initial preparation."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-session-cost-r33"
OUT = ROOT / "artifacts/coordinator-session-cost-r33-20261017"
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
prep = json.loads((OUT / "preparation.json").read_text(encoding="utf-8"))
test = "tests/test_session_preentry_cost_r33.py"
assert all(sha(WORK / path)==digest for path,digest in prep["complete_baseline"].items() if path != test)
assert not (OUT / "test-freeze.json").exists()
shutil.copyfile(WORK / test, OUT / "fixed-test.py")
receipt = dict(actual_task="/root", frozen_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), complete_inputs=prep["complete_baseline"] | {test:sha(WORK / test)}, original_preparation_sha256=sha(OUT / "preparation.json"), fixed_test_sha256=sha(WORK / test), fixed_test_path=test, only_offline_fixture_and_format_changed=True, product_changed=False, stage_intake=False, root_intake=False)
(OUT / "test-freeze.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(test_sha256=receipt["fixed_test_sha256"])))
