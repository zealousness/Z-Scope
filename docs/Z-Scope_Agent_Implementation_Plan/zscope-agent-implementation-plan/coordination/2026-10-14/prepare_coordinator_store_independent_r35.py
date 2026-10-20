"""Copy the unchanged Stage floor for coordinator-owned Store acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-store-active-transactions-r35"
BASE = ROOT / "artifacts/coordinator-store-active-transactions-r35-20261017"
FLOOR = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Unoptimized Linux Python required")
floor = json.loads(FLOOR.read_text(encoding="utf-8"))
sources, root_sources = floor["complete_inputs_after"], floor["root_inputs"]
assert len(sources) == 1082 and len(root_sources) == 1065
assert all(sha(STAGE / p) == v for p, v in sources.items())
assert all(sha(ROOT / p) == v for p, v in root_sources.items())
if WORK.exists() or BASE.exists():
    raise RuntimeError("Do not duplicate or replace an independent workspace")
WORK.mkdir()
BASE.mkdir()
for name in sources:
    target = WORK / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGE / name, target)
assert all(sha(WORK / p) == v for p, v in sources.items())
assert all(sha(STAGE / p) == v for p, v in sources.items())
assert all(sha(ROOT / p) == v for p, v in root_sources.items())
record = dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    independent_workspace=str(WORK), complete_stage_floor=sources, root_inputs=root_sources,
    source_floor_receipt_sha256=sha(FLOOR), initial_source_count=1082,
    stage_and_root_unchanged=True, producer_candidate_copied=False,
    product_ownership=["zscope/orchestration/jobs/store.py"],
    new_tests=["tests/test_store_active_transactions_r35.py", "tests/test_trace_callback_generation_probe_r35.py"],
    candidate_delivery_and_source_review_required_before_intake=True,
    test_execution=False, independent_acceptance=False, stage_intake=False, root_intake=False)
(BASE / "preparation.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(prepared_at=record["prepared_at"], source_count=1082, producer_candidate_copied=False)))
