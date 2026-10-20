"""Authorize the necessary pending-file producer fence in the isolated job repair."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") or Path.cwd().resolve() != ROOT:
    raise RuntimeError("Ownership metadata requires the fixed Linux root and unoptimized Python")
OUT = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017"
PREP = OUT / "preparation.json"
data = json.loads(PREP.read_text(encoding="utf-8"))
WORK = ROOT / data["workspace"]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
target = "zscope/orchestration/jobs/scheduler_hook.py"
assert sha(WORK / target) == data["complete_inputs"][target]
assert all(sha(ROOT / p) == v for p, v in data["root_inputs"].items())
receipt = dict(actual_coordinator_task="/root", actual_worker_task="/root/stage_cost_repair_r33", logical_task="JOB-RUNTIME-FOOTPRINT-REPAIR-R34", authorized_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), workspace=data["workspace"], original_preparation_sha256=sha(PREP), added_path=target, original_sha256=sha(WORK / target), allowed_change="persist_pending writer fence and necessary typed parameter: mkdir/temp/write/replace under real current job/run/owner/input/run_dir bound_attempt, narrow factory-issued runtime write fence; append_event after SQL transaction to avoid self deadlock", valid_binding_payload_returns_events_preserved=True, invalid_or_unknown_binding_zero_file_writes=True, other_hook_semantics_readonly=True, codec_readonly=True, source_review_required_before_implementation=True, existing_hook_owner_window_deadline_regressions_required=True, root1065_unchanged=True, stage_write=False, root_write=False, historical_failed_delivery_counts_unchanged=True)
path = OUT / "ownership-extension-pending-writer.json"
assert not path.exists()
path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(extension_sha256=sha(path), added_path=target, root_unchanged=True)))
