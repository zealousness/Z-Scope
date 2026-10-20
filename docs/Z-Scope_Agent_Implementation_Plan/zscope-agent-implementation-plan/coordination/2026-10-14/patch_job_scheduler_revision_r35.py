"""Apply the coordinator-owned Hook input-revision argument in the candidate only."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34"
CANDIDATE = WORK / "artifacts/job_runtime_footprint_r34/candidate-src-v2"
NAME = "zscope/orchestration/jobs/session_scheduler.py"
OUT = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/scheduler-readonly-dependency-override-r35"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Unoptimized Linux Python required")
target = CANDIDATE / NAME
original = target.read_bytes()
assert sha(target) == "f346a0f7e7d65f1e9c2043c2efbd0c06d276c771eab1d50fb278827f0ddfca08"
newline = b"\r\n" if b"\r\n" in original else b"\n"
old = b"            run_dir=self.run_dir," + newline + b"        )"
new = b"            run_dir=self.run_dir," + newline + b"            input_revision=self.input_revision," + newline + b"        )"
assert original.count(old) == 1 and b"self._hook = JobWindowHook(" in original
floor = json.loads((ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json").read_text(encoding="utf-8"))
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert all(sha(stage / p) == v for p, v in floor["complete_inputs_after"].items())
assert all(sha(ROOT / p) == v for p, v in floor["root_inputs"].items())
if OUT.exists():
    raise RuntimeError("Preserve original integration receipt")
OUT.mkdir()
(OUT / "original-session-scheduler.py").write_bytes(original)
target.write_bytes(original.replace(old, new))
assert sha(WORK / NAME) == "f346a0f7e7d65f1e9c2043c2efbd0c06d276c771eab1d50fb278827f0ddfca08"
assert all(sha(stage / p) == v for p, v in floor["complete_inputs_after"].items())
assert all(sha(ROOT / p) == v for p, v in floor["root_inputs"].items())
record = dict(actual_task="/root", applied_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    candidate_root=str(CANDIDATE), path=NAME,
    before_sha256=hashlib.sha256(original).hexdigest(), after_sha256=sha(target),
    exact_change="JobWindowHook receives the scheduler's already captured input_revision; no constructor SQL and no authorization from rereading changed rows.",
    coordinator_owned_shared_dependency=True, worker_path_remains_readonly=True,
    original_line_endings_preserved=True,
    initial_preparation_attempt="A LF-only exact fragment assertion rejected the existing CRLF file before any mutation; fixed by byte-preserving newline-aware exact replacement.",
    original_red_tree_unchanged=True, stage1082_root1065_unchanged=True,
    source_review_required_before_execution=True, independent_acceptance=False,
    stage_intake=False, root_intake=False)
(OUT / "receipt.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(record))
