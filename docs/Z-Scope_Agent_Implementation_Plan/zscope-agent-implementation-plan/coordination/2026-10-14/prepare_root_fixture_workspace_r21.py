"""Freeze the failed Root input for two isolated fixture corrections."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = json.loads((ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source.items())
name = "coordinator-root-fixtures-r21"
branch = ROOT / ".coordination/20261014/workspaces" / name
branch.mkdir(exist_ok=False)
for path, sha in sorted(source.items()):
    target = branch / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / path, target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
task = {"id": "COORD-ROOT-FIXTURES-R21", "workspace": name, "owner": "coordinator", "owns": ["tests/test_mcp_jobs.py", "tests/test_job_remaining.py"], "scope": "Two evidenced fixture assumptions only, no product/cancellation/scheduler/native/clock changes"}
receipt = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task": task, "files": [{"path": p, "sha256": h} for p, h in sorted(source.items())], "failed_joint_evidence": "artifacts/coordinator-r20-job-cli-intaken-20261015/review.json", "root_product_changed": False}
(HERE / "followups-r12" / (name + "-baseline.json")).write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"workspace": name, "inputs": len(source), "root_changed": False}), flush=True)
