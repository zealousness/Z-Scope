"""Retain a coordinator invocation error without counting a product failure."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
branch = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
row = next(r for r in json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in row["delivered_hashes"].items())
source = ROOT / "artifacts/coordinator-job-cli-window-r20-final-acceptance-20261015"
target = ROOT / "artifacts/coordinator-job-cli-window-r20-interrupted-nested-startup-20261015"
assert source.resolve().parent == target.resolve().parent == (ROOT / "artifacts").resolve()
assert source.is_dir() and not target.exists()
source.rename(target)
env = os.environ.copy()
env["ZSCOPE_COORDINATOR_TEST_SLOT"] = "diagnostic-inherited-slot"
probe = subprocess.run([sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", sys.executable, "-c", "raise RuntimeError('nested command must not run')"], env=env, capture_output=True, text=True)
assert probe.returncode == 2 and "nested test_slot invocation refused" in probe.stderr and "check_slot=" not in probe.stdout
receipt = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "classification": "coordinator startup invocation error, not product failure or acceptance", "outer_session": 98125, "outer_slot": 0, "internal_slot": 1, "interrupted_by_coordinator": True, "signal": "SIGINT only to verified coordinator validation process group2820452", "linux_processes_after": [], "child_cleanup": "two detached test children exited naturally after parent interrupt; no stale PID signal was sent", "owned_source_after": row["delivered_hashes"], "source_unchanged": True, "tests_or_timeouts_or_capture_weakened": False, "nested_guard_probe_returncode": probe.returncode, "nested_guard_probe_stderr": probe.stderr, "slot_helper_sha256": hashlib.sha256((HERE / "test_slot.py").read_bytes()).hexdigest(), "next_invocation": "direct verify_delivery_r12.py, which internally wraps each command once", "development_failure_streak_unchanged": 1}
(target / "interruption-receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"archived": str(target), "nested_guard_verified": True, "source_unchanged": True}), flush=True)
