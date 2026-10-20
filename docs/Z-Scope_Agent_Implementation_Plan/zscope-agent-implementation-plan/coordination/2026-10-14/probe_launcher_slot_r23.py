"""Probe the actual outer-slot gate without executing a product test."""
from pathlib import Path
import datetime as dt
import json
import os
import subprocess
import sys

assert sys.platform == "linux" and not os.environ.get("ZSCOPE_COORDINATOR_TEST_SLOT")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-launcher-slot-probe-r23-20261016"
out.mkdir(exist_ok=False)
code = "import sys,json;sys.path.insert(0,sys.argv[1]);from root_runtime_preflight_r23 import inspect_test_slot;print(json.dumps(inspect_test_slot()))"
base = [sys.executable, "-c", code, str(HERE)]
rows = []

def run(name, command, env=None):
    result = subprocess.run(command, env=env, cwd=ROOT, capture_output=True, text=True)
    (out / (name + ".log")).write_text(result.stdout + result.stderr, encoding="utf-8", newline="\n")
    rows.append({"name": name, "command": command, "returncode": result.returncode})
    return result

missing = run("missing-slot", base)
assert missing.returncode != 0 and "Run through exactly one outer test_slot.py" in missing.stderr
held = run("actual-held-slot", [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", *base])
assert held.returncode == 0
slot = json.loads(held.stdout.splitlines()[-1])
assert slot["exclusive_lock_already_held"]
stale_env = os.environ.copy()
stale_env["ZSCOPE_COORDINATOR_TEST_SLOT"] = slot["token"]
stale = run("released-slot-token", base, stale_env)
assert stale.returncode != 0 and "Declared outer test slot is not actually held" in stale.stderr
nested = run("nested-slot-refused", [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", *base])
assert nested.returncode != 0 and "nested test_slot invocation refused" in nested.stderr
proof = {"finished_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "commands": rows, "missing_slot_rejected": True, "actual_held_slot_accepted": True, "released_token_rejected": True, "nested_wrapper_rejected_before_tests": True, "product_tests_executed": 0, "product_changed": False, "wsl_process_inspection": False}
(out / "review.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(proof), flush=True)
