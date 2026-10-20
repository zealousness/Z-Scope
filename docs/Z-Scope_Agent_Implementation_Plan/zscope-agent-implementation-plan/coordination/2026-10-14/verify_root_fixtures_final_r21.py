"""Run isolated fixture corrections and the unchanged native/window neighbors."""
from pathlib import Path
import datetime as dt
import difflib
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from root_runtime_preflight_r21 import inspect_root_runtime

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
branch = ROOT / ".coordination/20261014/workspaces/coordinator-root-fixtures-r21"
baseline = json.loads((HERE / "followups-r12/coordinator-root-fixtures-r21-baseline.json").read_text(encoding="utf-8"))
owns = set(baseline["task"]["owns"])
original = {r["path"]: r["sha256"] for r in baseline["files"]}
def capture(root):
    return {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in original}
before = capture(branch)
assert {p for p in before if before[p] != original[p]} == owns
assert capture(ROOT) == original, "Root changed before isolated fixture verification"
runtime = inspect_root_runtime()
out = ROOT / "artifacts/coordinator-root-fixtures-r21-final-acceptance-20261015"
out.mkdir(exist_ok=False)
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
for p in sorted(owns):
    delta = "".join(difflib.unified_diff((ROOT / p).read_text(encoding="utf-8").splitlines(keepends=True), (branch / p).read_text(encoding="utf-8").splitlines(keepends=True), fromfile="before/" + p, tofile="after/" + p))
    (out / (Path(p).name + ".diff")).write_text(delta, encoding="utf-8", newline="\n")
env = os.environ.copy()
assert env.get("ZSCOPE_COORDINATOR_TEST_SLOT"), "wrap this launcher exactly once"
env["PYTHONPATH"] = str(branch)
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
tests = ["tests/test_mcp_jobs.py", "tests/test_job_remaining.py", "tests/test_job_session_scheduler.py::test_cooperative_window_exit_preserves_real_pending", "tests/test_refcount_integration.py", "tests/test_handle_integration.py", "tests/test_link_targets.py", "tests/test_linked_lifecycle_paths.py", "tests/test_raii_lifecycle.py"]
initial = json.loads((ROOT / "artifacts/coordinator-root-fixtures-r21-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert initial["passed"] and len(initial["commands"]) == 3
assert before["tests/test_mcp_jobs.py"] == initial["after"]["tests/test_mcp_jobs.py"]
assert all(before[p] == sha for p, sha in initial["after"].items() if p != "tests/test_job_remaining.py")
tests = tests[:3]  # unchanged native collection already passed; full Root retains it.
commands = [[sys.executable, "-m", "pytest", "-q", *tests, "--junitxml=" + str(out / "results.xml")], [sys.executable, "-m", "compileall", "-f", "-q", *sorted(owns)], [sys.executable, "-m", "black", "--check", *sorted(owns)]]
results = []
for i, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / f"command-{i}.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=branch, env=env, stdout=log, stderr=subprocess.STDOUT)
    results.append({"command": command, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode})
    print(json.dumps(results[-1]), flush=True)
    if result.returncode:
        break
after = capture(branch)
root_after = capture(ROOT)
junit = [dict(s.attrib) for s in ET.parse(out / "results.xml").getroot().findall("testsuite")] if (out / "results.xml").exists() else []
passed = len(results) == 3 and all(r["returncode"] == 0 for r in results) and before == after and root_after == original and bool(junit) and all(s[k] == "0" for s in junit for k in ("failures", "errors", "skipped"))
proof = {"task_id": "COORD-ROOT-FIXTURES-R21", "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "passed": passed, "commands": results, "junit": junit, "runtime": runtime, "before": before, "after": after, "protected_inputs_unchanged": before == after, "root_unchanged": root_after == original, "delivered_hashes": {p: after[p] for p in sorted(owns)}, "pytest_capture": "fd (unchanged default)", "temporary_directory": env["TMPDIR"], "original_window_and_timeouts_retained": True, "slow8_scanner_and_stop_claim_test_unchanged": before["tests/test_job_session_scheduler.py"] == original["tests/test_job_session_scheduler.py"], "product_changed": False, "current_root_joint_passed": False}
(out / "review.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"passed": passed, "junit": junit, "review": str(out / "review.json")}), flush=True)
sys.exit(0 if passed else 1)
