"""Fixed, source-bound focused probes; never accepts producer shell text."""
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
parser = argparse.ArgumentParser(__doc__)
parser.add_argument("scope", choices=("s01-origin", "shared-overlay", "s08-consumer", "s01-origin-forms"))
args = parser.parse_args()
assert not sys.flags.optimize and not os.environ.get("PYTHONOPTIMIZE")
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
branch_name = {"s01-origin": "s01-instance-semantics-min-r23", "shared-overlay": "coordinator-instance-integration-r24", "s08-consumer": "s08-instance-recovery-min-r23", "s01-origin-forms": "s01-instance-semantics-min-r23"}[args.scope]
branch = ROOT / ".coordination/20261014/workspaces" / branch_name
assert Path.cwd().resolve() == branch.resolve()
runtime = inspect_root_runtime(require_slot=True)
out = ROOT / "artifacts" / ("coordinator-" + args.scope + ("-r26-20261016" if args.scope == "s01-origin-forms" else "-r25-20261016"))
out.mkdir(exist_ok=False)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

root_sources = json.loads((ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
sources = {str(path): sha(path) for path in branch.rglob("*.py") if "__pycache__" not in path.parts and path.relative_to(branch).parts[0] in {"zscope", "tests", "scripts", "test"}}
if args.scope == "s01-origin":
    test_files = [ROOT / "artifacts/s01-origin-probe-r25-20261016/test_s01_origin_probe.py"]
    references = test_files + [ROOT / "artifacts/s01-authority-probe-r25-20261016/test_s01_authority_probe.py"]
elif args.scope == "s01-origin-forms":
    test_files = [ROOT / "artifacts/s01-origin-forms-probe-r26-20261016/test_s01_origin_forms_probe.py"]
    references = test_files + [ROOT / "artifacts/s01-authority-probe-r25-20261016/test_s01_authority_probe.py"]
elif args.scope == "s08-consumer":
    test_files = [ROOT / "artifacts/s08-consumer-probe-r25-20261016/test_s08_consumer_probe.py"]
    references = test_files
else:
    test_files = [branch / "tests/test_semantics_shadow_overlay.py", branch / "tests/test_semantics_defaults.py"]
    references = test_files
sources.update({str(path): sha(path) for path in references})
command = [sys.executable, "-m", "pytest", "-q", f"--rootdir={branch}", f"--confcutdir={branch}", *map(str, test_files), f"--junitxml={out / 'results.xml'}"]
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=branch, env=env, stdout=stream, stderr=subprocess.STDOUT)
junit_file = out / "results.xml"
suites = ET.parse(junit_file).getroot().findall("testsuite") if junit_file.is_file() else []
junit = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
stable = all(sha(Path(path)) == digest for path, digest in sources.items())
root_stable = all(sha(ROOT / path) == digest for path, digest in root_sources.items())
passed = result.returncode == 0 and junit["tests"] > 0 and not any(junit[key] for key in ("failures", "errors", "skipped")) and stable and root_stable
actual_task = {"s01-origin": "task_1297f2c18f", "s08-consumer": "task_8886dcf232", "shared-overlay": "/root", "s01-origin-forms": "task_f702313db8"}[args.scope]
proof = {"actual_task": actual_task, "scope": args.scope, "started_at": started, "finished_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "command": command, "returncode": result.returncode, "junit": junit, "source_before": sources, "sources_unchanged": stable, "root_unchanged": root_stable, "runtime_preflight": runtime, "focused_checks_passed": passed, "independent_acceptance": False, "integrated": False, "root_joint_verification": False, "whole_packages_complete": False}
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({key: proof[key] for key in ("scope", "finished_at", "returncode", "junit", "sources_unchanged", "root_unchanged", "focused_checks_passed")}), flush=True)
sys.exit(0 if passed else 1)
