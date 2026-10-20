"""Independent module dependency checks; no Root product intake or dispatch."""
from pathlib import Path
from collections import Counter
import argparse
import datetime as dt
import hashlib
import json
import os
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

if sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("optimized Python cannot run verification guards")
if os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
    raise RuntimeError("pytest environment overrides must be empty for controlled verification")
assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
parser = argparse.ArgumentParser(__doc__)
parser.add_argument("module", choices=("s01", "s08"))
args = parser.parse_args()
specs = {
    "s01": ("S01-INSTANCE-SEMANTICS-MIN-R23", "task_1297f2c18f", "s01-instance-semantics-min-r23", "instance-semantics-r23", ["tests/test_instance_semantics.py", "tests/test_semantics_defaults.py", "tests/test_contract_usr_scope.py", "tests/test_build_context.py", "tests/test_instance_analysis.py", "tests/test_validation_build_scope.py"]),
    "s08": ("S08-INSTANCE-RECOVERY-MIN-R23", "task_8886dcf232", "s08-instance-recovery-min-r23", "instance-recovery-r23", ["tests/test_instance_result_recovery.py", "tests/test_job_bound_completion.py", "tests/test_job_session_scheduler.py", "tests/test_scan_job_work_queue.py"]),
}
logical, actual, name, delivery_dir, test_files = specs[args.module]
branch = ROOT / ".coordination/20261014/workspaces" / name
out = ROOT / "artifacts" / ("coordinator-" + args.module + "-module-dependency-r25-20261016")

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

runtime = inspect_root_runtime(require_slot=True)
assert Path.cwd().resolve() == branch.resolve(), "outer test_slot must select the exact producer workspace"
row = next(row for row in read(HERE / "tasks.json")["tasks"] if row["id"] == logical)
assert row["bridge_task_id"] == actual and row["producer_status"] == "completed"
assert not row["integrated"] and row["artifact_available"]
baseline = read(HERE / "followups-r12" / (name + "-baseline.json"))
baseline_hashes = {row["path"]: row["sha256"] for row in baseline["files"]}
assert len(baseline_hashes) == 1067
dependencies = read(HERE / "followups-r12" / (name + "-dependencies.json"))
dependency_rows = dependencies["files"]
baseline_hashes.update({row["path"]: row["sha256"] for row in dependency_rows})
assert len(baseline_hashes) == 1069
assert all(sha(branch / path) == digest for path, digest in baseline_hashes.items())
owned = list(row["write_paths"])
assert len(owned) == 2 and all((branch / path).is_file() for path in owned)
assert all((branch / path).is_file() for path in test_files)
root_hashes = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_hashes.items())
producer_review = branch / "artifacts" / delivery_dir / "review.json"
assert (branch / "DELIVERY.md").is_file() and producer_review.is_file()
producer = read(producer_review)
prior_junits = []
producer_tests = []
for result in producer.get("commands", []):
    command = result.get("command", result.get("argv", []))
    if isinstance(command, str):
        # Read producer argv only to reconcile file/JUnit identities. It is
        # never executed: every subprocess argv below is constructed here.
        command = shlex.split(command)
    assert isinstance(command, list) and all(isinstance(arg, str) for arg in command)
    if "pytest" not in command and not any(str(arg).endswith("/pytest") for arg in command[:1]):
        continue
    producer_tests.extend(arg for arg in command if isinstance(arg, str) and arg.startswith("tests/") and arg.endswith(".py"))
    for arg in command:
        if isinstance(arg, str) and arg.startswith(("--junitxml=", "--junit-xml=")):
            path = Path(arg.partition("=")[2])
            path = path if path.is_absolute() else branch / path
            assert path.resolve().is_relative_to((branch / "artifacts" / delivery_dir).resolve())
            assert path.is_file()
            prior_junits.append(path)
assert producer_tests and prior_junits, "producer command/JUnit reconciliation required before verification"
test_files = list(dict.fromkeys(producer_tests + test_files))
for path in test_files:
    parsed = Path(path)
    assert not parsed.is_absolute() and ".." not in parsed.parts
    assert parsed.as_posix() == path and path in (set(baseline_hashes) | set(owned))
    assert (branch / path).resolve().is_relative_to(branch.resolve()) and (branch / path).is_file()
reference_junits = [
    ROOT / ("artifacts/coordinator-" + args.module + "-module-dependency-r24-20261016/results.xml"),
]
if args.module == "s01":
    reference_junits.append(ROOT / "artifacts/s01-authority-probe-r24-20261016/results-rerun-01.xml")
    probe_files = [ROOT / "artifacts/s01-authority-probe-r25-20261016/test_s01_authority_probe.py"]
else:
    reference_junits.extend(ROOT / "artifacts/s08-multipath-probe-r24-20261016" / name for name in ("results.xml", "boundary-results.xml", "schema-results.xml"))
    probe_files = [ROOT / "artifacts/s08-multipath-probe-r24-20261016" / name for name in ("test_s08_multipath_probe.py", "test_s08_boundary_probe.py", "test_s08_schema_probe.py")]
trusted_root_references = {path.relative_to(ROOT).as_posix(): sha(path) for path in [*reference_junits, *probe_files]}
assert all(path.resolve().is_relative_to((ROOT / "artifacts").resolve()) for path in [*reference_junits, *probe_files])
inputs = dict(baseline_hashes)
for path in [*owned, "DELIVERY.md", "artifacts/" + delivery_dir + "/review.json"]:
    inputs[path] = sha(branch / path)
for path in prior_junits:
    inputs[path.relative_to(branch).as_posix()] = sha(path)
def unexpected_paths():
    unexpected = set()
    for directory in ("zscope", "tests", "docs/modules"):
        for path in (branch / directory).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                relative = path.relative_to(branch).as_posix()
                if relative not in inputs:
                    unexpected.add(relative)
    for name in ("conftest.py", "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"):
        for path in branch.rglob(name):
            if path.is_file() and path.relative_to(branch).as_posix() not in inputs:
                unexpected.add(path.relative_to(branch).as_posix())
    return sorted(unexpected)

unexpected = unexpected_paths()
assert not unexpected, unexpected
env = os.environ.copy()
assert not env.get("PYTEST_ADDOPTS") and not env.get("PYTHONOPTIMIZE")
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
env["Z_SCOPE_TEST_CLANG_INDEXER"] = str(native)
assert sha(native) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
out.mkdir(exist_ok=False)
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
(out / "source-before.json").write_text(json.dumps(inputs, indent=2) + "\n", encoding="utf-8", newline="\n")
commands = [
    [sys.executable, "-m", "pytest", "-q", f"--rootdir={branch}", f"--confcutdir={branch}", *test_files, *[str(path) for path in probe_files], f"--junitxml={out / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "black", "--check", *owned],
]
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    log = out / f"command-{index}.log"
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=branch, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append({"command": command, "returncode": result.returncode, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "log": log.relative_to(ROOT).as_posix()})
    print(json.dumps({"module": args.module, "command_index": index, "returncode": result.returncode}), flush=True)
after = {path: sha(branch / path) for path in inputs}
junit_path = out / "results.xml"
suites = ET.parse(junit_path).getroot().findall("testsuite") if junit_path.is_file() else []
junit = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
source_unchanged = after == inputs
unexpected_after = unexpected_paths()
root_unchanged = all(sha(ROOT / path) == digest for path, digest in root_hashes.items())
references_unchanged = all(sha(ROOT / path) == digest for path, digest in trusted_root_references.items())
def cases(path):
    return Counter((case.get("classname"), case.get("name")) for case in ET.parse(path).getroot().iter("testcase"))

current_cases = cases(junit_path) if junit_path.is_file() else Counter()
producer_cases_preserved = all(cases(path) <= current_cases for path in [*prior_junits, *reference_junits])
passed = all(result["returncode"] == 0 for result in results) and junit["tests"] > 0 and not any(junit[key] for key in ("failures", "errors", "skipped")) and source_unchanged and not unexpected_after and root_unchanged and references_unchanged and producer_cases_preserved and sha(native) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
proof = {"logical_task": logical, "actual_producer_task_id": actual, "finished_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "commands": results, "junit": junit, "module_dependency_checks_passed": passed, "source_before": inputs, "source_after": after, "trusted_root_references": trusted_root_references, "references_unchanged": references_unchanged, "independent_probe_files": [path.relative_to(ROOT).as_posix() for path in probe_files], "source_unchanged": source_unchanged, "root_unchanged": root_unchanged, "producer_junit_case_identities_preserved": producer_cases_preserved, "runtime_preflight": runtime, "pytest_capture": "fd default", "outer_test_slot_wrappers": 1, "slice_independent_acceptance": False, "integrated": False, "root_joint_verification": False, "whole_packages_complete": False, "scope": "New module dependency checks only; real coordinator consumer wiring and recovery remain separately unaccepted"}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"logical_task": logical, "junit": junit, "module_dependency_checks_passed": passed}), flush=True)
sys.exit(0 if passed else 1)
