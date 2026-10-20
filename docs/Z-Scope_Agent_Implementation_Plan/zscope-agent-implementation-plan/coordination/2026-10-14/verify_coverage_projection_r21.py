"""Verify the isolated coordinator projection dependency, retaining its baseline."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
stage = sys.argv[1]
assert stage in {"before", "after", "integration_before", "final"}
negative_control = stage in {"before", "integration_before"}
branch = ROOT / ".coordination/20261014/workspaces/astra-stop-coverage-ux-r21"
baseline = json.loads((HERE / "followups-r12/astra-stop-coverage-ux-r21-baseline.json").read_text(encoding="utf-8"))
assert baseline["dispatch_state"] == "not_dispatched_waiting_coordinator_projection_dependency"
root_gate = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/review.json"
assert json.loads(root_gate.read_text(encoding="utf-8"))["all_current_selected_validation_passed"]
root_source = json.loads((root_gate.parent / "source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in root_source.items())
out = ROOT / f"artifacts/coordinator-coverage-projection-r21-{stage}-20261016"
out.mkdir(exist_ok=False)
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
new_test = "tests/test_coverage_gap_provenance.py"
names = sorted(set(root_source) | {new_test})
def hashes():
    return {p: hashlib.sha256((branch / p).read_bytes()).hexdigest() for p in names}
before = hashes()
env = os.environ.copy()
assert not env.get("PYTEST_ADDOPTS") and not env.get("PYTHONOPTIMIZE")
env["PYTHONPATH"] = str(branch)
tests = [new_test]
if stage == "integration_before":
    tests = ["tests/test_agent_integration_boundaries.py::test_compile_planning_does_not_hide_analysis_coverage_gap"]
if not negative_control:
    tests += ["tests/test_acceptance_projection.py", "tests/test_acceptance_feedback.py", "tests/test_acceptance_http_api.py", "tests/test_report_json_io.py", "tests/test_shared_report_storage.py", "tests/test_frozen_report_reader.py"]
if stage == "final":
    tests.append("tests/test_agent_integration_boundaries.py")
commands = [[sys.executable, "-m", "pytest", "-q", *tests, f"--junitxml={out / 'results.xml'}"]]
if not negative_control:
    commands += [
        [sys.executable, "-m", "compileall", "-f", "-q", *(["zscope", "scripts", "test", "tests"] if stage == "final" else ["zscope/reporting", new_test])],
        [sys.executable, "-m", "mypy", "zscope" if stage == "final" else "zscope/reporting/acceptance.py"],
        [sys.executable, "-m", "black", "--check", "zscope/reporting/acceptance.py", new_test, *(["tests/test_agent_integration_boundaries.py"] if stage == "final" else [])],
    ]
results = []
for i, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    log = out / f"command-{i}.log"
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run([sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", *command], cwd=branch, env=env, stdout=stream, stderr=subprocess.STDOUT)
    row = {"command": command, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "log": log.relative_to(ROOT).as_posix()}
    results.append(row)
    print(json.dumps({"stage": stage, "command_index": i, "returncode": result.returncode}), flush=True)
after = hashes()
suite = ET.parse(out / "results.xml").getroot().findall("testsuite")
junit = {k: sum(int(s.get(k, "0")) for s in suite) for k in ("tests", "failures", "errors", "skipped")}
proof = {"logical_task": "COORD-COVERAGE-PROJECTION-R21", "stage": stage, "finished_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "commands": results, "junit": junit, "before": before, "after": after, "source_unchanged_during_verification": before == after, "root_current_bytes_unchanged": all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in root_source.items()), "pytest_capture": "fd (unchanged default)", "test_slot_wrappers": 1, "root_product_changed": False, "native_executed": False, "scope": "Controlled serialized report projection only; not new native/real-project scan or Root joint acceptance", "independent_acceptance": False, "integrated": False, "joint_verification": False}
proof["projection_dependency_checks_passed"] = not negative_control and all(r["returncode"] == 0 for r in results) and junit["failures"] == junit["errors"] == junit["skipped"] == 0 and before == after and proof["root_current_bytes_unchanged"]
(out / "review.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("finished_at", "junit", "projection_dependency_checks_passed", "source_unchanged_during_verification", "root_current_bytes_unchanged")}), flush=True)
sys.exit(0 if negative_control and junit["failures"] > 0 and junit["errors"] == junit["skipped"] == 0 and before == after else 0 if proof["projection_dependency_checks_passed"] else 1)
