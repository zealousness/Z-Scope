"""Broaden revision compatibility checks, retaining unrelated full-mypy blockers."""
from collections import Counter
from pathlib import Path
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
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-contract-tests-r33"
OUT = ROOT / "artifacts/coordinator-review-revision-repair-r33-20261017/regression"
BASE = OUT.parent
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot():
    return {path.relative_to(WORK).as_posix(): sha(path) for path in WORK.rglob("*") if path.is_file() and path.relative_to(WORK).parts[0] != "artifacts" and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache"} for part in path.parts) and path.suffix != ".pyc"}


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


assert sys.platform == "linux" and not sys.flags.optimize and Path.cwd().resolve() == WORK
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
frozen, candidate = read(BASE / "test-freeze.json"), read(BASE / "candidate.json")
assert read(BASE / "green/review.json")["bounded_current_revision_green_passed"]
before = snapshot()
assert before == frozen["complete_red_inputs"] | {candidate["source_path"]: candidate["candidate_sha256"]} and len(before) == 1078
configs = {path.relative_to(WORK).as_posix(): sha(path) for name in ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml") for path in WORK.rglob(name) if path.is_file()}
assert configs == {"pyproject.toml": before["pyproject.toml"]}
runtime = inspect_root_runtime(require_slot=True)
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
old_prep = read(ROOT / "artifacts/coordinator-contract-tests-r33-20261017/preparation.json")
tests = old_prep["owned_paths"] + [frozen["fixed_test_path"], "tests/test_checked_proofs_gate.py", "tests/test_review_fact_checks.py", "tests/test_lock_coverage.py", "tests/test_review_regressions.py", "tests/test_rule_runtime_governance.py", "tests/test_rule_qualification.py", "tests/test_rule_catalog.py", "tests/test_review_proof_identity.py"]
assert len(tests) == len(set(tests)) == 13 and all((WORK / path).is_file() for path in tests)
prior_xml = {"legacy57": ROOT / "artifacts/coordinator-contract-tests-r33-20261017/results.xml", "current33": BASE / "green/results.xml"}
prior = {name: cases(path) for name, path in prior_xml.items()}
assert sum(prior["legacy57"].values()) == 57 and sum(prior["current33"].values()) == 33
references = [Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", BASE / "test-freeze.json", BASE / "candidate.json", BASE / "green/review.json", ROOT / "artifacts/coordinator-review-revision-audit-r33-20261017/review.json", *prior_xml.values()]
refs = {str(path): sha(path) for path in references}
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_before = sha(native)
commands = [
    [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", *tests, f"--junitxml={OUT / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", candidate["source_path"]],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "mypy", "--no-incremental", "zscope"],
    [sys.executable, "-m", "black", "--check", frozen["fixed_test_path"]],
]
OUT.mkdir(exist_ok=False)
write(OUT / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), inputs=before, configurations=configs, selected_test_files=len(tests), references_sha256=refs, prior_case_counters={name: [list(key)+[count] for key,count in value.items()] for name,value in prior.items()}, runtime=runtime, unchanged_baseline_parallel492_full_mypy_may_still_block=True))
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = str(native)
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, returncode=result.returncode, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=index, returncode=result.returncode)), flush=True)
tree = ET.parse(OUT / "results.xml").getroot()
actual = cases(OUT / "results.xml")
counts = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
gates = dict(source1078_unchanged=snapshot()==before, root1065_unchanged=all(sha(ROOT / path)==digest for path,digest in root_inputs.items()), references_unchanged=all(sha(Path(path))==digest for path,digest in refs.items()), native_unchanged=sha(native)==native_before, old57_and33_counters_preserved=all(not(counter-actual) for counter in prior.values()))
bounded = all(gates.values()) and counts["tests"] > 0 and counts["failures"] == counts["errors"] == counts["skipped"] == 0 and all(results[index]["returncode"] == 0 for index in (0,1,2,5))
full_quality = all(gates.values()) and all(results[index]["returncode"] == 0 for index in (1,2,3,4,5))
write(OUT / "review.json", dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, gates=gates, bounded_revision_regression_and_target_quality_passed=bounded, full_isolated_zscope_quality_passed=full_quality, full_stage_quality_passed=False, stage_intake=False, root_intake=False))
print(json.dumps(dict(bounded_passed=bounded, full_quality_passed=full_quality, junit=counts)))
raise SystemExit(0 if bounded and full_quality else 1)
