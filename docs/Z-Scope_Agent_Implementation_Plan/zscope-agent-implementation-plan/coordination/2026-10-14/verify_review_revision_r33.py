"""Actual compiler red/green checks with complete inputs and exact case identities."""
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
OUT = ROOT / "artifacts/coordinator-review-revision-repair-r33-20261017"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot():
    return {path.relative_to(WORK).as_posix(): sha(path) for path in WORK.rglob("*") if path.is_file() and path.relative_to(WORK).parts[0] != "artifacts" and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache"} for part in path.parts) and path.suffix != ".pyc"}


assert sys.platform == "linux" and not sys.flags.optimize and Path.cwd().resolve() == WORK
assert len(sys.argv) == 2 and sys.argv[1] in {"red", "green"}
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
phase = sys.argv[1]
frozen = read(OUT / "test-freeze.json")
candidate = read(OUT / "candidate.json")
expected = frozen["complete_red_inputs"] | ({candidate["source_path"]: frozen["product_candidate_sha256"]} if phase == "green" else {})
before = snapshot()
assert before == expected and len(before) == 1078
configs = {path.relative_to(WORK).as_posix(): sha(path) for name in ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml") for path in WORK.rglob(name) if path.is_file()}
assert configs == {"pyproject.toml": before["pyproject.toml"]}
runtime = inspect_root_runtime(require_slot=True)
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
rules = list(candidate["explicit_current_additions"])
expected_counter = Counter(("tests.test_review_current_revisions_r33", f"test_current_revision_preserves_independent_proof_requirement[{mode}-{rule}]") for mode in ("current_safe", "current_unsafe", "unknown_revision") for rule in rules)
assert sum(expected_counter.values()) == 33
references = [Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", OUT / "candidate.json", OUT / "test-freeze.json", OUT / "test_review_current_revisions_r33.py"]
if phase == "green":
    references += [OUT / "red/review.json", OUT / "red/results.xml"]
refs = {str(path): sha(path) for path in references}
target = OUT / phase
target.mkdir(exist_ok=False)
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_before = sha(native)
write(target / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), phase=phase, complete_inputs=before, configurations=configs, expected_counter=[list(key)+[count] for key,count in expected_counter.items()], references_sha256=refs, runtime=runtime))
command = [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", frozen["fixed_test_path"], f"--junitxml={target / 'results.xml'}"]
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = str(native)
with (target / "command-0.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
tree = ET.parse(target / "results.xml").getroot()
actual = Counter((node.get("classname", ""), node.get("name", "")) for node in tree.iter("testcase"))
counts = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
gates = dict(source1078_unchanged=snapshot()==before, root1065_unchanged=all(sha(ROOT / path)==digest for path,digest in root_inputs.items()), fixed_test_unchanged=sha(WORK / frozen["fixed_test_path"])==frozen["fixed_test_sha256"], references_unchanged=all(sha(Path(path))==digest for path,digest in refs.items()), exact33_counter=actual==expected_counter, native_unchanged=sha(native)==native_before)
if phase == "green":
    red = read(OUT / "red/review.json")
    gates["red_green_counter_exact"] = red["case_counter"] == [list(key)+[count] for key,count in sorted(actual.items())]
    gates["red_valid"] = red["valid_red_reproduction"]
passed = all(gates.values()) and counts["tests"] == 33 and counts["errors"] == counts["skipped"] == 0
valid_red = phase == "red" and passed and result.returncode == 1 and counts["failures"] == 11
green_passed = phase == "green" and passed and result.returncode == 0 and counts["failures"] == 0
write(target / "review.json", dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), phase=phase, command=command, returncode=result.returncode, junit=counts, gates=gates, case_counter=[list(key)+[count] for key,count in sorted(actual.items())], valid_red_reproduction=valid_red, bounded_current_revision_green_passed=green_passed, stage_intake=False, root_intake=False))
print(json.dumps(dict(phase=phase, junit=counts, gates=gates, valid_red=valid_red, green_passed=green_passed)))
raise SystemExit(0 if valid_red or green_passed else 1)
