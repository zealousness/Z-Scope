"""Execute all cases of four strictly adapted tests against unchanged production."""
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
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-contract-tests-r33-20261017"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot():
    return {path.relative_to(WORK).as_posix(): sha(path) for path in WORK.rglob("*") if path.is_file() and path.relative_to(WORK).parts[0] != "artifacts" and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache"} for part in path.relative_to(WORK).parts) and path.suffix != ".pyc"}


assert sys.platform == "linux" and Path.cwd().resolve() == WORK and not sys.flags.optimize
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
prep = read(OUT / "preparation.json")
before = snapshot()
assert before == prep["complete_baseline"] | prep["candidate_sha256"] and len(before) == 1077
configs = {path.relative_to(WORK).as_posix(): sha(path) for name in ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml") for path in WORK.rglob(name) if path.is_file()}
assert configs == {"pyproject.toml": before["pyproject.toml"]}
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert all(sha(STAGE / path) == digest for path, digest in prep["complete_baseline"].items())
old_xml = ROOT / "artifacts/coordinator-stage-joint-r32-20261017/results.xml"
classes = {path[:-3].replace("/", ".") for path in prep["owned_paths"]}
prior = Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(old_xml).getroot().iter("testcase") if node.get("classname", "") in classes)
assert prior and len({key[0] for key in prior}) == 4
references = [Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", OUT / "preparation.json", old_xml]
refs = {str(path): sha(path) for path in references}
runtime = inspect_root_runtime(require_slot=True)
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_before = sha(native)
assert not (OUT / "results.xml").exists()
write(OUT / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), inputs=before, configurations=configs, prior_counter=[list(key)+[count] for key,count in prior.items()], references_sha256=refs, runtime=runtime))
commands = [
    [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", *prep["owned_paths"], f"--junitxml={OUT / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", *prep["owned_paths"]],
]
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
actual = Counter((node.get("classname", ""), node.get("name", "")) for node in tree.iter("testcase"))
counts = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
source_ok = snapshot() == before
stage_ok = all(sha(STAGE / path) == digest for path, digest in prep["complete_baseline"].items())
root_ok = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
refs_ok = all(sha(Path(path)) == digest for path, digest in refs.items())
native_ok = sha(native) == native_before
passed = all(row["returncode"] == 0 for row in results) and counts["failures"] == counts["errors"] == counts["skipped"] == 0 and actual == prior and source_ok and stage_ok and root_ok and refs_ok and native_ok
write(OUT / "review.json", dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, source1077_unchanged=source_ok, root1065_unchanged=root_ok, stage1077_unchanged=stage_ok, native_unchanged=native_ok, references_unchanged=refs_ok, old_case_counter_exact=actual==prior, isolated_contract_test_verification_passed=passed, production_changed=False, stage_intake=False, root_intake=False))
print(json.dumps(dict(passed=passed, junit=counts)))
raise SystemExit(0 if passed else 1)
