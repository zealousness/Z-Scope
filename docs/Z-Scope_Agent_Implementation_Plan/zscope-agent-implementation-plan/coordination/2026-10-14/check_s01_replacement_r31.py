"""Fixed unchanged-standard checks for the new public S01 fourth delivery."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/s01-origin-repair-r31"
PREP = ROOT / "artifacts/coordinator-s01-replacement-r31-20261017/preparation.json"
assert sys.platform == "linux" and not sys.flags.optimize and not os.environ.get("PYTHONOPTIMIZE")
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
assert len(sys.argv) == 3 and sys.argv[1] in {"producer", "independent"} and re.fullmatch(r"[a-z0-9-]{1,40}", sys.argv[2])
assert Path.cwd().resolve() == WORK.resolve()
runtime = inspect_root_runtime(require_slot=True)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


prep = read(PREP)
old = ROOT / prep["old_workspace"]
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
configuration_names = {"conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml"}
configuration_baseline = {path: digest for path, digest in prep["new_source_inputs"].items() if Path(path).name in configuration_names}


def configurations():
    return {path.relative_to(WORK).as_posix(): sha(path) for name in configuration_names for path in WORK.rglob(name) if path.is_file()}


def guard():
    assert configurations() == configuration_baseline, "No new, missing or modified test/type configuration files"
    assert all(sha(WORK / path) == digest for path, digest in prep["readonly_sources"].items())
    assert all(sha(old / path) == digest for path, digest in prep["old_workspace_inputs"].items())
    assert all(sha(ROOT / path) == digest for path, digest in prep["root_inputs"].items())
    assert all(sha(stage / path) == digest for path, digest in prep["stage_inputs"].items())
    assert (WORK / "tests/test_instance_semantics.py").read_bytes().startswith((old / "tests/test_instance_semantics.py").read_bytes())
    actual = {path.relative_to(WORK).as_posix() for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (WORK / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}
    expected = {path for path in prep["new_source_inputs"] if path.startswith(("zscope/", "scripts/", "test/", "tests/", "docs/modules/"))}
    assert actual == expected, "Only the two owned source/test files may change"


guard()
source_before = {path: sha(WORK / path) for path in prep["new_source_inputs"]}
configurations_before = configurations()
mode, label = sys.argv[1:]
out = (WORK / "artifacts/s01-repair-r31" / label) if mode == "producer" else ROOT / "artifacts" / f"coordinator-s01-repair-r31-{label}-20261017"
out.mkdir(parents=True, exist_ok=False)
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
prior = read(ROOT / "artifacts/coordinator-s01-module-dependency-r26-20261016/review.json")
test_files = prior["commands"][0]["command"][6:-1]
assert len(test_files) == 12 and test_files[0] == "tests/test_instance_semantics.py"
forms = ROOT / "artifacts/s01-origin-forms-probe-r26-20261016/test_s01_origin_forms_probe.py"
authority = ROOT / "artifacts/s01-authority-probe-r24-20261016/test_s01_authority_probe.py"
external = [ROOT / path for path in prior["independent_probe_files"]] + [forms, authority]
references = {str(path): sha(path) for path in [Path(__file__), PREP, HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", *external]}
base = [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}"]
commands = [
    base + test_files + [str(forms), f"--junitxml={out / 'results.xml'}"],
    base + [str(authority), f"--junitxml={out / 'authority-r24.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "mypy", "--no-incremental", "zscope"],
    [sys.executable, "-m", "black", "--check", *prep["write_paths"]],
]
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (out / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), returncode=result.returncode))
    print(json.dumps(dict(mode=mode, command_index=index, returncode=result.returncode)), flush=True)
guard()
source_after = {path: sha(WORK / path) for path in prep["new_source_inputs"]}
configurations_after = configurations()
assert configurations_before == configurations_after == configuration_baseline
assert source_before == source_after and all(sha(Path(path)) == digest for path, digest in references.items())
summaries = {}
for name in ("results.xml", "authority-r24.xml"):
    if (out / name).exists():
        tree = ET.parse(out / name).getroot()
        summaries[name] = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
required = cases(ROOT / "artifacts/coordinator-s01-module-dependency-r26-20261016/results.xml") + cases(ROOT / "artifacts/coordinator-s01-origin-forms-r26-20261016/results.xml")
preserved = (out / "results.xml").exists() and not required - cases(out / "results.xml")
passed = all(item["returncode"] == 0 for item in results) and len(summaries) == 2 and all(not item["failures"] and not item["errors"] and not item["skipped"] for item in summaries.values()) and preserved
review = dict(actual_task="producer via new public Bridge" if mode == "producer" else "/root", logical_task=prep["logical_task"], request_id=prep["request_id"], mode=mode, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=summaries, original160_and_native3_case_counter_preserved=bool(preserved), source_before=source_before, source_after=source_after, configurations_before=configurations_before, configurations_after=configurations_after, configurations_unchanged=True, sources_unchanged=True, readonly_old_root_stage_unchanged=True, references_sha256=references, references_unchanged=True, runtime_preflight=runtime, checks_passed=bool(passed), previous_failed_delivery_count=3, counter_reset_by_this_check=False, independent_acceptance=False, integrated=False, joint_verification=False, whole_package_complete=False)
write(out / "review.json", review)
print(json.dumps(dict(receipt=out.relative_to(ROOT).as_posix() + "/review.json", checks_passed=bool(passed), junit=summaries)), flush=True)
raise SystemExit(0 if passed else 1)
