"""Current Stage union: retain Root R23, Stage R30 and S01 R31 cases/checks."""
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
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
PRODUCER = ROOT / ".coordination/20261014/workspaces/s01-origin-repair-r31"
OUT = ROOT / "artifacts/coordinator-stage-joint-r32-20261017"
INTAKE = ROOT / "artifacts/s01-stage-intake-r32-20261017/receipt.json"
assert sys.platform == "linux" and not sys.flags.optimize and not os.environ.get("PYTHONOPTIMIZE")
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
assert Path.cwd().resolve() == STAGE.resolve()
runtime = inspect_root_runtime(require_slot=True)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


def snapshot():
    return {path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}


configuration_names = {"conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml"}


def configurations():
    return {path.relative_to(STAGE).as_posix(): sha(path) for name in configuration_names for path in STAGE.rglob(name) if path.is_file()}


intake = read(INTAKE)
assert intake["stage_intake"] and intake["independent_module_acceptance"] and not intake["root_intake"]
assert snapshot() == intake["stage_source_after"]
assert configurations() == intake["configuration_baseline"]
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
prep = read(ROOT / "artifacts/coordinator-s01-replacement-r31-20261017/preparation.json")
freeze = read(PRODUCER / "artifacts/s01-repair-r31/freeze.json")
producer_inputs = prep["readonly_sources"] | freeze["source_sha256"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert all(sha(PRODUCER / path) == digest for path, digest in producer_inputs.items())
root_receipt = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/review.json"
stage_receipt = ROOT / "artifacts/coordinator-stage-regression-r30-20261017/review.json"
s01_receipt = ROOT / "artifacts/coordinator-s01-repair-r31-r32-independent-20261017/review.json"
root_joint, stage_joint, s01 = map(read, (root_receipt, stage_receipt, s01_receipt))
root_tests = root_joint["commands"][0]["command"][4:-1]
stage_tests = stage_joint["commands"][0]["argv"][6:-1]
s01_tests = s01["commands"][0]["argv"][6:-1]
assert len(root_tests) == 171 and len(stage_tests) == 34 and len(s01_tests) == 13
tests = list(dict.fromkeys(root_tests + stage_tests + s01_tests + ["tests/test_instance_semantics_context.py", "tests/test_instance_semantics_integration.py", "tests/test_instance_partial_recovery_integration.py"]))
assert all((Path(path) if Path(path).is_absolute() else STAGE / path).is_file() for path in tests)
old_black = root_joint["commands"][4]["command"]
assert old_black[:4] == [sys.executable, "-m", "black", "--check"]
changed_python = [path for path in intake["stage_changed_python_since_root"] if path.endswith(".py")]
black_paths = list(dict.fromkeys(old_black[4:] + changed_python))
authority_probe = ROOT / "artifacts/s01-authority-probe-r24-20261016/test_s01_authority_probe.py"
main_xml, authority_xml = OUT / "results.xml", OUT / "authority-r24.xml"
base = [sys.executable, "-m", "pytest", "-q", f"--rootdir={STAGE}", f"--confcutdir={STAGE}"]
commands = [
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "mypy", "--no-incremental", "zscope"],
    base + tests + [f"--junitxml={main_xml}"],
    base + [str(authority_probe), f"--junitxml={authority_xml}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    root_joint["commands"][3]["command"],
    [sys.executable, "-m", "black", "--check", *black_paths],
    root_joint["commands"][5]["command"],
]
assert commands[5] == [sys.executable, "-m", "mypy", "scripts/agent_plan_evaluation.py"]
assert commands[7] == [sys.executable, "scripts/portable/web_assets.py"]
before, configs_before = snapshot(), configurations()
references_cases = dict(root_r23=ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/results.xml", stage_r30=ROOT / "artifacts/coordinator-stage-regression-r30-20261017/results.xml", s01_r32=s01_receipt.parent / "results.xml")
prior_counters = {key: cases(path) for key, path in references_cases.items()}
prior_authority_counter = cases(s01_receipt.parent / "authority-r24.xml")
assert {key: sum(value.values()) for key, value in prior_counters.items()} == dict(root_r23=2551, stage_r30=1147, s01_r32=209)
assert sum(prior_authority_counter.values()) == 4
refs = [Path(__file__), INTAKE, HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", root_receipt, stage_receipt, s01_receipt, PRODUCER / "artifacts/s01-repair-r31/freeze.json", ROOT / "artifacts/s01-source-review-r32-20261017/review.json", authority_probe]
refs += [*references_cases.values(), s01_receipt.parent / "authority-r24.xml"]
refs += [Path(path) for path in tests if Path(path).is_absolute()]
reference_hashes = {str(path): sha(path) for path in refs}
OUT.mkdir(exist_ok=False)
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
write(OUT / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), selected_test_files=len(tests), unchanged_root_selected171=True, native_currentness_and_recovery_files_included=True, configurations=configs_before, prior_case_counters={key: [list(identity) + [count] for identity, count in counter.items()] for key, counter in prior_counters.items()}, prior_r24_counter=[list(identity) + [count] for identity, count in prior_authority_counter.items()], references_sha256=reference_hashes, runtime_preflight=runtime, root_intake=False))
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=STAGE, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), returncode=result.returncode))
    print(json.dumps(dict(command_index=index, returncode=result.returncode)), flush=True)
counts = {}
for name, path in (("main", main_xml), ("authority_r24", authority_xml)):
    if path.exists():
        tree = ET.parse(path).getroot()
        counts[name] = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
actual = cases(main_xml) if main_xml.exists() else Counter()
missing = {key: [list(identity) + [count] for identity, count in (counter - actual).items()] for key, counter in prior_counters.items()}
authority_preserved = authority_xml.exists() and cases(authority_xml) == prior_authority_counter
source_ok = before == snapshot() and configs_before == configurations() == intake["configuration_baseline"]
root_ok = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
producer_ok = all(sha(PRODUCER / path) == digest for path, digest in producer_inputs.items())
references_ok = all(sha(Path(path)) == digest for path, digest in reference_hashes.items())
zero_junit = len(counts) == 2 and all(item["tests"] > 0 and item["failures"] == item["errors"] == item["skipped"] == 0 for item in counts.values())
passed = all(item["returncode"] == 0 for item in results) and zero_junit and not any(missing.values()) and authority_preserved and source_ok and root_ok and producer_ok and references_ok
quality_passed = all(results[index]["returncode"] == 0 for index in (0, 1, 4, 5, 6, 7)) and source_ok and references_ok
write(OUT / "review.json", dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, selected_test_files=len(tests), old_root2551_stage1147_s01_209_case_counters_preserved=not any(missing.values()), missing_prior_cases=missing, separate_r24_counter_exact=bool(authority_preserved), source_before=before, sources_unchanged=source_ok, configurations_unchanged=configs_before==configurations(), root_unchanged=root_ok, producer_unchanged=producer_ok, references_sha256=reference_hashes, references_unchanged=references_ok, runtime_preflight=runtime, full_stage_quality_passed=quality_passed, selected_stage_joint_checks_passed=bool(passed), native_currentness_and_recovery_selected_checks_executed=True, root_intake=False, root_joint_verification=False, full_repository_suite_run=False, full_packages_complete=False, real_project_effect_acceptance=False))
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), passed=bool(passed), quality_passed=quality_passed, junit=counts)))
raise SystemExit(0 if passed else 1)
