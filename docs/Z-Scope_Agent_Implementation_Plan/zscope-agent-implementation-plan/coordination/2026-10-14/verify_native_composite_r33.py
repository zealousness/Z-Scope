"""Independently execute frozen composite native behavior without producer writes."""
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
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-native-composite-r33"
OUT = ROOT / "artifacts/coordinator-native-composite-r33-20261017"
PROBE = ROOT / "artifacts/coordinator-native-classifier-probes-r33-20261017/test_native_classifier_currentness_r33.py"
CONFIG_NAMES = {"conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml"}


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot():
    return {path.relative_to(WORK).as_posix(): sha(path) for path in WORK.rglob("*") if path.is_file() and path.relative_to(WORK).parts[0] != "artifacts" and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache"} for part in path.parts) and path.suffix != ".pyc" and path.name != "DELIVERY.md"}


def configs():
    return {path.relative_to(WORK).as_posix(): sha(path) for name in CONFIG_NAMES for path in WORK.rglob(name) if path.is_file()}


def counter(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


def host_inputs():
    tool = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
    assert sha(tool) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
    linked = subprocess.run(["ldd", str(tool)], capture_output=True, text=True, timeout=10)
    assert linked.returncode == 0 and "not found" not in linked.stdout + linked.stderr
    libraries = {Path(value) for value in re.findall(r"/[^\s()]+", linked.stdout)}
    assert libraries and all(path.is_file() for path in libraries)
    files = {str(path): dict(sha256=sha(path), physical=str(path.resolve(strict=True))) for path in libraries | {tool, Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")}}
    installation = {}
    for header in (Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")):
        for path in (header, *header.parents):
            info = path.lstat()
            installation[str(path)] = dict(uid=info.st_uid, mode=info.st_mode, physical=str(path.resolve(strict=True)))
    return dict(files=files, standard_installation=installation)


assert sys.platform == "linux" and not sys.flags.optimize and Path.cwd().resolve() == WORK
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
prep = read(OUT / "preparation.json")
assert len(prep["root_inputs"]) == 1065 and all(sha(ROOT / path) == digest for path, digest in prep["root_inputs"].items())
probe_prep = read(OUT / "probe-preparation.json")
assert probe_prep["previous_preparation_sha256"] == sha(OUT / "preparation.json")
assert probe_prep["frozen_external_probe_sha256"] == sha(PROBE)
before = snapshot()
assert before == probe_prep["complete_inputs"] and len(before) == 1080
configs_before = configs()
assert configs_before == {"pyproject.toml": before["pyproject.toml"]}
runtime = inspect_root_runtime(require_slot=True)
host_before = host_inputs()
cost = ROOT / ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/bridge-v3-check"
context = ROOT / ".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33/own-20261017T025955.464720Z"
references = [Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", PROBE, OUT / "preparation.json", OUT / "probe-preparation.json", cost / "receipt.json", cost / "pytest.xml", context / "receipt.json", context / "pytest.xml"]
assert all(path.is_file() for path in references)
reference_sha = {str(path): sha(path) for path in references} | prep["reference_sha256"]
assert all(sha(Path(path)) == digest for path, digest in reference_sha.items())
prior_cost, prior_context = counter(cost / "pytest.xml"), counter(context / "pytest.xml")
assert sum(prior_cost.values()) == 4 and sum(prior_context.values()) == 45
changes = [("binary", "changed"), ("library", "changed")] + [(header, change) for header in ("/usr/include/stdlib.h", "/usr/include/features.h") for change in ("uid", "group_write", "other_write", "symlink", "missing")] + [(parent, change) for parent in ("/usr/include", "/usr", "/") for change in ("uid", "group_write", "symlink", "missing")]
classifier_counter = Counter({("tests.test_native_classifier_currentness_r33", "test_current_composite_retains_real_factory_standard_authority"): 1})
classifier_counter.update(("tests.test_native_classifier_currentness_r33", f"test_actual_classifier_rechecks_composite_authority[{kind}-{change}-{when}]") for kind, change in changes for when in ("before", "after"))
assert sum(classifier_counter.values()) == 49
native_xml, probe_xml = OUT / "native.xml", OUT / "classifier.xml"
assert not native_xml.exists() and not probe_xml.exists()
base = [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}"]
commands = [
    base + ["tests/test_instance_currentness_revocation_r33.py", "tests/test_instance_partial_recovery_integration.py::test_all_restored_still_runs_current_validation_once", "tests/test_instance_recovery_cost_r33.py::test_native_lookup_bridge_keeps_signature_and_rejects_foreign_identity", "tests/test_instance_recovery_cost_r33.py::test_real_native_same_line_functions_cannot_exchange_lookup_identity", "tests/test_instance_recovery_cost_r33.py::test_real_native_project_standard_spelling_does_not_authorize_external_skip", f"--junitxml={native_xml}"],
    base + ["tests/test_native_classifier_currentness_r33.py", f"--junitxml={probe_xml}"],
]
write(OUT / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), inputs=before, configurations=configs_before, references_sha256=reference_sha, prior_case_counters={"cost": [list(key)+[count] for key,count in prior_cost.items()], "context": [list(key)+[count] for key,count in prior_context.items()]}, classifier_counter=[list(key)+[count] for key,count in classifier_counter.items()], expected_counts=[49, 49], host_inputs_before=host_before, runtime=runtime, stage_intake=False, root_intake=False))
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, returncode=result.returncode, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=index, returncode=result.returncode)), flush=True)
counts = {}
for name, path in (("native", native_xml), ("classifier", probe_xml)):
    tree = ET.parse(path).getroot()
    counts[name] = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
actual = counter(native_xml)
case_preserved = actual == prior_cost + prior_context
classifier_preserved = counter(probe_xml) == classifier_counter
host_after = host_inputs()
host_ok = host_after == host_before
source_ok = snapshot() == before and configs() == configs_before
references_ok = all(sha(Path(path)) == digest for path, digest in reference_sha.items())
root_ok = all(sha(ROOT / path) == digest for path, digest in prep["root_inputs"].items())
passed = all(row["returncode"] == 0 for row in results) and all(row["tests"] == 49 and row["failures"] == row["errors"] == row["skipped"] == 0 for row in counts.values()) and case_preserved and classifier_preserved and host_ok and source_ok and references_ok and root_ok
write(OUT / "review.json", dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, complete1080_inputs_unchanged=source_ok, prior4_and45_counters_exact=case_preserved, classifier49_counter_exact=classifier_preserved, host_inputs_after=host_after, host_inputs_unchanged=host_ok, references_unchanged=references_ok, root1065_unchanged=root_ok, bounded_composite_native_independent_passed=passed, P2_cost_logic_changed=False, stage_intake=False, root_intake=False, joint_verification=False))
print(json.dumps(dict(passed=passed, junit=counts)))
raise SystemExit(0 if passed else 1)
