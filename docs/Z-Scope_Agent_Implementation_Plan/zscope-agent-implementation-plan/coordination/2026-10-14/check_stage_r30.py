"""Bounded Stage checks with full failure evidence and unchanged standards."""
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

assert sys.platform == "linux" and not sys.flags.optimize and not os.environ.get("PYTHONOPTIMIZE")
assert not os.environ.get("PYTEST_ADDOPTS") and not os.environ.get("PYTEST_PLUGINS")
assert len(sys.argv) == 2 and sys.argv[1] in {"mypy-before", "mypy-after", "mypy-fresh-before", "mypy-fresh-after", "regression", "quality", "quality-probe-before", "quality-probe-corrected-before", "quality-probe-after"}
MODE = sys.argv[1]
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert Path.cwd().resolve() == STAGE.resolve()
runtime = inspect_root_runtime(require_slot=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


def snapshot():
    return {path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}


def configs():
    return {path.relative_to(STAGE).as_posix(): sha(path) for name in ("conftest.py", "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml") for path in STAGE.rglob(name) if path.is_file()}


intake_path = ROOT / "artifacts/consumer-stage-intake-r30-20261017/receipt.json"
intake = read(intake_path)
assert intake["stage_intake"] and not intake["root_intake"]
assert all(sha(STAGE / path) == digest for path, digest in intake["copied_source_sha256"].items())
assert not (STAGE / "zscope/semantics/instance_semantics.py").exists()
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
producer = ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29"
producer_inputs = read(ROOT / "artifacts/coordinator-consumer-repair-r29-20261017/review.json")["source_before"]
assert all(sha(producer / path) == digest for path, digest in producer_inputs.items())
before = snapshot()
post_repair = MODE in {"mypy-after", "mypy-fresh-after", "regression", "quality", "quality-probe-after"}
repair_path = ROOT / "artifacts/stage-quality-repair-r30-20261017/repair-source.json"
if post_repair:
    assert before == read(repair_path)["full_stage_source_after"]
configs_before = configs()
assert all(intake["stage_source_after"].get(path) == digest for path, digest in configs_before.items())
OUT = ROOT / "artifacts" / f"coordinator-stage-{MODE}-r30-20261017"
OUT.mkdir(exist_ok=False)
launcher = Path(__file__).read_bytes()
(OUT / "launcher.py").write_bytes(launcher)
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = str(native)
prior_consumer_xml = ROOT / "artifacts/coordinator-consumer-repair-r29-20261017/results.xml"
prior_store_xml = ROOT / "artifacts/coordinator-store-queue-r26-e0560b7b2e9d/results.xml"
probe = ROOT / "artifacts/astra-consumer-boundary-probes-r28-20261017/test_consumer_boundaries.py"
assert sha(probe) == "99a83adadeadc26ac1348acfffc6eee190a74b2750132faa58c48addd9f8d058"
failure_probe_xml = ROOT / "artifacts/coordinator-stage-quality-probe-corrected-before-r30-20261017/results.xml"
controls = [Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", intake_path, prior_consumer_xml, prior_store_xml, native, probe, ROOT / "artifacts/coordinator-astra-consumers-r28-20261017/review.json"]
if post_repair:
    controls.extend([repair_path, failure_probe_xml, HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-06.json"])
references = {str(path): sha(path) for path in controls}
test_files = read(ROOT / "artifacts/coordinator-astra-consumers-r28-20261017/review.json")["test_files"] + [
    "tests/test_job_bound_instance_results.py", "tests/test_job_bound_completion.py",
    "tests/test_job_session_scheduler.py", "tests/test_scan_job_work_queue.py",
    "tests/test_instance_result_recovery.py", "tests/test_candidate_ledger.py",
    "tests/test_stage_independent_quality.py",
]
assert len(test_files) == len(set(test_files)) == 33
required = cases(prior_consumer_xml) + cases(prior_store_xml)
assert sum(required.values()) == 1120
if MODE.startswith("mypy"):
    commands = [[sys.executable, "-m", "mypy", *(["--no-incremental", "--verbose"] if "fresh" in MODE else []), "zscope"]]
elif MODE == "quality":
    commands = [
        [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
        [sys.executable, "-m", "black", "--check", "zscope/core/analysis/analyzer.py", "zscope/orchestration/parallel_analyzer.py", "zscope/orchestration/candidates.py", "zscope/orchestration/jobs/scan_work.py", "zscope/orchestration/instance_semantics_context.py", "tests/test_instance_semantics_context.py", "tests/test_stage_independent_quality.py", *[path for path in intake["copied_source_sha256"] if path.endswith(".py")]],
    ]
else:
    files = test_files if MODE == "regression" else ["tests/test_stage_independent_quality.py"]
    commands = [[sys.executable, "-m", "pytest", "-q", f"--rootdir={STAGE}", f"--confcutdir={STAGE}", *files, *([str(probe)] if MODE == "regression" else []), f"--junitxml={OUT / 'results.xml'}"]]
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=STAGE, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), returncode=result.returncode))
    print(json.dumps(dict(mode=MODE, command_index=index, returncode=result.returncode)), flush=True)
xml = OUT / "results.xml"
counts = None
missing = []
failure_probe_preserved = None
if xml.exists():
    suites = ET.parse(xml).getroot().findall("testsuite")
    counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
    if MODE == "regression":
        missing = [list(key) + [count] for key, count in (required - cases(xml)).items()]
    if MODE in {"regression", "quality-probe-after"}:
        failure_probe_preserved = not bool(cases(failure_probe_xml) - cases(xml))
        if MODE == "quality-probe-after":
            failure_probe_preserved = cases(failure_probe_xml) == cases(xml)
source_ok = before == snapshot() and configs_before == configs()
root_ok = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
producer_ok = all(sha(producer / path) == digest for path, digest in producer_inputs.items())
references_ok = all(sha(Path(path)) == digest for path, digest in references.items()) and launcher == Path(__file__).read_bytes()
passed = all(row["returncode"] == 0 for row in results) and source_ok and root_ok and producer_ok and references_ok and not missing
if counts is not None:
    passed = passed and counts["tests"] > 0 and counts["failures"] == counts["errors"] == counts["skipped"] == 0
if failure_probe_preserved is not None:
    passed = passed and failure_probe_preserved
proof = dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", phase=MODE, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, required1120_case_counter_preserved=(not missing) if MODE == "regression" else None, prior14_failure_probe_case_counter_preserved=failure_probe_preserved, missing_required_cases=missing, source_before=before, sources_unchanged=source_ok, configurations_unchanged=configs_before==configs(), root_unchanged=root_ok, producer_unchanged=producer_ok, references_sha256=references, references_unchanged=references_ok, runtime_preflight=runtime, bounded_checks_passed=passed, full_stage_quality_passed=False, missing_s01_still_not_admitted=True, independent_acceptance=False, root_intake=False, root_joint_verification=False, whole_packages_complete=False, scope="S01-independent bounded Stage checks only. Full mypy runs with original settings; any missing real dependency remains an error. No placeholders, ignore flags or weakened tests. Full native instance/PRE/current Validator and Root joint acceptance remain pending.")
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), phase=MODE, junit=counts, passed=passed)), flush=True)
sys.exit(0 if passed else 1)
