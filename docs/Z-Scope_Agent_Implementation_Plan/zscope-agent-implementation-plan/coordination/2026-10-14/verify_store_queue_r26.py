"""Fixed Store/Queue checks in coordinator isolation; no whole-scan claim."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("Only non-optimized Linux Python may run verification guards")
if os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
    raise RuntimeError("Pytest environment overrides are forbidden")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert Path.cwd().resolve() == STAGE.resolve()
runtime = inspect_root_runtime(require_slot=True)

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
baseline = read(HERE / "followups-r12/coordinator-instance-integration-r24-baseline.json")
expected = {entry["path"]: entry["sha256"] for entry in baseline["files"]}
allowed = set(baseline["task"]["write_paths"])
extensions = [HERE / "followups-r12" / ("coordinator-instance-integration-r24-ownership-extension-" + suffix + ".json") for suffix in ("01", "02", "03", "04")]
for extension in extensions:
    allowed.update(read(extension)["write_paths"])
assert all(sha(STAGE / path) == digest for path, digest in expected.items() if path not in allowed)
assert all((STAGE / path).is_file() for path in allowed), "All declared stage files are required"
assert not (STAGE / "zscope/semantics/instance_semantics.py").exists(), "Failed S01 must not enter coordinator isolation"
intake_path = ROOT / "artifacts/s08-codec-stage-intake-r26-20261016/receipt.json"
intake = read(intake_path)
assert intake["stage_intake"] and not intake["root_intake"] and intake["actual_producer_task_id"] == "task_0d7256802a"
assert all(sha(STAGE / path) == digest for path, digest in intake["source_sha256"].items())
assert intake["references_unchanged"] and all(sha(Path(path)) == digest for path, digest in intake["references_sha256"].items())
def snapshot():
    result = {path: sha(STAGE / path) for path in sorted(set(expected) | allowed)}
    result.update({path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"})
    return result

def config_snapshot():
    result = {}
    for name in ("conftest.py", "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"):
        for path in STAGE.rglob(name):
            if path.is_file():
                result[path.relative_to(STAGE).as_posix()] = sha(path)
    return result

source_before = snapshot()
assert not set(source_before) - set(expected) - allowed
config_before = config_snapshot()
assert all(path in expected and expected[path] == digest for path, digest in config_before.items())
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
assert sha(native) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
references = {str(path): sha(path) for path in [Path(__file__), intake_path, native, *extensions, *map(Path, intake["references_sha256"])]}
OUT = ROOT / "artifacts" / ("coordinator-store-queue-r26-" + uuid.uuid4().hex[:12])
OUT.mkdir(exist_ok=False)
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
test_files = ["tests/test_job_bound_instance_results.py", "tests/test_job_bound_completion.py", "tests/test_job_session_scheduler.py", "tests/test_scan_job_work_queue.py", "tests/test_instance_result_recovery.py"]
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
commands = [
    [sys.executable, "-m", "pytest", "-q", f"--rootdir={STAGE}", f"--confcutdir={STAGE}", *test_files, f"--junitxml={OUT / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "black", "--check", "zscope/orchestration/jobs/store.py", "zscope/orchestration/jobs/session_scheduler.py", "zscope/orchestration/jobs/instance_results.py", "tests/test_job_bound_instance_results.py", "tests/test_instance_result_recovery.py"],
]
results = []
for index, command in enumerate(commands):
    start = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=STAGE, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(command=command, returncode=result.returncode, started_at=start, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=index, returncode=result.returncode)), flush=True)
junit = OUT / "results.xml"
suites = ET.parse(junit).getroot().findall("testsuite") if junit.is_file() else []
counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
stable = source_before == snapshot() and config_before == config_snapshot()
root_stable = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
reference_stable = all(sha(Path(path)) == digest for path, digest in references.items())
reference_stable = reference_stable and (OUT / "launcher.py").read_bytes() == Path(__file__).read_bytes()
passed = all(result["returncode"] == 0 for result in results) and counts["tests"] > 0 and not any(counts[key] for key in ("failures", "errors", "skipped")) and stable and root_stable and reference_stable
proof = dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", scope="Controlled codec payloads with actual SQL/queue fencing, scheduler/queue regressions and accepted codec tests. No native producer closure, P/R/E, fresh Validator barrier or full-scan acceptance.", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, source_before=source_before, sources_unchanged=stable, root_unchanged=root_stable, references=references, references_unchanged=reference_stable, runtime_preflight=runtime, focused_checks_passed=passed, independent_acceptance=False, integrated=False, root_joint_verification=False, whole_packages_complete=False)
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), junit=counts, passed=passed)), flush=True)
sys.exit(0 if passed else 1)
