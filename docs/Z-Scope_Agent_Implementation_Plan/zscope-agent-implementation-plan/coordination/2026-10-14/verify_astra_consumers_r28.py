"""Independent checks of the frozen consumer candidate; no Root intake."""
from pathlib import Path
from collections import Counter
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("Non-optimized Linux Python required")
if os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
    raise RuntimeError("Pytest environment overrides forbidden")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
ART = BRANCH / "artifacts/instance-consumers-r25"
if Path.cwd().resolve() != BRANCH.resolve():
    raise RuntimeError("Wrong outer test-slot workspace")
runtime = inspect_root_runtime(require_slot=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def cases(path):
    return Counter((case.get("classname", ""), case.get("name", "")) for case in ET.parse(path).getroot().iter("testcase"))

root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
producer_path = ART / "review.json"
assert sha(producer_path) == "5101d36e10090514e2b4dabb41536e8e555f4075701a0c9a0853fbf9ec544352"
producer = read(producer_path)
assert producer["actual_task"] == "/root/astra_design_contract_r23" and producer["candidate_complete"]
assert not producer["slice_accepted"] and not producer["root_intake"] and not producer["coordinator_stage_intake"]
owned = producer["ownership"]["owned_paths"]
assert len(owned) == 11 and set(producer["source_after"]) == set(owned)
effective_path = HERE / "followups-r12/astra-instance-consumers-r25-readonly-dependencies-r26.json"
assert sha(effective_path) == producer["ownership"]["effective_manifest_sha256"]
effective = read(effective_path)
assert effective["coordinator_owned"] and not effective["root_intake"] and not effective["stage_intake"]
inputs = {row["path"]: row["sha256"] for row in effective["files"]}
assert len(inputs) == 1070
readonly = {path: digest for path, digest in inputs.items() if path not in owned}
assert len(readonly) == 1060
inputs.update(producer["source_after"])
assert len(inputs) == 1071 and all(sha(BRANCH / path) == digest for path, digest in inputs.items())
assert all(sha(ART / path) == digest for path, digest in producer["artifact_sha256"].items())
test_files = [
    "tests/test_instance_builtin_consumers.py", "tests/test_regex_candidates.py",
    "tests/test_graph_candidates.py", "tests/test_clang_ast_cfg_candidates.py",
    "tests/test_cpp_candidate_domains.py", "tests/test_rule_catalog.py",
    "tests/test_rule_implementation.py", "tests/test_rule_runtime_governance.py",
    "tests/test_rule_qualification.py", "tests/test_rule_engine.py",
    "tests/test_candidate_rule_policy.py", "tests/test_candidate_build_identity.py",
    "tests/test_semantic_contract_schema.py", "tests/test_semantic_contract_chain.py",
    "tests/test_conditional_ownership_contracts.py", "tests/test_contract_build_scope.py",
    "tests/test_contract_usr_scope.py", "tests/test_contract_symbol_ambiguity.py",
    "tests/test_lock_modes.py", "tests/test_lock_coverage.py", "tests/test_analyzer_semantics.py",
    "tests/test_semantics_defaults.py", "tests/test_semantics_shadow_overlay.py",
    "tests/test_review_regressions.py", "tests/test_branch_return_missing_unlock.py",
    "tests/test_candidate_evidence.py",
]
# Inspect the producer argv as data solely to reconcile file identities;
# never execute the producer's wrapper, shell, environment or saved argv.
producer_files = [arg for arg in read(ART / "regression-05.json")["argv"] if isinstance(arg, str) and arg.startswith("tests/") and arg.endswith(".py")]
assert producer_files == test_files and all(path in inputs for path in test_files)
prior_xmls = [ART / "regression-04.xml", ART / "regression-05.xml"]
assert sum(cases(prior_xmls[-1]).values()) == 852
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
assert sha(native) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
references = {str(path): sha(path) for path in [Path(__file__), producer_path, effective_path, native, BRANCH / "DELIVERY.md", *[ART / path for path in producer["artifact_sha256"]], *prior_xmls]}

def snapshot():
    result = {path: sha(BRANCH / path) for path in inputs}
    result.update({path.relative_to(BRANCH).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (BRANCH / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"})
    return result

def configurations():
    return {path.relative_to(BRANCH).as_posix(): sha(path) for name in ("conftest.py", "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml") for path in BRANCH.rglob(name) if path.is_file()}

before = snapshot()
assert not set(before) - set(inputs)
configs_before = configurations()
assert all(path in inputs and inputs[path] == digest for path, digest in configs_before.items())
OUT = ROOT / "artifacts/coordinator-astra-consumers-r28-20261017"
OUT.mkdir(exist_ok=False)
launcher = Path(__file__).read_bytes()
(OUT / "launcher.py").write_bytes(launcher)
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = str(native)
commands = [
    [sys.executable, "-m", "pytest", "-q", f"--rootdir={BRANCH}", f"--confcutdir={BRANCH}", *test_files, f"--junitxml={OUT / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "black", "--check", *[path for path in owned if path.endswith(".py")]],
]
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=BRANCH, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(command=command, returncode=result.returncode, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=index, returncode=result.returncode)), flush=True)
junit_path = OUT / "results.xml"
suites = ET.parse(junit_path).getroot().findall("testsuite") if junit_path.is_file() else []
counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
current_cases = cases(junit_path) if junit_path.is_file() else Counter()
counter_checks = [dict(path=path.relative_to(ROOT).as_posix(), missing=[list(key) + [count] for key, count in (cases(path) - current_cases).items()]) for path in prior_xmls]
source_stable = before == snapshot() and configs_before == configurations()
root_stable = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
reference_stable = all(sha(Path(path)) == digest for path, digest in references.items()) and launcher == Path(__file__).read_bytes() == (OUT / "launcher.py").read_bytes()
passed = all(row["returncode"] == 0 for row in results) and counts == dict(tests=852, failures=0, errors=0, skipped=0) and not any(check["missing"] for check in counter_checks) and source_stable and root_stable and reference_stable
proof = dict(actual_task="/root", actual_producer_task="/root/astra_design_contract_r23", logical_task="ASTRA-INSTANCE-CONSUMERS-R25", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, test_files=test_files, junit=counts, prior_case_counter_checks=counter_checks, source_before=before, sources_unchanged=source_stable, root_unchanged=root_stable, references_sha256=references, references_unchanged=reference_stable, runtime_preflight=runtime, candidate_independent_execution_checks_passed=passed, independent_acceptance=False, source_review_required=True, integrated=False, root_joint_verification=False, whole_packages_complete=False, scope="Frozen consumer-only candidate using controlled semantics and existing real native regressions; no authority for current S01 factory, full native instance scan, complete S08, Root intake or joint regression.")
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), junit=counts, passed=passed)), flush=True)
sys.exit(0 if passed else 1)
