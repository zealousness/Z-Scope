"""Independent frozen consumer repair validation; no Stage or Root intake."""
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

if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("Non-optimized Linux required")
if os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
    raise RuntimeError("Test environment overrides forbidden")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29"
OUT = ROOT / "artifacts/coordinator-consumer-repair-r29-20261017"
if Path.cwd().resolve() != BRANCH.resolve():
    raise RuntimeError("Wrong single outer slot workspace")
runtime = inspect_root_runtime(require_slot=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


manifest_path = HERE / "followups-r12/consumer-exact-repair-r29-ownership.json"
manifest = read(manifest_path)
freeze_path = ROOT / "artifacts/consumer-repair-coordinator-inputs-r29-20261017/frozen-inputs.json"
freeze = read(freeze_path)
assert freeze["actual_producer_task"] == "/root/consumer_exact_repair_r29" and freeze["producer_frozen"]
inputs = freeze["source_after"]
assert set(inputs) == set(manifest["source_baseline"]) and len(inputs) == 1071
owned = set(manifest["owned_paths"])
readonly = set(manifest["readonly_paths"])
assert owned == {
    "zscope/core/candidates/cpp_domains/typed_resources.py",
    "zscope/core/candidates/cpp_domains/protocol_ownership_logic.py",
    "tests/test_instance_builtin_consumers.py",
}
assert len(owned) == 3 and len(readonly) == 1068
assert not owned & readonly and owned | readonly == set(inputs)
assert all(inputs[path] == digest for path, digest in manifest["readonly_paths"].items())
assert all(sha(BRANCH / path) == digest for path, digest in inputs.items())
original_root = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
assert all(sha(original_root / path) == digest for path, digest in manifest["source_baseline"].items())
failure_path = ROOT / manifest["frozen_failure_receipt"]
assert sha(failure_path) == manifest["frozen_failure_sha256"]
failure = read(failure_path)
history_path = ROOT / freeze["failure_history_receipt"]
assert history_path == failure_path.parent / "history-preservation.json"
assert sha(history_path) == freeze["failure_history_sha256"]
history = read(history_path)
assert history["parent_failure_receipt_sha256"] == sha(failure_path)
assert history["all129_producer_artifacts_copied"] and len(history["copied_files"]) == 129
original_art = original_root / "artifacts/instance-consumers-r25"


def history_current():
    actual = {path.relative_to(original_art).as_posix(): sha(path) for path in original_art.rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}
    return (
        actual == history["copied_files"]
        and all(sha(failure_path.parent / "complete-producer-history" / path) == digest for path, digest in history["copied_files"].items())
        and all(sha(failure_path.parent / path) == digest for path, digest in failure["frozen_files"].items())
    )


assert history_current()
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
probe = ROOT / manifest["immutable_probe"]
assert sha(probe) == manifest["immutable_probe_sha256"]
original_xml = ROOT / "artifacts/coordinator-astra-consumers-r28-20261017/results.xml"
probe_xml = ROOT / "artifacts/coordinator-consumer-boundary-probes-r28-20261017/results.xml"
producer_xml = ROOT / freeze["producer_final_xml"]
old_cases = cases(original_xml)
external_cases = cases(probe_xml)
producer_cases = cases(producer_xml)
assert sum(old_cases.values()) == 852 and sum(external_cases.values()) == 3
assert not (old_cases + external_cases - producer_cases)
assert sum(producer_cases.values()) > 855, "Meaningful owned regressions must accompany the repair"
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
assert len(test_files) == 26 and all(path in inputs for path in test_files)
old_producer_review_path = original_art / "review.json"
old_producer_review = read(old_producer_review_path)
black_files = [path for path in old_producer_review["ownership"]["owned_paths"] if path.endswith(".py")]
assert len(black_files) == 10 and set(manifest["owned_paths"]) <= set(black_files)
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
assert sha(native) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
reference_paths = [Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", manifest_path, freeze_path, failure_path, history_path, old_producer_review_path, original_xml, probe_xml, producer_xml, native, probe, *[ROOT / path for path in freeze["producer_artifacts_sha256"]]]
references = {str(path): sha(path) for path in reference_paths}
assert all(sha(ROOT / path) == digest for path, digest in freeze["producer_artifacts_sha256"].items())


def snapshot():
    result = {path: sha(BRANCH / path) for path in inputs}
    result.update({path.relative_to(BRANCH).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (BRANCH / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"})
    return result


def configurations():
    return {path.relative_to(BRANCH).as_posix(): sha(path) for name in ("conftest.py", "pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml") for path in BRANCH.rglob(name) if path.is_file()}


before = snapshot()
assert before == inputs
configs_before = configurations()
assert all(inputs.get(path) == digest for path, digest in configs_before.items())
OUT.mkdir(exist_ok=False)
launcher = Path(__file__).read_bytes()
(OUT / "launcher.py").write_bytes(launcher)
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = str(native)
commands = [
    [sys.executable, "-m", "pytest", "-q", f"--rootdir={BRANCH}", f"--confcutdir={BRANCH}", *test_files, str(probe), f"--junitxml={OUT / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "black", "--check", *black_files],
]
results = []
for index, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=BRANCH, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, returncode=result.returncode, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=index, returncode=result.returncode)), flush=True)
xml_path = OUT / "results.xml"
suites = ET.parse(xml_path).getroot().findall("testsuite") if xml_path.is_file() else []
counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
current_cases = cases(xml_path) if xml_path.is_file() else Counter()
source_stable = before == snapshot() and configs_before == configurations()
root_stable = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
original_stable = all(sha(original_root / path) == digest for path, digest in manifest["source_baseline"].items())
history_stable = history_current()
reference_stable = all(sha(Path(path)) == digest for path, digest in references.items()) and launcher == Path(__file__).read_bytes() == (OUT / "launcher.py").read_bytes()
counter_exact = current_cases == producer_cases
passed = all(row["returncode"] == 0 for row in results) and counts == dict(tests=sum(producer_cases.values()), failures=0, errors=0, skipped=0) and counter_exact and source_stable and root_stable and original_stable and history_stable and reference_stable
proof = dict(actual_task="/root", actual_producer_task="/root/consumer_exact_repair_r29", logical_task="CONSUMER-EXACT-REPAIR-R29", parent_logical_task="ASTRA-INSTANCE-CONSUMERS-R25", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, prior852_and_external3_preserved=not bool(old_cases + external_cases - current_cases), producer_full_case_counter_exact=counter_exact, missing_cases=[list(key) + [count] for key, count in (producer_cases - current_cases).items()], extra_cases=[list(key) + [count] for key, count in (current_cases - producer_cases).items()], source_before=before, sources_unchanged=source_stable, root_unchanged=root_stable, original_failed_candidate_unchanged=original_stable, original129_history_and_failure_freeze_unchanged=history_stable, references_sha256=references, references_unchanged=reference_stable, runtime_preflight=runtime, independent_execution_checks_passed=passed, source_review_required=True, independent_acceptance=False, integrated=False, root_joint_verification=False, whole_packages_complete=False, scope="Frozen non-UI consumer repair only; controlled public probes and existing native regressions do not accept current S01 factory/full native instance scan/PRE/current Validator, completeS08 or real-project effects.")
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), junit=counts, passed=passed)), flush=True)
sys.exit(0 if passed else 1)
