"""Independently validate the frozen repair combination and complete quality gates."""
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
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-shared-style-r34"
BASE = ROOT / "artifacts/coordinator-shared-style-r34-20261017"
OUT = BASE / "independent"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
CONFIG_NAMES = {"conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml"}


def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot():
    return {p.relative_to(WORK).as_posix():sha(p) for p in WORK.rglob("*") if p.is_file() and p.relative_to(WORK).parts[0] != "artifacts" and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


def configs():
    return {p.relative_to(WORK).as_posix():sha(p) for name in CONFIG_NAMES for p in WORK.rglob(name) if p.is_file()}


def cases(p):
    return Counter((n.get("classname", ""), n.get("name", "")) for n in ET.parse(p).getroot().iter("testcase"))


def host_inputs():
    tool = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
    assert sha(tool) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
    linked = subprocess.run(["ldd", str(tool)], capture_output=True, text=True, timeout=10)
    assert linked.returncode == 0 and "not found" not in linked.stdout + linked.stderr
    libraries = {Path(v) for v in re.findall(r"/[^\s()]+", linked.stdout)}
    assert libraries and all(p.is_file() for p in libraries)
    files = {str(p):dict(sha256=sha(p), physical=str(p.resolve(strict=True))) for p in libraries | {tool, Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")}}
    installation = {}
    for header in (Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")):
        for p in (header, *header.parents):
            stat = p.lstat()
            installation[str(p)] = dict(uid=stat.st_uid, mode=stat.st_mode, physical=str(p.resolve(strict=True)))
    return dict(files=files, standard_installation=installation)


if sys.platform != "linux" or sys.flags.optimize or Path.cwd().resolve() != WORK:
    raise RuntimeError("Linux, unoptimized Python and the fixed workspace are required")
if any(os.environ.get(k) for k in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONOPTIMIZE")):
    raise RuntimeError("External test plugins/options and optimization are forbidden")
prep, frozen = read(BASE / "preparation.json"), read(BASE / "input-freeze.json")
assert frozen["original_preparation_sha256"] == sha(BASE / "preparation.json")
assert frozen["entire_AST_identical"] and frozen["all_other_1080_inputs_unchanged"]
before = snapshot()
assert len(before) == 1082 and before == frozen["complete_inputs"]
config_before = configs()
assert config_before == {"pyproject.toml":before["pyproject.toml"]}
root_inputs = prep["root_inputs"]
assert len(root_inputs) == 1065 and all(sha(ROOT / p) == digest for p,digest in root_inputs.items())
runtime, host_before = inspect_root_runtime(require_slot=True), host_inputs()
context = ROOT / ".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33/own-20261017T034756.798542Z"
cost = ROOT / ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/green-usage"
revision = ROOT / "artifacts/coordinator-review-revision-repair-r33-20261017/green"
classifier = ROOT / "artifacts/coordinator-native-composite-r33-20261017"
session = ROOT / "artifacts/coordinator-session-cost-r33-20261017/green2"
prior_paths = dict(session=session / "results.xml", context=context / "pytest.xml", cost=cost / "pytest.xml", revision=revision / "results.xml", classifier=classifier / "classifier.xml")
prior = {name:cases(p) for name,p in prior_paths.items()}
assert {name:sum(c.values()) for name,c in prior.items()} == dict(session=2, context=50, cost=16, revision=33, classifier=49)
expected = sum(prior.values(), Counter())
assert sum(expected.values()) == len(expected) == 150
references = [Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", BASE / "preparation.json", BASE / "input-freeze.json", session / "review.json", context / "receipt.json", cost / "receipt.json", revision / "review.json", classifier / "review.json", *prior_paths.values(), ROOT / "artifacts/coordinator-policy-expectation-r33-20261017/candidate.json"]
refs = dict(prep["source_review_sha256"])
assert all(sha(Path(p)) == digest for p,digest in refs.items())
for p in references:
    name, digest = str(p), sha(p)
    if name in refs and refs[name] != digest:
        raise RuntimeError("Frozen reference differs from the current input: " + name)
    refs[name] = digest
assert all(sha(Path(p)) == digest for p,digest in refs.items())
tests = ["tests/test_session_preentry_cost_r33.py", "tests/test_instance_currentness_revocation_r33.py", "tests/test_instance_recovery_cost_r33.py", "tests/test_review_current_revisions_r33.py", "tests/test_native_classifier_currentness_r33.py"]
black = [*tests, "zscope/orchestration/scan_session.py", "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12/test_scan_checkpoint_dependency_boundary.py", "zscope/orchestration/instance_semantics_context.py", "zscope/orchestration/parallel_analyzer.py", "zscope/core/analysis/analyzer.py", "tests/test_instance_semantics_integration.py", "tests/test_instance_analysis.py"]
commands = [
    [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", *tests, f"--junitxml={OUT / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "mypy", "--no-incremental", "zscope"],
    [sys.executable, "-m", "mypy", "scripts/agent_plan_evaluation.py"],
    [sys.executable, "-m", "black", "--check", *black],
    [sys.executable, "scripts/portable/web_assets.py"],
]
OUT.mkdir(exist_ok=False)
write(OUT / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), complete_inputs=before, configurations=config_before, references_sha256=refs, prior_counters={name:[list(key)+[v] for key,v in sorted(c.items())] for name,c in prior.items()}, runtime=runtime, host_inputs_before=host_before, stage_intake=False, root_intake=False, Session_Wiki_handoff_in_this_combination=True))
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
results = []
for i, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    with (OUT / f"command-{i}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, returncode=result.returncode, started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=i, returncode=result.returncode)), flush=True)
tree = ET.parse(OUT / "results.xml").getroot()
counts = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
gates = dict(complete1082_unchanged=snapshot()==before, configurations_unchanged=configs()==config_before, root1065_unchanged=all(sha(ROOT/p)==digest for p,digest in root_inputs.items()), references_unchanged=all(sha(Path(p))==digest for p,digest in refs.items()), host_inputs_unchanged=host_inputs()==host_before, all_five_prior_counters_exact=cases(OUT/"results.xml")==expected)
passed = all(gates.values()) and all(r["returncode"]==0 for r in results) and counts==dict(tests=150, failures=0, errors=0, skipped=0)
write(OUT / "review.json", dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, gates=gates, bounded_combined_repair_independent_and_full_quality_passed=passed, stage_intake=False, root_intake=False, whole_package_complete=False))
print(json.dumps(dict(passed=passed, junit=counts, gates=gates)))
raise SystemExit(0 if passed else 1)
