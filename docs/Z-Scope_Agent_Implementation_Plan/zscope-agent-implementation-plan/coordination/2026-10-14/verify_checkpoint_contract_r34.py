"""Execute all ten unchanged checkpoint case identities after an AST-only format."""
from collections import Counter
from pathlib import Path
import ast
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
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-checkpoint-contract-r34"
BASE = ROOT / "artifacts/coordinator-checkpoint-contract-r34-20261017"
OUT = BASE / "independent"
TARGET = "tests/test_scan_checkpoint_resume.py"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def snapshot():
    return {p.relative_to(WORK).as_posix(): sha(p) for p in WORK.rglob("*") if p.is_file() and p.relative_to(WORK).parts[0] != "artifacts" and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


def configs():
    return {p.relative_to(WORK).as_posix(): sha(p) for name in ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml") for p in WORK.rglob(name) if p.is_file()}


def cases(p):
    return Counter((n.get("classname", ""), n.get("name", "")) for n in ET.parse(p).getroot().iter("testcase"))


def host_inputs():
    tool = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
    assert sha(tool) == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
    linked = subprocess.run(["ldd", str(tool)], capture_output=True, text=True, timeout=10)
    assert linked.returncode == 0 and "not found" not in linked.stdout + linked.stderr
    libraries = {Path(v) for v in re.findall(r"/[^\s()]+", linked.stdout)}
    assert libraries and all(p.is_file() for p in libraries)
    headers = {Path("/usr/include/stdlib.h"), Path("/usr/include/features.h")}
    files = {str(p): dict(sha256=sha(p), physical=str(p.resolve(strict=True))) for p in libraries | headers | {tool}}
    installation = {}
    for header in headers:
        for p in (header, *header.parents):
            stat = p.lstat()
            installation[str(p)] = dict(uid=stat.st_uid, mode=stat.st_mode, physical=str(p.resolve(strict=True)))
    return dict(files=files, standard_installation=installation)


if sys.platform != "linux" or sys.flags.optimize or Path.cwd().resolve() != WORK:
    raise RuntimeError("Linux, unoptimized Python and the fixed workspace are required")
if any(os.environ.get(k) for k in ("PYTHONOPTIMIZE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
    raise RuntimeError("External test options/plugins and optimization are forbidden")
prep = read(BASE / "preparation.json")
before = snapshot()
assert len(before) == 1082 and before == prep["complete_inputs"]
config_before = configs()
assert config_before == {"pyproject.toml": before["pyproject.toml"]}
root_inputs = prep["root_inputs"]
assert len(root_inputs) == 1065 and all(sha(ROOT / p) == v for p, v in root_inputs.items())
prior_xml = ROOT / "artifacts/coordinator-stage-joint-r32-20261017/results.xml"
expected = Counter({k: v for k, v in cases(prior_xml).items() if k[0] == "tests.test_scan_checkpoint_resume"})
assert sum(expected.values()) == len(expected) == 10
refs = dict(prep["reference_sha256"])
for p in (Path(__file__), HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", BASE / "preparation.json"):
    key, digest = str(p), sha(p)
    if key in refs and refs[key] != digest:
        raise RuntimeError("A frozen reference changed: " + key)
    refs[key] = digest
assert all(sha(Path(p)) == v for p, v in refs.items())
runtime, host_before = inspect_root_runtime(require_slot=True), host_inputs()
OUT.mkdir(exist_ok=False)
write(OUT / "preflight.json", dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), complete_inputs=before, configurations=config_before, references_sha256=refs, prior_counter=[list(k) + [v] for k, v in sorted(expected.items())], runtime=runtime, host_inputs=host_before, default_fd_capture=True, test_slot_wrappers=1, stage_intake=False, root_intake=False))
raw_ast = ast.dump(ast.parse((WORK / TARGET).read_text(encoding="utf-8")))
with (OUT / "black-format.log").open("w", encoding="utf-8") as stream:
    formatting = subprocess.run([sys.executable, "-m", "black", TARGET], cwd=WORK, stdout=stream, stderr=subprocess.STDOUT)
assert formatting.returncode == 0
assert ast.dump(ast.parse((WORK / TARGET).read_text(encoding="utf-8"))) == raw_ast
formatted = before | {TARGET: sha(WORK / TARGET)}
assert snapshot() == formatted
write(BASE / "formatted-input-freeze.json", dict(complete_inputs=formatted, raw_candidate_sha256=before[TARGET], formatted_test_sha256=formatted[TARGET], entire_candidate_AST_identical=True, only_target_formatting_changed=True))
formatted_freeze = BASE / "formatted-input-freeze.json"
refs[str(formatted_freeze)] = sha(formatted_freeze)
write(OUT / "post-format-preflight.json", dict(complete_inputs=formatted, references_sha256=refs, formatted_input_freeze_sha256=refs[str(formatted_freeze)], formatted_test_sha256=formatted[TARGET]))
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
commands = [[sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", TARGET, f"--junitxml={OUT / 'results.xml'}"], [sys.executable, "-m", "black", "--check", TARGET]]
results = []
for i, command in enumerate(commands):
    with (OUT / f"command-{i}.log").open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=WORK, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append(dict(argv=command, returncode=result.returncode, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()))
    print(json.dumps(dict(command_index=i, returncode=result.returncode)), flush=True)
tree = ET.parse(OUT / "results.xml").getroot()
counts = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
gates = dict(complete1082_unchanged_after_format=snapshot() == formatted, configs_unchanged=configs() == config_before, root1065_unchanged=all(sha(ROOT / p) == v for p, v in root_inputs.items()), references_unchanged=all(sha(Path(p)) == v for p, v in refs.items()), host_inputs_unchanged=host_inputs() == host_before, original10_case_counter_exact=cases(OUT / "results.xml") == expected, formatting_entire_AST_identical=True)
passed = all(gates.values()) and all(r["returncode"] == 0 for r in results) and counts == dict(tests=10, failures=0, errors=0, skipped=0)
write(OUT / "review.json", dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), commands=results, junit=counts, gates=gates, formatted_input_freeze_sha256=refs[str(formatted_freeze)], formatted_test_sha256=formatted[TARGET], references_sha256=refs, bounded_checkpoint_contract_test_independent_passed=passed, full_product_quality_not_repeated_for_test_only_change=True, stage_intake=False, root_intake=False, whole_package_complete=False))
print(json.dumps(dict(passed=passed, junit=counts, gates=gates)))
raise SystemExit(0 if passed else 1)
