"""Run the full frozen R22 collection plus all accepted R23 additions."""
from pathlib import Path
import copy
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from root_runtime_preflight_r23 import inspect_root_runtime

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
assert sys.argv[1:] == ["coordinator-r23-ui-projection-union-20261016"]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

prior_dir = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016"
prior = read(prior_dir / "source-evidence.json")
assert len(prior["commands"]) == 6 and all(r["returncode"] == 0 for r in prior["commands"])
assert read(prior_dir / "review.json")["passed"] == 2539
intake_path = ROOT / "artifacts/intake-ui-projection-r23-20261016/receipt.json"
intake = read(intake_path)
assert intake["independent_acceptance_passed"] and intake["resource_lock_verified"]
assert len(intake["files"]) == 11
expected = dict(prior["after"])
for row in intake["files"]:
    assert expected.get(row["path"]) == row["before"]
    expected[row["path"]] = row["after"]
assert expected == intake["expected_root"] and len(expected) == 1059
assert all(sha(ROOT / p) == h for p, h in expected.items()), "Unreviewed Root drift"
for key in ("ui_review", "projection_review"):
    assert sha(ROOT / intake[key]) == intake[key + "_sha256"]
commands = copy.deepcopy([r["command"] for r in prior["commands"]])
old_tests = [p for p in commands[0] if p.endswith(".py")]
assert len(old_tests) == 169 and len(set(old_tests)) == 169
additions = ["tests/test_coverage_gap_provenance.py", "tests/test_ux_capability_boundaries_ui.py"]
assert not set(additions) & set(old_tests)
tests = old_tests + additions
assert len(tests) == 171
OUT = ROOT / "artifacts" / sys.argv[1]
runtime = inspect_root_runtime(require_slot=True)
OUT.mkdir(exist_ok=False)
write(OUT / "runtime-preflight.json", runtime)
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
helpers = {str((HERE / name).relative_to(ROOT)) for name in (
    "intake_ui_r23.py", "verify_current_root_r23.py", "verify_joint_with_clock_r23.py",
    "root_runtime_preflight_r23.py", "publish_joint_r23.py", "publish_current_root_checked_r23.py",
)}
paths = sorted(set(expected) | helpers)

def capture():
    return {p: sha(ROOT / p) for p in paths}

before = capture()
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_before = sha(native)
assert native_before == runtime["native_sha256"]
env = os.environ.copy()
assert not env.get("PYTEST_ADDOPTS") and not env.get("PYTHONOPTIMIZE")
temporary = tempfile.mkdtemp(prefix="zscope-root-r23-", dir="/tmp")
env.update(PYTHONPATH=str(ROOT), TMPDIR=temporary, TMP=temporary, TEMP=temporary,
    Z_SCOPE_TEST_CLANG_INDEXER=str(native),
    ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright",
    ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
    ZSCOPE_UI_MULTI_TARGET_EDITING="1")
for key, directory in (("ZSCOPE_UI_EVIDENCE", "browser"), ("ZSCOPE_UI_CONFIG_EVIDENCE", "config"), ("ZSCOPE_UI_JOB_EVIDENCE", "owner"), ("ZSCOPE_INSTANCE_EVIDENCE", "native-browser"), ("ZSCOPE_UX_BOUNDARY_EVIDENCE", "boundaries")):
    env[key] = str(OUT / directory)
commands[0] = [sys.executable, "-m", "pytest", "-q", *tests, f"--junitxml={OUT / 'results.xml'}"]
assert commands[1][1:] == ["-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"]
assert commands[2][1:] == ["-m", "mypy", "zscope"]
assert commands[3][1:] == ["-m", "mypy", "scripts/agent_plan_evaluation.py"]
assert commands[4][1:4] == ["-m", "black", "--check"]
assert commands[5][1:] == ["scripts/portable/web_assets.py"]
commands[4] += additions
for command in commands:
    command[0] = sys.executable
results = []
for i, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    log = OUT / f"command-{i}.log"
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append({"command": command, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "log": log.relative_to(ROOT).as_posix()})
    print(json.dumps({"command_index": i, "returncode": result.returncode}), flush=True)
after = capture()
proof = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "before": before, "after": after,
    "direct_source_unchanged": before == after, "commands": results, "test_file_count": len(tests),
    "r22_ordered_collection_preserved": tests[:169] == old_tests, "new_test_files": additions,
    "native_before": native_before, "native_after": sha(native), "launcher_before": before[str(Path(__file__).relative_to(ROOT))], "launcher_after": sha(Path(__file__)),
    "pytest_capture": "fd (unchanged default)", "test_slot_wrappers": 1, "test_slot": runtime["coordinator_test_slot"], "temporary_directory": temporary,
    "runtime_preflight": runtime, "intake_receipt": intake_path.relative_to(ROOT).as_posix(), "intake_sha256": sha(intake_path),
    "r22_source_sha256": sha(prior_dir / "source-evidence.json"),
    "parallel_timing_assertion_unchanged": after["tests/test_subagents_parallel.py"] == "1a7e5a43ce8ae095a9e802e16f307a9f0640c7b61ba5c4c68c439bee36c48699",
    "whole_packages_complete": False, "full_repository_suite_run": False,
    "scope": "Complete prior R22 selected union plus accepted UI/provenance additions. Actual native fixture/owner/SQLite/HTTP/browser retained; controlled scanners/reports/model responses do not establish real-project effect, formal benchmark or portable smoke. No counts added to independent receipts."}
write(OUT / "source-evidence.json", proof)
stable = before == after and native_before == proof["native_after"] and proof["launcher_before"] == proof["launcher_after"]
sys.exit(0 if stable and all(r["returncode"] == 0 for r in results) else 1)
