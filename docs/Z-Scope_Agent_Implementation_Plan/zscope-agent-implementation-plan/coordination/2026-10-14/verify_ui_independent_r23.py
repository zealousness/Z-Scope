"""Independent frozen UI/projection acceptance with the original collection retained."""
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

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
prepared = json.loads((ROOT / "artifacts/coordinator-recovery-r23-20261016/prepared.json").read_text(encoding="utf-8"))
branch = ROOT / prepared["coordinator_workspace"]
out = ROOT / "artifacts/coordinator-ui-r23-independent-20261016"
runtime = inspect_root_runtime()
out.mkdir(exist_ok=False)
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
(out / "runtime-preflight.json").write_text(json.dumps(runtime, indent=2) + "\n", encoding="utf-8", newline="\n")
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def hashes():
    return {r["path"]: sha(branch / r["path"]) for r in prepared["files"]}
before = hashes()
assert before == {r["path"]: r["sha256"] for r in prepared["files"]}
root_source = json.loads((ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(sha(ROOT / p) == h for p, h in root_source.items())
producer = ROOT / ".coordination/20261014/workspaces/astra-stop-coverage-ux-r21"
producer_review = json.loads((producer / "artifacts/stop-coverage-ux-r21/review.json").read_text(encoding="utf-8"))
producer_tests = [p for p in producer_review["commands"][0]["command"] if p.startswith("tests/") and p.endswith(".py")]
assert len(producer_tests) == 13
tests = list(dict.fromkeys(producer_tests + ["tests/test_agent_docs.py", "tests/test_web_dashboard_server.py", "tests/test_scan_jobs_http_api.py", "tests/test_config_stop_at_consumers.py", "tests/test_job_cli_stop_window.py", "tests/test_portable_release.py", "tests/test_portable_runtime.py"]))
env = os.environ.copy()
assert not env.get("PYTEST_ADDOPTS") and not env.get("PYTHONOPTIMIZE")
env.update(PYTHONPATH=str(branch), Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer", ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright", ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome", ZSCOPE_UI_MULTI_TARGET_EDITING="1")
for key, subdir in (("ZSCOPE_UI_EVIDENCE", "workbench"), ("ZSCOPE_UI_CONFIG_EVIDENCE", "config"), ("ZSCOPE_UI_JOB_EVIDENCE", "owner"), ("ZSCOPE_INSTANCE_EVIDENCE", "native-browser"), ("ZSCOPE_UX_BOUNDARY_EVIDENCE", "boundaries")):
    env[key] = str(out / subdir)
commands = [
    [sys.executable, "-m", "pytest", "-q", *tests, f"--junitxml={out / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "black", "--check", "zscope/reporting/acceptance.py", "tests/test_coverage_gap_provenance.py", "tests/test_agent_integration_boundaries.py", "tests/test_agent_workbench_ui.py", "tests/test_instance_coverage_ui.py", "tests/test_ux_capability_boundaries_ui.py"],
]
commands += [["node", "--check", p] for p in ("zscope/web/static/dashboard_workbench.js", "tests/fixtures/agent_workbench_ui.cjs", "tests/fixtures/instance_coverage_ui.cjs", "tests/fixtures/ux_capability_boundaries_ui.cjs")]
commands.append([sys.executable, "scripts/portable/web_assets.py"])
native_before = sha(Path(env["Z_SCOPE_TEST_CLANG_INDEXER"]))
results = []
for i, command in enumerate(commands):
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    log = out / f"command-{i}.log"
    with log.open("w", encoding="utf-8") as stream:
        result = subprocess.run([sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", *command], cwd=branch, env=env, stdout=stream, stderr=subprocess.STDOUT)
    results.append({"command": command, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "log": log.relative_to(ROOT).as_posix()})
    print(json.dumps({"command_index": i, "returncode": result.returncode}), flush=True)
after = hashes()
root_unchanged = all(sha(ROOT / p) == h for p, h in root_source.items())
producer_unchanged = all(sha(producer / p) == h for p, h in prepared["producer_hashes"].items())
native_after = sha(Path(env["Z_SCOPE_TEST_CLANG_INDEXER"]))
suites = ET.parse(out / "results.xml").getroot().findall("testsuite")
junit = {k: sum(int(s.get(k, "0")) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
def cases(p):
    return Counter((c.get("classname"), c.get("name")) for c in ET.parse(p).getroot().iter("testcase"))
prior_cases = cases(producer / "artifacts/stop-coverage-ux-r21/self/final-01/pytest.xml")
current_cases = cases(out / "results.xml")
all_prior_cases_preserved = prior_cases <= current_cases
passed = all(r["returncode"] == 0 for r in results) and all(junit[k] == 0 for k in ("failures", "errors", "skipped")) and all_prior_cases_preserved and before == after and root_unchanged and producer_unchanged and native_before == native_after
proof = {"logical_task": "ASTRA-STOP-COVERAGE-UX-R21", "actual_producer_task": "/root/astra_instance_ui_r18", "finished_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "junit": junit, "commands": results, "all_13_producer_test_files_and_junit_identities_preserved": all_prior_cases_preserved, "test_file_count": len(tests), "before": before, "after": after, "source_unchanged": before == after, "producer_frozen_outputs_unchanged": producer_unchanged, "root_unchanged": root_unchanged, "native_before": native_before, "native_after": native_after, "runtime_preflight": runtime, "pytest_capture": "fd (unchanged default)", "test_slot_wrappers": 1, "independent_acceptance_passed": passed, "resource_lock_verified": results[-1]["returncode"] == 0, "integrated": False, "root_joint_verification": False, "whole_packages_complete": False, "scope": "Frozen UI and coordinator projection with actual native fixture/HTTP/owner/browser; synthetic reports remain controlled; no actual LLM/real-project accuracy/formal/portable acceptance"}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"finished_at": proof["finished_at"], "junit": junit, "independent_acceptance_passed": passed, "all_commands": len(results), "root_unchanged": root_unchanged}), flush=True)
sys.exit(0 if passed else 1)
