"""Migrate the UI test to the actual owner-authoritative per-attempt queue receipt."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = json.loads((ROOT / "artifacts/coordinator-r18-ui-doc-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
branch = ROOT / ".coordination/20261014/workspaces/coordinator-ui-queue-r19"
branch.mkdir(exist_ok=False)
for p, h in source["after"].items():
    target = branch / p
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((ROOT / p).read_bytes())
    assert hashlib.sha256(target.read_bytes()).hexdigest() == h
name = "tests/test_instance_coverage_ui.py"
target = branch / name
old = target.read_text(encoding="utf-8")
needle = '''        queues = list(project.rglob("work-queue.db"))
        assert queues
        with sqlite3.connect(queues[0]) as connection:'''
assert old.count(needle) == 1
replacement = '''        # Use the same actual scheduler receipt as the owner. The current
        # queue is a per-attempt nonce file; neither globbing a legacy filename
        # nor trusting a report-supplied queue path proves this run's work.
        envelope = json.loads((output / "http-result.json").read_text(encoding="utf-8"))
        binding = envelope["binding"]
        job = engine.detail(binding["job_id"]).payload["job"]
        assert job["run_id"] == binding["run_id"]
        assert job["input_revision"] == binding["input_revision"]
        assert job["report"]["report_id"] == binding["report_id"]
        store = engine._locate_store()
        receipt = store.latest_event(
            job["job_id"], run_id=job["run_id"], kind="session_scheduler_started"
        )
        assert receipt is not None
        assert receipt["data"]["input_revision"] == job["input_revision"]
        queue = Path(receipt["data"]["work_queue"])
        run_dir = (store.db_path.parent / job["job_id"] / job["run_id"]).resolve()
        assert queue.is_absolute() and queue.resolve().parent == run_dir
        assert Path(binding["report_path"]).resolve().parent == run_dir
        assert queue.name.startswith("work-queue.db.") and queue.is_file()
        with sqlite3.connect(queue.resolve().as_uri() + "?mode=ro", uri=True) as connection:'''
target.write_text(old.replace(needle, replacement), encoding="utf-8", newline="\n")
out = ROOT / "artifacts/coordinator-ui-queue-receipt-r19-migration-20261015"
out.mkdir(exist_ok=False)
(out / "original-test.py").write_text(old, encoding="utf-8", newline="\n")
def call(argv):
    return [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", sys.executable, *argv]
subprocess.run(call(["-m", "black", name]), check=True)
names = set(source["after"])
def hashes():
    return {p: hashlib.sha256((branch / p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
assert [p for p in before if before[p] != source["after"][p]] == [name]
env = dict(os.environ, Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer", ZSCOPE_UI_MULTI_TARGET_EDITING="1", ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright", ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome", ZSCOPE_INSTANCE_EVIDENCE=str(out / "native-browser"), ZSCOPE_UI_EVIDENCE=str(out / "browser"), ZSCOPE_UI_CONFIG_EVIDENCE=str(out / "config"))
native_before = hashlib.sha256(Path(env["Z_SCOPE_TEST_CLANG_INDEXER"]).read_bytes()).hexdigest()
assert native_before == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
tests = ["test_instance_coverage_ui", "test_job_result_http_binding", "test_job_result_projection", "test_scan_session_jobs", "test_scan_checkpoint_resume", "test_job_session_scheduler", "test_scan_job_work_queue"]
commands = [["-m", "pytest", "-q", *["tests/" + p + ".py" for p in tests], "--junitxml=" + str(out / "results.xml")], ["-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"], ["-m", "mypy", "zscope"], ["-m", "black", "--check", name]]
results = []
for i, argv in enumerate(commands):
    at = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / f"command-{i}.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(call(argv), env=env, stdout=log, stderr=subprocess.STDOUT)
    row = {"argv": argv, "returncode": result.returncode, "started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    results.append(row)
    print(json.dumps(row), flush=True)
    if result.returncode:
        break
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
native_after = hashlib.sha256(Path(env["Z_SCOPE_TEST_CLANG_INDEXER"]).read_bytes()).hexdigest()
passed = len(results) == 4 and all(r["returncode"] == 0 for r in results) and before == after and native_before == native_after and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped"))
receipt = {"finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "coordinator_validation_passed": passed, "source_unchanged": before == after, "path": name, "before_sha256": source["after"][name], "after_sha256": after[name], "before_all_inputs": before, "after_all_inputs": after, "commands": results, "junit": dict(suite.attrib), "native_before": native_before, "native_after": native_after, "root_changed": False, "scope": "Only migrate the test queue locator to the real scoped scheduler SQL receipt; original real native/browser and two completed instance assertions retained, with stronger job/run/input/path/readonly checks. No product change or real-project/model/full-package acceptance."}
(out / "review.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert passed
