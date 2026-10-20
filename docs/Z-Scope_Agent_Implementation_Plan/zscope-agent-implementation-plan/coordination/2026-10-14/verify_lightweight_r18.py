"""Validate the coordinator-owned additive projection before UI dependency refresh."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
workspace = ROOT / ".coordination/20261014/workspaces/coordinator-lightweight-r18"
out = ROOT / "artifacts/coordinator-lightweight-r18-20261015"
out.mkdir(exist_ok=False)
owned = ["zscope/web/services.py", "tests/test_lightweight_instance_metadata.py"]
def call(argv):
    return [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, *argv]
subprocess.run(call(["-m", "black", *owned]), check=True)
baseline = json.loads((HERE / "followups-r12/coordinator-lightweight-r18-baseline.json").read_text(encoding="utf-8"))["before"]
names = set(baseline) | set(owned)
def hashes():
    return {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
assert all(before[p] == sha for p, sha in baseline.items() if p not in owned)
tests = ["test_lightweight_instance_metadata", "test_job_result_projection", "test_job_result_http_binding", "test_scan_jobs_http_api", "test_mcp_jobs", "test_report_views", "test_frozen_report_reader"]
commands = [["-m", "pytest", "-q", *["tests/" + p + ".py" for p in tests], "--junitxml=" + str(out / "results.xml")], ["-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"], ["-m", "mypy", "zscope"], ["-m", "black", "--check", *owned]]
results = []
for index, argv in enumerate(commands):
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / f"command-{index}.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(call(argv), stdout=log, stderr=subprocess.STDOUT)
    row = {"argv": argv, "returncode": result.returncode, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    results.append(row)
    print(json.dumps(row), flush=True)
    if result.returncode:
        break
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
after = hashes()
assert suite is not None
passed = len(results) == 4 and all(r["returncode"] == 0 for r in results) and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")) and before == after
proof = {"finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "coordinator_validation_passed": passed, "independent_worker_acceptance": False, "source_unchanged": before == after, "before": before, "after": after, "commands": results, "junit": dict(suite.attrib), "owned": owned, "root_changed": False}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert passed
