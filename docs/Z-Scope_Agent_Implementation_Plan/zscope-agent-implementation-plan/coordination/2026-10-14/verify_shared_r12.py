"""Strict Linux verification of the coordinator's isolated shared R12 repair."""
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
branch = ROOT / ".coordination/20261014/workspaces/coordinator-shared-r12"
out = ROOT / "artifacts" / sys.argv[1]
out.mkdir(exist_ok=False)
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
baseline = json.loads((HERE / "followups-r12/coordinator-shared-baseline.json").read_text(encoding="utf-8"))
owns = set(baseline["owns"]) | {"zscope/orchestration/jobs/work_queue.py", "tests/test_job_remaining.py"}
names = set(baseline["files"]) | {"tests/test_job_remaining.py"}

def hashes():
    return {name: hashlib.sha256((branch / name).read_bytes()).hexdigest() for name in sorted(names)}

before = hashes()
changed = {name: sha for name, sha in before.items() if baseline["files"].get(name) != sha}
assert set(changed) <= owns, set(changed) - owns
for name in names:
    if name not in changed:
        continue
    target = out / "source-before" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((branch / name).read_bytes())
tests = ["test_job_remaining", "test_scan_jobs", "test_scan_job_execution", "test_scan_job_work_queue", "test_job_session_scheduler", "test_scan_jobs_http_api", "test_mcp_jobs"]
commands = [
    [sys.executable, "-m", "pytest", "-q", *[f"tests/{name}.py" for name in tests], f"--junitxml={out / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "black", "--check", "zscope/orchestration/jobs/owner.py", "zscope/orchestration/jobs/work_queue.py", "tests/test_job_remaining.py"],
]
results = []
for index, command in enumerate(commands):
    at = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / f"command-{index}.log").open("w", encoding="utf-8") as stream:
        completed = subprocess.run([sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", *command], stdout=stream, stderr=subprocess.STDOUT, env=os.environ.copy())
    results.append({"command":command,"returncode":completed.returncode,"started_at":at,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"log":str((out / f"command-{index}.log").relative_to(ROOT))})
    print(json.dumps(results[-1]), flush=True)
    if completed.returncode:
        break
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
after = hashes()
passed = len(results) == 4 and all(row["returncode"] == 0 for row in results) and before == after and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped"))
proof = {"verified_at":dt.datetime.now(dt.timezone.utc).isoformat(),"junit":suite.attrib,"commands":results,"before_all_inputs":before,"after_all_inputs":after,"source_unchanged":before==after,"changed_files":changed,"passed":passed,"integrated":False,"whole_package_complete":False,"scope":"Real SQLite/owner accounting and cooperative queue stop over controlled scanner/report/work inputs. Does not establish full ScanSession integration or real project effects."}
(out / "review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"passed":passed,"junit":suite.attrib,"receipt":str(out / "review.json")}))
sys.exit(0 if passed else 1)
