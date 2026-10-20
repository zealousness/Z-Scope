"""Validate coordinator-authored test migration without changing the producer."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import audit, ROOT, HERE

assert sys.platform == "linux"
name = "coordinator-contract-migration-r17"
branch = ROOT / ".coordination/20261014/workspaces" / name
out = ROOT / "artifacts/coordinator-contract-migration-r17-20261015"
out.mkdir(exist_ok=False)
baseline = json.loads((HERE / ("followups-r12/" + name + "-baseline.json")).read_text(encoding="utf-8"))
owns = baseline["task"]["owns"]
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
def run(args, label):
    command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", *args]
    at = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / (label + ".log")).open("w", encoding="utf-8") as stream:
        value = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
    row = {"command": command, "returncode": value.returncode, "started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    print(json.dumps(row), flush=True)
    return row
assert run([sys.executable, "-m", "black", *owns], "format")["returncode"] == 0
def hashes():
    return {row["path"]: hashlib.sha256((branch / row["path"]).read_bytes()).hexdigest() for row in baseline["files"]}
before = hashes()
ownership = audit(name)
assert not ownership["nonowned_changes"], ownership
(out / "launcher.py").write_bytes(Path(__file__).read_bytes())
for path in owns:
    target = out / "source-before" / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((branch / path).read_bytes())
commands = [
    [sys.executable, "-m", "pytest", "-q", *owns, "--junitxml=" + str(out / "results.xml")],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "black", "--check", *owns],
]
results = []
for number, args in enumerate(commands):
    results.append(run(args, "command-" + str(number)))
    if results[-1]["returncode"]:
        break
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
after = hashes()
accepted = len(results) == 4 and all(row["returncode"] == 0 for row in results) and before == after and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped"))
proof = {"coordinator_authored": True, "validated": accepted, "independent_worker_acceptance": False, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "junit": suite.attrib, "commands": results, "ownership": ownership, "before": before, "after": after, "root_changed": False, "integrated": False, "whole_package_complete": False}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"validated": accepted, "junit": suite.attrib, "receipt": str(out / "review.json")}), flush=True)
raise SystemExit(0 if accepted else 1)
