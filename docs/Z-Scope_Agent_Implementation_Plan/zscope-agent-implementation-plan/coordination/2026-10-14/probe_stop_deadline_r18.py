"""Independent real-token/HTTP probes of the isolated stop-at delivery."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import HERE, ROOT, audit

assert sys.platform == "linux"
workspace = ROOT / ".coordination/20261014/workspaces/config-stop-at-r18"
assert not audit("config-stop-at-r18")["nonowned_changes"]
baseline = json.loads((HERE / "followups-r12/config-stop-at-r18-baseline.json").read_text(encoding="utf-8"))
names = {r["path"] for r in baseline["files"]} | set(baseline["task"]["owns"])
def hashes():
    return {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
out = ROOT / "artifacts/coordinator-stop-deadline-r18-probes-20261015"
out.mkdir(exist_ok=False)
original = HERE / "followups-r12/test_config_stop_deadline_boundary.py"
probe = out / original.name
shutil.copyfile(original, probe)
probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
started = dt.datetime.now(dt.timezone.utc).isoformat()
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, "-m", "pytest", "-q", str(probe), "--junitxml=" + str(out / "results.xml")]
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
unchanged = before == after and hashlib.sha256(original.read_bytes()).hexdigest() == probe_sha == hashlib.sha256(probe.read_bytes()).hexdigest()
proof = {"task_id": "task_5b722e514f", "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "junit": dict(suite.attrib), "command": command, "before": before, "after": after, "source_unchanged": unchanged, "probe_sha256": probe_sha, "independent_acceptance_passed": result.returncode == 0 and unchanged and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")), "scope": "Real ScanSessionRunner/shared CancellationToken and real local HTTP/LLMClient; controlled slow headers and subsecond budget, not a real remote model/project or complete S08 acceptance."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("finished_at", "returncode", "junit", "source_unchanged", "independent_acceptance_passed")}), flush=True)
sys.exit(result.returncode)
