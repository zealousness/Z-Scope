"""Check deterministic first-observation behavior on the unchanged current Root."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = json.loads((ROOT / "artifacts/coordinator-r19-all-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
def hashes():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in source}
before = hashes()
assert before == source
out = ROOT / "artifacts/coordinator-current-first-cause-r20-probes-20261015"
out.mkdir(exist_ok=False)
original = HERE / "followups-r12/test_stop_first_cause_observation_boundary.py"
probe = out / original.name
shutil.copyfile(original, probe)
sha = hashlib.sha256(probe.read_bytes()).hexdigest()
at = dt.datetime.now(dt.timezone.utc).isoformat()
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", sys.executable, "-m", "pytest", "-q", str(probe), "--junitxml=" + str(out / "results.xml")]
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
proof = {"started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "junit": dict(suite.attrib), "before": before, "after": after, "source_unchanged": before == after, "probe_sha256": sha, "probe_unchanged": sha == hashlib.sha256(original.read_bytes()).hexdigest() == hashlib.sha256(probe.read_bytes()).hexdigest(), "scope": "Actual CancellationToken first-observation order; deterministic expired monotonic deadline then later parent/explicit cancellation, no clock patch or watcher schedule assumption. This does not re-open or redo the independently accepted parent slice."}
(out / "review.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("finished_at", "junit", "source_unchanged", "probe_unchanged")}), flush=True)
sys.exit(result.returncode)
