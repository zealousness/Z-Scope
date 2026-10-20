"""Run two additional native immutable-call-context boundaries independently."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import HERE, ROOT, audit

assert sys.platform == "linux"
workspace = ROOT / ".coordination/20261014/workspaces/validation-context-r18"
ownership = audit("validation-context-r18")
assert not ownership["nonowned_changes"]
baseline = json.loads((HERE / "followups-r12/validation-context-r18-baseline.json").read_text(encoding="utf-8"))
names = {r["path"] for r in baseline["files"]} | {r["path"] for r in ownership["changes"]}
def hashes():
    return {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
out = ROOT / "artifacts/coordinator-validation-snapshot-r19-probes-20261015"
out.mkdir(exist_ok=False)
original = HERE / "followups-r12/test_validation_call_snapshot_boundary.py"
probe = out / original.name
shutil.copyfile(original, probe)
sha = hashlib.sha256(probe.read_bytes()).hexdigest()
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_sha = hashlib.sha256(native.read_bytes()).hexdigest()
assert native_sha == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
env = dict(os.environ, Z_SCOPE_TEST_CLANG_INDEXER=str(native))
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, "-m", "pytest", "-q", str(probe), "--junitxml=" + str(out / "results.xml")]
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
stable = before == after and hashlib.sha256(original.read_bytes()).hexdigest() == sha == hashlib.sha256(probe.read_bytes()).hexdigest() and hashlib.sha256(native.read_bytes()).hexdigest() == native_sha
proof = {"task_id": "task_bf7efdfce3", "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "junit": dict(suite.attrib), "before": before, "after": after, "source_unchanged": stable, "probe_sha256": sha, "native_sha256": native_sha, "independent_acceptance_passed": stable and result.returncode == 0 and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")), "scope": "Actual native mixed-overload identities and real fact-provider submission; parent binding mutation after capture must not grant the single int overload. Identity-selection isolation, not physical I/O or real-project/model effect."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("task_id", "finished_at", "returncode", "junit", "source_unchanged", "independent_acceptance_passed")}), flush=True)
sys.exit(0 if proof["independent_acceptance_passed"] else 1)
