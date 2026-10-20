"""Independent native identity rebinding probes; no product-file edits."""
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
assert not audit("validation-context-r18")["nonowned_changes"]
baseline = json.loads((HERE / "followups-r12/validation-context-r18-baseline.json").read_text(encoding="utf-8"))
names = {r["path"] for r in baseline["files"]} | set(baseline["task"]["owns"])
def hashes():
    return {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
out = ROOT / "artifacts/coordinator-validation-callee-r18-probes-20261015"
out.mkdir(exist_ok=False)
original = HERE / "followups-r12/test_validation_callee_rebind_boundary.py"
probe = out / original.name
shutil.copyfile(original, probe)
probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
env = dict(os.environ, Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_before = hashlib.sha256(Path(env["Z_SCOPE_TEST_CLANG_INDEXER"]).read_bytes()).hexdigest()
assert native_before == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
started = dt.datetime.now(dt.timezone.utc).isoformat()
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, "-m", "pytest", "-q", str(probe), "--junitxml=" + str(out / "results.xml")]
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
native_after = hashlib.sha256(Path(env["Z_SCOPE_TEST_CLANG_INDEXER"]).read_bytes()).hexdigest()
unchanged = before == after and native_before == native_after and hashlib.sha256(original.read_bytes()).hexdigest() == probe_sha == hashlib.sha256(probe.read_bytes()).hexdigest()
proof = {"task_id": "task_cb7011476d", "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "junit": dict(suite.attrib), "command": command, "before": before, "after": after, "source_unchanged": unchanged, "native_before": native_before, "native_after": native_after, "probe_sha256": probe_sha, "independent_acceptance_passed": result.returncode == 0 and unchanged and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")), "scope": "Actual native C++ overload and caller identities; contract-selection isolation only, not physical I/O, whole-project/model or whole-package effect acceptance."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("finished_at", "returncode", "junit", "source_unchanged", "independent_acceptance_passed")}), flush=True)
sys.exit(result.returncode)
