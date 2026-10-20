"""Freeze and independently probe the final shared-token budget and cause precedence."""
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
workspace = ROOT / ".coordination/20261014/workspaces/config-stop-at-r18"
ownership = audit("config-stop-at-r18")
assert not ownership["nonowned_changes"]
baseline = json.loads((HERE / "followups-r12/config-stop-at-r18-baseline.json").read_text(encoding="utf-8"))
names = {r["path"] for r in baseline["files"]} | {r["path"] for r in ownership["changes"]}
def hashes():
    return {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
task_id = next(r["bridge_task_id"] for r in json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))["tasks"] if r["id"] == "U01-STOP-AT-R18")
out = ROOT / "artifacts" / sys.argv[1]
out.mkdir(exist_ok=False)
probes, probe_hashes = [], {}
for name in ("test_config_stop_deadline_boundary.py", "test_stop_reason_precedence_boundary.py"):
    original = HERE / "followups-r12" / name
    target = out / name
    shutil.copyfile(original, target)
    probe_hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    probes.append(str(target))
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_sha = hashlib.sha256(native.read_bytes()).hexdigest()
assert native_sha == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
env = dict(os.environ, Z_SCOPE_TEST_CLANG_INDEXER=str(native))
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, "-m", "pytest", "-q", *probes, "--junitxml=" + str(out / "results.xml")]
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
stable = before == after and all(hashlib.sha256((HERE / "followups-r12" / p).read_bytes()).hexdigest() == sha == hashlib.sha256((out / p).read_bytes()).hexdigest() for p, sha in probe_hashes.items()) and hashlib.sha256(native.read_bytes()).hexdigest() == native_sha
proof = {"task_id": task_id, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "junit": dict(suite.attrib), "before": before, "after": after, "source_unchanged": stable, "probe_hashes": probe_hashes, "native_sha256": native_sha, "independent_acceptance_passed": stable and result.returncode == 0 and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")), "scope": "Original real ScanSession/shared token/local HTTP probes plus earlier deadline and inherited parent cancellation cause precedence. Controlled model headers; not real remote model/project or full S08/U01 acceptance."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("task_id", "finished_at", "returncode", "junit", "source_unchanged", "independent_acceptance_passed")}), flush=True)
sys.exit(0 if proof["independent_acceptance_passed"] else 1)
