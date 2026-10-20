"""Bind independent process-level native premise probes to the current green root."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
accepted = json.loads((ROOT / "artifacts/coordinator-r18-same-bytes-clock-observed-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
def hashes():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in accepted}
before = hashes()
assert before == accepted
out = ROOT / "artifacts" / (sys.argv[1] if len(sys.argv) > 1 else "coordinator-current-native-process-r19-20261015")
out.mkdir(exist_ok=False)
original = HERE / "followups-r12/test_native_hot_process_boundary.py"
probe = out / original.name
shutil.copyfile(original, probe)
probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_sha = hashlib.sha256(native.read_bytes()).hexdigest()
assert native_sha == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
env = dict(os.environ, Z_SCOPE_TEST_CLANG_INDEXER=str(native), ZSCOPE_NATIVE_PROCESS_EVIDENCE=str(out / "native-processes"))
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", sys.executable, "-m", "pytest", "-q", str(probe), "--junitxml=" + str(out / "results.xml")]
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
stable = before == after and hashlib.sha256(original.read_bytes()).hexdigest() == probe_sha == hashlib.sha256(probe.read_bytes()).hexdigest() and hashlib.sha256(native.read_bytes()).hexdigest() == native_sha
proof = {"started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "junit": dict(suite.attrib), "before": before, "after": after, "source_unchanged": stable, "probe_sha256": probe_sha, "native_sha256": native_sha, "passed": stable and result.returncode == 0 and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")), "scope": "Actual native Popen execution delegated without mocking outputs; cold/warm and include appearance/disappearance/higher-priority lookup with fresh fact comparisons on isolated fixtures. Does not establish complete navigation projection, full S01/S07, real projects/models or benchmarks. Old28-case replay assertion remains pending a separately verified test migration."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("finished_at", "returncode", "junit", "source_unchanged", "passed")}), flush=True)
sys.exit(0 if proof["passed"] else 1)
