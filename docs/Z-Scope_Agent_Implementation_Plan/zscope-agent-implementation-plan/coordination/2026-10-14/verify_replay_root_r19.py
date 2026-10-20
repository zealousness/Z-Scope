"""Independently check reported native replay failure against current root."""
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
out = ROOT / "artifacts/coordinator-current-native-replay-r19-20261015"
out.mkdir(exist_ok=False)
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native_sha = hashlib.sha256(native.read_bytes()).hexdigest()
assert native_sha == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
names = sorted({p.relative_to(ROOT).as_posix() for p in (ROOT / "zscope").rglob("*.py")} | {"tests/test_incremental_replay.py"})
def hashes():
    return {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in names}
before = hashes()
env = dict(os.environ, Z_SCOPE_TEST_CLANG_INDEXER=str(native))
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", sys.executable, "-m", "pytest", "-q", "tests/test_incremental_replay.py", "--junitxml=" + str(out / "results.xml")]
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
stable = before == after and hashlib.sha256(native.read_bytes()).hexdigest() == native_sha
proof = {"started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "junit": dict(suite.attrib), "command": command, "before": before, "after": after, "source_unchanged": stable, "native_sha256": native_sha, "passed": stable and result.returncode == 0 and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")), "scope": "Reported old isolated-branch replay failure checked independently against exact current root; actual native fixture, not real-project/model or full S07 acceptance."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("finished_at", "returncode", "junit", "source_unchanged", "passed")}), flush=True)
sys.exit(0 if proof["passed"] else 1)
