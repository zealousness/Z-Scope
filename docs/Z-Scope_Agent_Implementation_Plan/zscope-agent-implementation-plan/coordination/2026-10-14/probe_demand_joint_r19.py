"""Reproduce inferred early joint failures against an isolated current-byte copy."""
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
names = set(json.loads((ROOT / "artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"])
names.update(r["path"] for r in json.loads((ROOT / "artifacts/intake-batch-r17-20261015/receipt.json").read_text(encoding="utf-8"))["files"])
workspace = ROOT / ".coordination/20261014/workspaces/coordinator-demand-r19"
workspace.mkdir(exist_ok=False)
before = {}
for name in sorted(names):
    data = (ROOT / name).read_bytes()
    before[name] = hashlib.sha256(data).hexdigest()
    target = workspace / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
out = ROOT / "artifacts/coordinator-demand-joint-r19-probe-20261015"
out.mkdir(exist_ok=False)
started = dt.datetime.now(dt.timezone.utc).isoformat()
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, "-m", "pytest", "-q", "tests/test_scan_demand_equivalence.py", "--junitxml=" + str(out / "results.xml")]
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in before}
proof = {"started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "command": command, "returncode": result.returncode, "junit": dict(suite.attrib), "before": before, "after": after, "source_unchanged": before == after, "root_unchanged": all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in before.items()), "scope": "Synthetic S07 equivalence oracle, isolated exact current root inputs; diagnosis only, not native/model/whole-package acceptance."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({k: proof[k] for k in ("finished_at", "returncode", "junit", "source_unchanged", "root_unchanged")}), flush=True)
sys.exit(result.returncode)
