"""Exercise added context cases against the already frozen rejected R4 bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import ROOT, HERE

assert sys.platform == "linux"
previous = json.loads((ROOT / "artifacts/coordinator-contract-r12-r4-context-probes-20261015/review.json").read_text(encoding="utf-8"))
branch = ROOT / ".coordination/20261014/workspaces/coordinator-coordinator-contract-r12-r4-context-probes-20261015"
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha for p, sha in previous["before"].items())
out = ROOT / "artifacts/coordinator-contract-r12-r4-context-tail-20261015"
out.mkdir(exist_ok=False)
probe = HERE / "followups-r12/test_contract_context_receipt_boundary.py"
(out / probe.name).write_bytes(probe.read_bytes())
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", sys.executable, "-m", "pytest", "-q", str(probe), "--junitxml=" + str(out / "results.xml")]
at = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
stable = all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha for p, sha in previous["before"].items())
proof = {"started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "command": command, "returncode": result.returncode, "junit": suite.attrib, "stable_frozen_inputs": stable, "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(), "original_frozen_receipt": "artifacts/coordinator-contract-r12-r4-context-probes-20261015/review.json", "synthetic_identity_boundary_only": True, "independent_acceptance": False, "root_changed": False, "whole_package_complete": False}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(proof), flush=True)
raise SystemExit(result.returncode)
