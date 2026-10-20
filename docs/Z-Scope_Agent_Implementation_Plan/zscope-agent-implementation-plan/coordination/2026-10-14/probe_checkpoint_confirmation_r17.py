"""Test serialized authority against the frozen delivered checkpoint bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import ROOT, HERE

assert sys.platform == "linux"
previous = json.loads((ROOT / "artifacts/coordinator-checkpoint-r17-authority-probes-20261015/review.json").read_text(encoding="utf-8"))
branch = ROOT / ".coordination/20261014/workspaces/coordinator-coordinator-checkpoint-r17-authority-probes-20261015"
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha for p, sha in previous["before"].items())
out = ROOT / "artifacts/coordinator-checkpoint-r17-confirmation-probe-20261015"
out.mkdir(exist_ok=False)
source = HERE / "followups-r12/test_scan_checkpoint_authority_boundary.py"
probe = out / source.name
probe.write_bytes(source.read_bytes())
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", sys.executable, "-m", "pytest", "-q", str(probe) + "::test_serialized_confirmation_cannot_become_a_current_scan_confirmation", "--junitxml=" + str(out / "results.xml")]
at = dt.datetime.now(dt.timezone.utc).isoformat()
environment = dict(__import__("os").environ)
environment["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
stable = all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha for p, sha in previous["before"].items())
proof = {"started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "command": command, "returncode": result.returncode, "junit": suite.attrib, "stable_frozen_inputs": stable, "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(), "original_frozen_receipt": "artifacts/coordinator-checkpoint-r17-authority-probes-20261015/review.json", "actual_native_scan_and_sql": True, "controlled_report_output_not_real_proof": True, "independent_acceptance": False, "root_changed": False, "whole_package_complete": False}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"finished_at": proof["finished_at"], "returncode": result.returncode, "junit": suite.attrib, "stable_frozen_inputs": stable}), flush=True)
raise SystemExit(result.returncode)
