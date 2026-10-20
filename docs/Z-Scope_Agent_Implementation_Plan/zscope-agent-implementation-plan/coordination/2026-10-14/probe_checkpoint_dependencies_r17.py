"""Check the exact current dependency helper against a preserved frozen copy."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import ROOT, HERE

assert sys.platform == "linux"
producer = ROOT / ".coordination/20261014/workspaces/scan-checkpoint-r17"
frozen = ROOT / ".coordination/20261014/workspaces/coordinator-coordinator-checkpoint-r17-repaired-authority-20261015"
names = ["zscope/orchestration/jobs/scan_work.py", "zscope/orchestration/parallel_analyzer.py", "zscope/config/user_config_store.py", "zscope/config/protocol_feedback.py", "zscope/semantics/contracts.py", "zscope/semantics/standard_api.py"]
def hashes(base):
    return {name: hashlib.sha256((base / name).read_bytes()).hexdigest() for name in names}
before = hashes(frozen)
assert before == hashes(producer), "the dependency helper/import inputs must match the current producer"
out = ROOT / "artifacts" / (sys.argv[1] if len(sys.argv) > 1 else "coordinator-checkpoint-r17-dependency-probes-20261015")
out.mkdir(exist_ok=False)
source = HERE / "followups-r12/test_scan_checkpoint_dependency_boundary.py"
probe = out / source.name;probe.write_bytes(source.read_bytes())
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(frozen), "--", sys.executable, "-m", "pytest", "-q", str(probe), "--junitxml=" + str(out / "results.xml")]
at = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
data = {"started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "returncode": result.returncode, "command": command, "junit": suite.attrib, "before": before, "after": hashes(frozen), "stable_frozen_inputs": hashes(frozen) == before, "current_producer_inputs_match": hashes(producer) == before, "actual_sqlite_synthetic_plan_only": True, "full_scanner_acceptance": False, "root_changed": False, "whole_package_complete": False}
(out / "review.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"finished_at": data["finished_at"], "junit": suite.attrib, "returncode": result.returncode, "current_producer_inputs_match": data["current_producer_inputs_match"]}), flush=True)
raise SystemExit(result.returncode)
