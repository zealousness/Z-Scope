"""Linux documentation check after coordination updates; no new product claim."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import ROOT, HERE

assert sys.platform == "linux"
out = ROOT / "artifacts/coordinator-r17-coordination-docs-20261015"
out.mkdir(exist_ok=False)
source = json.loads((ROOT / "artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in source.items())
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", sys.executable, "-m", "pytest", "-q", "tests/test_agent_docs.py", "--junitxml=" + str(out / "results.xml")]
at = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "command-0.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
stable = all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in source.items())
proof = {"started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "command": command, "returncode": result.returncode, "junit": suite.attrib, "root_r16_bytes_unchanged": stable, "new_product_acceptance": False, "whole_package_complete": False}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(proof), flush=True)
raise SystemExit(result.returncode)
