"""Check the staged candidate; never edit the repository or run a sanitizer."""
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

base = Path(__file__).resolve().parent
previous = json.loads((base / (sys.argv[2] if len(sys.argv) > 2 else "candidate-regressions.json")).read_text())
stage = Path(previous["work"]) / "repo"
label = sys.argv[1]
xml = base / (label + ".xml")
out = base / (label + ".stdout.log")
err = base / (label + ".stderr.log")
command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
           "--tb=short", "--basetemp=" + str(stage.parent / label),
           "--junitxml=" + str(xml), str(base / "test_resource_lifecycle.py")]
env = {"PATH": "/home/zeal/venv313/bin:/usr/bin:/bin", "PYTHONPATH": str(stage),
       "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
       "TMPDIR": str(stage.parent), "LANG": "C.UTF-8"}
with out.open("xb") as so, err.open("xb") as se:
    result = subprocess.run(command, cwd=stage, env=env, stdout=so, stderr=se,
                            timeout=30, check=False)
counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
failures = []
for case in ET.parse(xml).getroot().iter("testcase"):
    state = ("errors" if case.find("error") is not None else
             "failed" if case.find("failure") is not None else
             "skipped" if case.find("skipped") is not None else "passed")
    counts[state] += 1
    if state != "passed":
        failures.append({"name": case.get("name"), "detail": [e.text for e in case]})
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
record = {"exit_code": result.returncode, "counts": counts, "failures": failures,
          "test_sha256": digest(base / "test_resource_lifecycle.py"),
          "command": command, "stage_digest": digest(stage / "zscope/core/validation/dynamic_reproduction.py"),
          "product_modified": False, "sanitizer_execution": False, "pressure": False,
          "max_fixture_output_bytes": 64,
          "artifacts": {p.name: {"sha256": digest(p), "bytes": p.stat().st_size}
                        for p in (xml, out, err)}}
(base / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({k: record[k] for k in ("exit_code", "counts", "failures", "stage_digest")}))
