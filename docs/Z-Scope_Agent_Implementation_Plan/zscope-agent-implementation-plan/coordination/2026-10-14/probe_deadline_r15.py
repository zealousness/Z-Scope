"""Diagnose the real owner deadline on a previously frozen R2 source, never live producer."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
prior=ROOT/"artifacts/coordinator-scan-session-r12-r2-refreshed-final-probes-20261015"
proof=json.loads((prior/"review.json").read_text(encoding="utf-8"))
branch=ROOT/".coordination/20261014/workspaces/coordinator-coordinator-scan-session-r12-r2-refreshed-final-probes-20261015"
def hashes():
    return {name:hashlib.sha256((branch/name).read_bytes()).hexdigest() for name in proof["before"]}
before=hashes();assert before==proof["before"]
out=ROOT/"artifacts/coordinator-scan-session-r12-r2-deadline-20261015"
out.mkdir(exist_ok=False)
for name in ("test_scan_session_crash_resume.py","test_scan_session_deadline.py"):
    shutil.copyfile(HERE/"followups-r12"/name,out/name)
env=os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"]="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
command=[sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",sys.executable,"-m","pytest","-q",str(out/"test_scan_session_deadline.py"),"--junitxml="+str(out/"results.xml")]
started=dt.datetime.now(dt.timezone.utc).isoformat()
with (out/"command-0.log").open("w",encoding="utf-8") as log:
    result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
suite=ET.parse(out/"results.xml").getroot().find("testsuite");assert suite is not None
after=hashes()
receipt={"started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"task_id":"task_658717aaa6","source_version":"frozen R2 with refreshed8readonlydependencies, not current R3 producer","source_evidence":(prior/"review.json").relative_to(ROOT).as_posix(),"before":before,"after":after,"source_unchanged":before==after,"command":command,"returncode":result.returncode,"junit":suite.attrib,"probe_hashes":{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob("test_*.py")},"diagnostic_only":True,"independent_delivery_acceptance":False,"integrated":False,"whole_package_complete":False}
(out/"review.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({k:receipt[k] for k in ("finished_at","returncode","junit","source_unchanged","source_version")}),flush=True)
sys.exit(result.returncode)
