"""Verify changed behavior without dropping the former Java resume coverage."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
baseline=json.loads((HERE/"followups-r12/coordinator-main-migration-r16-baseline.json").read_text(encoding="utf-8"))
branch=ROOT/".coordination/20261014/workspaces/coordinator-main-migration-r16"
out=ROOT/"artifacts/coordinator-main-migration-r16-20261015";out.mkdir(exist_ok=False)
name="tests/test_scan_session_resume_svf.py"
env=os.environ.copy();env["Z_SCOPE_TEST_CLANG_INDEXER"]="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
def run(command,logname):
    with (out/logname).open("w",encoding="utf-8") as log:
        result=subprocess.run([sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",*command],env=env,stdout=log,stderr=subprocess.STDOUT)
    return result.returncode
assert run([sys.executable,"-m","black",name],"format.log")==0
def hashes():
    return {p:hashlib.sha256((branch/p).read_bytes()).hexdigest() for p in baseline["files"]}
before=hashes()
assert all(before[p]==sha for p,sha in baseline["files"].items() if p!=name)
probes=[str(HERE/"followups-r12"/p) for p in ("test_scan_session_native_boundary.py","test_scan_session_crash_resume.py","test_scan_session_queue_fencing.py","test_scan_session_deadline.py")]
commands=[
    [sys.executable,"-m","pytest","-q",name,"tests/test_scan_session_instances.py","tests/test_scan_session_jobs.py",*probes,"--junitxml="+str(out/"results.xml")],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","black","--check",name,*[p for p in baseline["producer_owned_hashes"] if p.endswith(".py")]],
]
results=[];started=dt.datetime.now(dt.timezone.utc).isoformat()
for index,command in enumerate(commands):
    at=dt.datetime.now(dt.timezone.utc).isoformat();code=run(command,f"command-{index}.log")
    results.append({"command":command,"started_at":at,"returncode":code});print(json.dumps(results[-1]),flush=True)
    if code:break
suite=ET.parse(out/"results.xml").getroot().find("testsuite");assert suite is not None
after=hashes();accepted=len(results)==4 and all(r["returncode"]==0 for r in results) and before==after and all(suite.get(k)=="0" for k in ("errors","failures","skipped"))
receipt={"started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"commands":results,"junit":suite.attrib,"before":before,"after":after,"source_unchanged":before==after,"coordinator_validation_passed":accepted,"coordinator_owned_files":{name:after[name]},"producer_owned_hashes":baseline["producer_owned_hashes"],"producer_task_id":"task_2ba352c7a1","scope":baseline["scope"],"independent_worker_acceptance":False,"integrated":False,"whole_package_complete":False}
(out/"review.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"coordinator_validation":accepted,"junit":suite.attrib,"finished_at":receipt["finished_at"]}),flush=True)
sys.exit(0 if accepted else 1)
