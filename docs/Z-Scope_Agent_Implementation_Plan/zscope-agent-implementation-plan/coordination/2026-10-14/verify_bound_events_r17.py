"""Shared API validation on frozen coordinator source, not full ScanSession acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

assert sys.platform=="linux"
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
baseline=json.loads((HERE/"followups-r12/coordinator-bound-events-r17-baseline.json").read_text(encoding="utf-8"))
branch=ROOT/".coordination/20261014/workspaces/coordinator-bound-events-r17"
label=sys.argv[1] if len(sys.argv)>1 else "coordinator-bound-events-r17-20261015"
out=ROOT/"artifacts"/label;out.mkdir(exist_ok=False)
(out/"launcher.py").write_bytes(Path(__file__).read_bytes())
names=sorted(set(baseline["files"])|set(baseline["owns"]))
def hashes():return {p:hashlib.sha256((branch/p).read_bytes()).hexdigest() for p in names}
before=hashes()
if len(sys.argv)>2:
    prior=json.loads((ROOT/"artifacts"/sys.argv[2]/"review.json").read_text(encoding="utf-8"))
    assert before==prior["after"], "same-byte retry cannot change product or test inputs"
assert all(before[p]==sha for p,sha in baseline["files"].items() if p not in baseline["owns"])
for p in baseline["owns"]:
    target=out/"source-before"/p;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((branch/p).read_bytes())
tests=["test_job_bound_completion","test_scan_jobs","test_scan_job_execution","test_job_session_scheduler","test_scan_job_work_queue","test_job_remaining","test_job_queue_receipts","test_job_result_http_binding"]
commands=[
    [sys.executable,"-m","pytest","-q",*[f"tests/{name}.py" for name in tests],"--junitxml="+str(out/"results.xml")],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","black","--check",*baseline["owns"]],
]
env=os.environ.copy();env["Z_SCOPE_TEST_CLANG_INDEXER"]="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
clock_stop=threading.Event()
clock_changes=[]
def observe_clock():
    wall,mono=time.time(),time.monotonic()
    while not clock_stop.wait(.02):
        next_wall,next_mono=time.time(),time.monotonic()
        drift=(next_wall-wall)-(next_mono-mono)
        if abs(drift)>.01:
            clock_changes.append({"wall_epoch":next_wall,"monotonic":next_mono,"wall_minus_monotonic_delta":drift})
        wall,mono=next_wall,next_mono
clock_thread=threading.Thread(target=observe_clock,daemon=True);clock_thread.start()
started=dt.datetime.now(dt.timezone.utc).isoformat();results=[]
for index,command in enumerate(commands):
    at=dt.datetime.now(dt.timezone.utc).isoformat()
    with (out/f"command-{index}.log").open("w",encoding="utf-8") as log:
        result=subprocess.run([sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",*command],env=env,stdout=log,stderr=subprocess.STDOUT)
    results.append({"command":command,"returncode":result.returncode,"started_at":at,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat()});print(json.dumps(results[-1]),flush=True)
    if result.returncode:break
clock_stop.set();clock_thread.join(timeout=1)
(out/"clock-observations.json").write_text(json.dumps({"read_only_sampler":True,"sampling_interval":.02,"clock_changes":clock_changes},indent=2)+"\n",encoding="utf-8",newline="\n")
suite=ET.parse(out/"results.xml").getroot().find("testsuite");assert suite is not None
after=hashes();accepted=len(results)==4 and all(r["returncode"]==0 for r in results) and before==after and all(suite.get(k)=="0" for k in ("failures","errors","skipped"))
proof={"started_at":started,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"commands":results,"junit":suite.attrib,"before":before,"after":after,"source_unchanged":before==after,"coordinator_authored":True,"coordinator_validation_passed":accepted,"independent_worker_acceptance":False,"files":{p:after[p] for p in baseline["owns"]},"integrated":False,"whole_package_complete":False,"scope":"Actual SQLite and service/owner regression; controlled work/report inputs. Bound event publication and read coordinates, not proof of file contents or semantic validity. ScanSession consumption and per-instance/cross-run native recovery remain separate acceptance."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"coordinator_validation":accepted,"junit":suite.attrib,"finished_at":proof["finished_at"]}),flush=True)
sys.exit(0 if accepted else 1)
