"""Frozen shared queue receipt and Web projection checks; accepted MCP dependency."""
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
branch=ROOT/".coordination/20261014/workspaces/coordinator-shared-r14"
baseline=json.loads((HERE/"followups-r12/coordinator-shared-r14-baseline.json").read_text(encoding="utf-8"))
mcp=json.loads((ROOT/"artifacts/coordinator-mcp-findings-r12-ijson-ready-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert mcp["independent_acceptance_passed"] and mcp["source_unchanged"]
assert baseline["staged_mcp_dependencies"]==mcp["delivered_hashes"]
names=set(baseline["files"])|{"tests/test_job_queue_receipts.py","tests/test_job_result_http_binding.py"}
out=ROOT/"artifacts"/sys.argv[1]
out.mkdir(exist_ok=False)
(out/"launcher.py").write_bytes(Path(__file__).read_bytes())
def hashes():
    return {p:hashlib.sha256((branch/p).read_bytes()).hexdigest() for p in sorted(names)}
before=hashes()
changed={p:sha for p,sha in before.items() if baseline["files"].get(p)!=sha}
assert set(changed)<=set(baseline["owns"]),set(changed)-set(baseline["owns"])
for name in changed:
    target=out/"source-before"/name
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes((branch/name).read_bytes())
tests=["test_job_queue_receipts","test_job_result_http_binding","test_job_remaining","test_scan_jobs_http_api","test_job_result_projection","test_scan_jobs","test_scan_job_execution","test_scan_job_work_queue","test_job_session_scheduler","test_mcp_jobs","test_report_views","test_acceptance_projection","test_web_dashboard_server"]
probes=[str(HERE/"followups-r12/test_mcp_findings_boundaries.py")]
commands=[
    [sys.executable,"-m","pytest","-q",*["tests/"+name+".py" for name in tests],*probes,"--junitxml="+str(out/"results.xml")],
    [sys.executable,"-m","compileall","-f","-q","zscope","scripts","test","tests"],
    [sys.executable,"-m","mypy","zscope"],
    [sys.executable,"-m","black","--check",*sorted(changed)],
]
results=[]
for i,command in enumerate(commands):
    at=dt.datetime.now(dt.timezone.utc).isoformat()
    with (out/f"command-{i}.log").open("w",encoding="utf-8") as log:
        result=subprocess.run([sys.executable,str(HERE/"test_slot.py"),"--workspace",str(branch),"--",*command],env=os.environ.copy(),stdout=log,stderr=subprocess.STDOUT)
    results.append({"command":command,"returncode":result.returncode,"started_at":at,"finished_at":dt.datetime.now(dt.timezone.utc).isoformat(),"log":str((out/f"command-{i}.log").relative_to(ROOT))})
    print(json.dumps(results[-1]),flush=True)
    if result.returncode:
        break
suite=ET.parse(out/"results.xml").getroot().find("testsuite")
after=hashes()
passed=len(results)==4 and all(r["returncode"]==0 for r in results) and before==after and all(suite.get(k)=="0" for k in ("failures","errors","skipped"))
proof={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"junit":suite.attrib,"commands":results,"before_all_inputs":before,"after_all_inputs":after,"source_unchanged":before==after,"changed_files":changed,"passed":passed,"coordinator_authored":True,"dependency_acceptance":"artifacts/coordinator-mcp-findings-r12-ijson-ready-acceptance-20261015/review.json","integrated":False,"whole_package_complete":False,"scope":"Real HTTP/SQLite/owner/window and same-hash actual resume; current queue receipt/path binding and original caller-selected Web report scope. Work bodies and findings are controlled synthetic inputs, not real-project scanning acceptance."}
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"passed":passed,"junit":suite.attrib,"receipt":str(out/"review.json")}))
sys.exit(0 if passed else 1)
