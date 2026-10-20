"""Refresh coordinator-accepted readonly dependencies only after producer stops."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
branch=ROOT/".coordination/20261014/workspaces/scan-session-r12"
linux_here="/mnt/c/"+HERE.as_posix()[3:]
processes=json.loads(subprocess.check_output(["wsl","-d","Ubuntu","--","bash","-lc",f"/home/zeal/venv313/bin/python {linux_here}/inspect_workspace_processes.py scan-session-r12"],text=True))
assert not processes["processes"],processes
baseline=json.loads((HERE/"followups-r12/scan-session-r12-baseline.json").read_text(encoding="utf-8"))
original={r["path"]:r["sha256"] for r in baseline["files"]}
receipts=["artifacts/intake-coordinator-source-roots-r13-20261015/receipt.json","artifacts/intake-coordinator-queue-web-r14-20261015/receipt.json","artifacts/intake-coordinator-remaining-r12-20261015/receipt.json"]
authorities={}
for name in reversed(receipts):
    receipt=json.loads((ROOT/name).read_text(encoding="utf-8"))
    assert receipt["integrated"]
    authorities.update({p:(sha,name) for p,sha in receipt.get("accepted_files",receipt.get("files",{})).items()})
names=["zscope/retrieval/code_index.py","zscope/orchestration/jobs/owner.py","zscope/orchestration/jobs/store.py","zscope/orchestration/jobs/work_queue.py","tests/test_scan_job_execution.py","tests/test_job_remaining.py","tests/test_native_source_roots.py","tests/test_job_queue_receipts.py"]
out=HERE/"followups-r12/scan-session-r12-dependencies.json"
assert not out.exists()
rows=[]
for name in names:
    sha,authority=authorities[name]
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha,name
    target=branch/name
    before=hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
    assert before==original.get(name),(name,before,original.get(name))
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/name,target)
    rows.append({"path":name,"previous_sha256":before,"sha256":sha,"authority":authority,"readonly":True})
out.write_text(json.dumps({"at":dt.datetime.now(dt.timezone.utc).isoformat(),"producer_task":"task_658717aaa6","producer_quiescence":processes,"files":rows,"original_baseline_preserved":True,"contract_dependency_pending":"CONTRACT-VALIDATION-R12; not copied from an unaccepted active writer"},indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"refreshed":len(rows),"receipt":str(out),"producer_owned_files_unchanged":True}))
