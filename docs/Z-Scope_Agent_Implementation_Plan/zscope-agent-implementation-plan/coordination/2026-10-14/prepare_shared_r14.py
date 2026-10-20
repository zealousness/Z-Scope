"""Stage shared queue/Web integration; MCP bytes stay pending its acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
source=json.loads((ROOT/"artifacts/coordinator-shared-r13-source-roots-20261015/review.json").read_text(encoding="utf-8"))["after_all_inputs"]
before={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source}
branch=ROOT/".coordination/20261014/workspaces/coordinator-shared-r14"
branch.mkdir(exist_ok=False)
for name in before:
    target=branch/name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/name,target)
assert before=={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in source}
producer=ROOT/".coordination/20261014/workspaces/mcp-findings-r12"
mcp=json.loads((HERE/"followups-r12/mcp-findings-r12-baseline.json").read_text(encoding="utf-8"))["task"]["owns"]
dependencies={}
for name in mcp:
    dependencies[name]=hashlib.sha256((producer/name).read_bytes()).hexdigest()
    target=branch/name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(producer/name,target)
merged={**before,**dependencies}
baseline={"at":dt.datetime.now(dt.timezone.utc).isoformat(),"workspace":str(branch),"files":merged,"parent_root_inputs":before,"staged_mcp_dependencies":dependencies,"staged_dependency_task":"task_e4ab0da557","dependency_independent_acceptance":False,"owns":["zscope/orchestration/jobs/owner.py","zscope/orchestration/jobs/store.py","zscope/web/scan_jobs_service.py","zscope/reporting/job_result_projection.py","tests/test_job_queue_receipts.py","tests/test_scan_jobs_http_api.py","tests/test_job_result_http_binding.py"],"intaken":False}
(HERE/"followups-r12/coordinator-shared-r14-baseline.json").write_text(json.dumps(baseline,indent=2)+"\n",encoding="utf-8",newline="\n")
shutil.copyfile(HERE/"followups-r12/test_job_queue_receipts.py",branch/"tests/test_job_queue_receipts.py")
print(json.dumps({"prepared":str(branch),"inputs":len(merged),"staged_mcp_dependency_pending":True}))
