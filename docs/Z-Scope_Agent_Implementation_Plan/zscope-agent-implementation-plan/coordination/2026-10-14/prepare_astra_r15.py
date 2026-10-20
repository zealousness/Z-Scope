"""Prepare a new UI-owned snapshot after the previous Astra intake is green."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
source=json.loads((ROOT/"artifacts/coordinator-r15-mcp-queue-web-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
branch=ROOT/".coordination/20261014/workspaces/astra-job-projection-r15"
branch.mkdir(exist_ok=False)
for name,sha in source.items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha
    target=branch/name
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(ROOT/name,target)
    assert hashlib.sha256(target.read_bytes()).hexdigest()==sha
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row={"id":"ASTRA-JOB-PROJECTION-R15","title":"Web current-run report projection and resume UX verification","owner":"Astra","agent_kind":"native_subagent","agent_task_id":"/root/astra_v3_editor_r6","requested_model":"gpt-6-astra","requested_at":at,"depends_on":["CURRENT-JOINT-R15"],"packages":["U01","U02"],"isolated_workspace":str(branch),"isolated_workspace_linux":"/mnt/c/"+branch.as_posix()[3:],"write_paths":["zscope/web/static/**","tests/test_agent_workbench_ui.py","tests/fixtures/agent_workbench_ui.cjs"],"readonly_paths":["zscope/web/static/vendor/**","zscope/web/static/LICENSE*","requirements/portable/web-assets.lock.json"],"status":"prepared_dispatch_pending","artifact_available":False,"independent_acceptance":False,"integrated":False,"joint_verification":False,"whole_package_complete":False}
baseline={"captured_at":at,"task":row,"files":[{"path":name,"sha256":sha} for name,sha in sorted(source.items())],"source_evidence":"artifacts/coordinator-r15-mcp-queue-web-intaken-20261015/source-evidence.json"}
(HERE/"followups-r12/astra-job-projection-r15-baseline.json").write_text(json.dumps(baseline,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
ledger_path=HERE/"tasks.json"
ledger=json.loads(ledger_path.read_text(encoding="utf-8"))
assert not any(r["id"]==row["id"] for r in ledger["tasks"])
ledger["tasks"].append(row);ledger["updated_at"]=at
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"prepared":str(branch),"inputs":len(source),"at":at}))
