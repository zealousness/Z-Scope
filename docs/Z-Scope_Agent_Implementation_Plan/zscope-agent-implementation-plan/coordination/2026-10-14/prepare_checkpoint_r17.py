"""Prepare isolated checkpoint work from accepted inputs; root remains R16."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
root_source=json.loads((ROOT/"artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
inputs=dict(root_source)
branch=ROOT/".coordination/20261014/workspaces/scan-checkpoint-r17"
branch.mkdir(exist_ok=False)
for name,sha in root_source.items():
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha
    target=branch/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
authorities=[]
main_path=ROOT/"artifacts/coordinator-scan-session-r12-r3-acceptance-20261015/review.json"
main=json.loads(main_path.read_text(encoding="utf-8"));assert main["independent_acceptance_passed"] and main["source_unchanged"]
api_path=ROOT/"artifacts/coordinator-bound-events-r17-same-bytes-20261015/review.json"
api=json.loads(api_path.read_text(encoding="utf-8"));assert api["coordinator_validation_passed"] and api["source_unchanged"]
migration_path=ROOT/"artifacts/coordinator-main-migration-r16-20261015/review.json"
migration=json.loads(migration_path.read_text(encoding="utf-8"));assert migration["coordinator_validation_passed"]
overlays=[(main["delivered_hashes"],main_path.parent/"source-before",main_path,"worker independent acceptance"),(api["files"],api_path.parent/"source-before",api_path,"coordinator validation; not root-intaken"),(migration["coordinator_owned_files"],ROOT/".coordination/20261014/workspaces/coordinator-main-migration-r16",migration_path,"coordinator validated readonly test migration")]
for files,source,authority,scope in overlays:
    for name,sha in files.items():
        assert hashlib.sha256((source/name).read_bytes()).hexdigest()==sha
        target=branch/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target)
        inputs[name]=sha
        authorities.append({"path":name,"sha256":sha,"authority":authority.relative_to(ROOT).as_posix(),"scope":scope})
assert all(hashlib.sha256((branch/name).read_bytes()).hexdigest()==sha for name,sha in inputs.items())
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
owns=["zscope/orchestration/scan_session.py","zscope/orchestration/parallel_analyzer.py","zscope/orchestration/jobs/scan_work.py","tests/test_scan_session_instances.py","tests/test_scan_session_jobs.py","tests/test_scan_checkpoint_resume.py"]
row={"id":"SCAN-CHECKPOINT-R17","title":"Current native plan checkpoint recovery across actual job runs","owner":"kimi","agent":"kimi","requested_model":"volceapi/kimi-k3","model":"volceapi/kimi-k3","session_id":"sess_261a55289f","bridge_session_id":"sess_261a55289f","workspace":"scan-checkpoint-r17","isolated_workspace":str(branch),"isolated_workspace_linux":"/mnt/c/"+branch.as_posix()[3:],"owns":owns,"write_paths":owns,"depends_on":["SCAN-SESSION-R12","COORD-BOUND-EVENTS-R17"],"integration_depends_on":["CONTRACT-VALIDATION-R12"],"packages":["S08","S01"],"status":"prepared_dispatch_pending","artifact_available":False,"independent_acceptance":False,"integrated":False,"joint_verification":False,"whole_package_complete":False,"baseline_receipt":"followups-r12/scan-checkpoint-r17-baseline.json","parent_intakes_joint_required":True,"contract_dependency":"R4 active; not copied. Refresh only after independent acceptance."}
baseline={"captured_at":at,"task":row,"files":[{"path":name,"sha256":sha} for name,sha in sorted(inputs.items())],"dependency_receipts":authorities,"root_source_evidence":"artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json","root_unchanged":True}
(HERE/row["baseline_receipt"]).write_text(json.dumps(baseline,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
p=HERE/"tasks.json";d=json.loads(p.read_text(encoding="utf-8"));rows={r["id"]:r for r in d["tasks"]}
assert row["id"] not in rows
if "COORD-BOUND-EVENTS-R17" not in rows:
    d["tasks"].append({"id":"COORD-BOUND-EVENTS-R17","title":"Atomic current-owner completion receipts","owner":"coordinator","depends_on":["CURRENT-JOINT-R16"],"packages":["S08"],"write_paths":["zscope/orchestration/jobs/store.py","tests/test_job_bound_completion.py"],"status":"coordinator_validated_intake_pending","artifact_available":True,"coordinator_validation":True,"independent_acceptance":False,"integrated":False,"joint_verification":False,"whole_package_complete":False,"validation_evidence":api_path.relative_to(ROOT).as_posix(),"validation_result":api["junit"],"validation_finished_at":api["finished_at"],"prior_clock_failure":"artifacts/coordinator-bound-events-r17-20261015/deadline-timeline.json"})
d["tasks"].append(row);d["updated_at"]=at
rows={r["id"]:r for r in d["tasks"]};left,done,layers=set(rows),set(),[]
while left:
    ready=[r["id"] for r in d["tasks"] if r["id"] in left and set(r["depends_on"])<=done];assert ready
    layers.append(ready);left.difference_update(ready);done.update(ready)
d["topological_layers"]=layers
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"prepared":str(branch),"inputs":len(inputs),"root_unchanged":True,"at":at}))
