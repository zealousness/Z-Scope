"""Intake only the three independently accepted bounded slices and staged docs."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import time
from uuid import uuid4

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
route=HERE/"route-check"
name="r19-intake-sessions-"+uuid4().hex[:10]
request={"id":name,"tool":"list_sessions","arguments":{"active_only":True}}
(route/"bridge-queue"/("080-"+name+".request.json")).write_text(json.dumps(request)+"\n",encoding="utf-8",newline="\n")
response=route/("bridge-response-"+name+".json")
until=time.monotonic()+40
while not response.exists() and time.monotonic()<until:time.sleep(.25)
assert response.exists()
sessions=json.loads(response.read_text(encoding="utf-8"))
assert not [s for s in sessions.get("sessions",[]) if s.get("proc_state")=="busy" and str(s.get("cwd","")).lower()==str(ROOT).lower()], "later same-repo worker exists; inspect ownership before intake"
base=json.loads((ROOT/"artifacts/coordinator-r18-same-bytes-clock-observed-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==sha for p,sha in base.items())
specs={"VALIDATION-CONTEXT-R18":("validation-context-r18","coordinator-validation-context-r19-final-acceptance-20261015"),"U01-STOP-AT-R18":("config-stop-at-r18","coordinator-stop-r19-final-acceptance-20261015"),"S07-NATIVE-HOT-R19":("native-hot-cache-r19","coordinator-native-hot-r19-final-acceptance-20261015")}
sources={}
reviews={}
for identity,(workspace_name,label) in specs.items():
    review=json.loads((ROOT/"artifacts"/label/"review.json").read_text(encoding="utf-8"))
    assert review["independent_acceptance_passed"] and review["source_unchanged"]
    assert len(review["commands"])==4 and all(r["returncode"]==0 for r in review["commands"])
    assert all(review["junit"][k]=="0" for k in ("errors","failures","skipped"))
    workspace=ROOT/".coordination/20261014/workspaces"/workspace_name
    baseline=json.loads((HERE/"followups-r12"/(workspace_name+"-baseline.json")).read_text(encoding="utf-8"))
    parents={r["path"]:r["sha256"] for r in baseline["files"]}
    for p,sha in review["delivered_hashes"].items():
        assert hashlib.sha256((workspace/p).read_bytes()).hexdigest()==sha
        if p in parents: assert base.get(p)==parents[p], "owned parent diverged: "+p
        else: assert not (ROOT/p).exists(), "new owned file already exists: "+p
        assert p not in sources or sources[p][1]==sha
        sources[p]=(workspace/p,sha,identity)
    reviews[identity]=(label,review)
dependencies=json.loads((HERE/"followups-r12/config-stop-at-r18-dependencies.json").read_text(encoding="utf-8"))
for r in dependencies["files"]:
    p=r["path"]
    source=ROOT/".coordination/20261014/workspaces/config-stop-at-r18"/p
    assert base[p]==r["previous_sha256"] and hashlib.sha256(source.read_bytes()).hexdigest()==r["sha256"]
    assert reviews["U01-STOP-AT-R18"][1]["after_all_inputs"][p]==r["sha256"]
    if p=="tests/test_incremental_replay.py":assert reviews["S07-NATIVE-HOT-R19"][1]["after_all_inputs"][p]==r["sha256"]
    sources[p]=(source,r["sha256"],"coordinator_readonly_test_migration")
staged=ROOT/"artifacts/staged-r19-module-notes-20261015"
for r in json.loads((staged/"staging.json").read_text(encoding="utf-8"))["files"]:
    p=r["path"]
    assert base[p]==r["before"] and hashlib.sha256((staged/p).read_bytes()).hexdigest()==r["after"]
    sources[p]=(staged/p,r["after"],"coordinator_module_notes")
assert len(sources)==22
out=ROOT/"artifacts/intake-batch-r19-20261015"
out.mkdir(exist_ok=False)
rows=[]
for p,(source,sha,owner) in sorted(sources.items()):
    target=ROOT/p
    before=hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
    if before is not None:
        backup=out/"backup"/p
        backup.parent.mkdir(parents=True,exist_ok=True)
        backup.write_bytes(target.read_bytes())
    data=source.read_bytes()
    assert hashlib.sha256(data).hexdigest()==sha
    data.decode("utf-8")
    assert not data.startswith(b"\xef\xbb\xbf") and b"\r\n" not in data and data.endswith(b"\n"),p
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_bytes(data)
    assert hashlib.sha256(target.read_bytes()).hexdigest()==sha
    rows.append({"path":p,"before":before,"after":sha,"source":str(source),"owner":owner})
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
receipt={"intaken_at":at,"files":rows,"independent_reviews":{p:"artifacts/"+v[0]+"/review.json" for p,v in reviews.items()},"session_preflight":response.relative_to(HERE).as_posix(),"joint_verification_passed":False,"whole_packages_complete":False,"scope":"Three bounded slices, two coordinator readonly test migrations and six module notes. Old current2079 becomes historical; full union regression/quality required. Not real-project/model, complete S01/S07/S08/U01, formal benchmark or portable smoke."}
(out/"receipt.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
by_id={r["id"]:r for r in ledger["tasks"]}
for identity,(label,review) in reviews.items():
    row=by_id[identity]
    assert row["bridge_task_id"]==review["task_id"]
    row.update(status="independent_accepted_intaken_current_union_joint_pending",artifact_available=True,independent_acceptance=True,acceptance_evidence="artifacts/"+label+"/review.json",independent_result=review["junit"],independent_finished_at=review["finished_at"],integrated=True,integrated_at=at,intake_evidence="artifacts/intake-batch-r19-20261015/receipt.json",joint_verification=False,whole_package_complete=False,checked_at=at)
assert "CURRENT-JOINT-R19" not in by_id
ledger["tasks"].append({"id":"CURRENT-JOINT-R19","owner":"coordinator","depends_on":["CURRENT-JOINT-R18",*specs],"status":"intaken_current_union_joint_pending","evidence":"artifacts/coordinator-r19-all-intaken-20261015","whole_package_complete":False})
remaining={r["id"] for r in ledger["tasks"]};done=set();layers=[]
while remaining:
    ready=[r["id"] for r in ledger["tasks"] if r["id"] in remaining and set(r.get("depends_on",[]))<=done]
    assert ready
    layers.append(ready);done.update(ready);remaining.difference_update(ready)
ledger["topological_layers"]=layers
ledger["current_accepted_stage"].update(is_current_root=False,current_root_status="R19 22-file batch intaken; R18 selected2079/six0 now historical; fresh full union pending")
ledger["updated_at"]=at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"continuation-r6.json"
data=json.loads(path.read_text(encoding="utf-8"))
data.update(updated_at=at,current_joint="artifacts/coordinator-r19-all-intaken-20261015",current_joint_status="intaken_current_union_joint_pending",current_root_status=ledger["current_accepted_stage"]["current_root_status"],prior_pass_is_current_root=False,latest_joint_attempt_passed=False,latest_joint_attempt="artifacts/coordinator-r19-all-intaken-20261015",active_phase="R19 all3 independently accepted/intaken; fresh union plus six commands and clock observations required")
path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"## {at} · R19 22文件验收后导入，当前联合待验\n\n三独立集合：context task_1ef444cf29 1084/0及四命令0；stop task_4e43cb393d 532/0及四命令0；native baseline task_7118aeca55 175/0及四命令0。范围不同不相加。原native28的27/1、各返修失败、无效coordinator fixture均保留并分开分类。两只读测试由协调者迁移；native测试说明更正仅文档AST不变。六模块/交接说明同步。导入22路径及backup/前后SHA见 artifacts/intake-batch-r19-20261015/receipt.json。\n\n当前Root已变：此前R18 2079/六命令0为历史。新R19启动器自动保留全部R18及三独验集合/最新探针的并集，未降低capture/超时/skip标准，需在Linux两槽/default fd/ext4重跑并观测时钟；暂无新Root通过结论。正常owner80748及停写目录所有权核对，无新派单/旧S06操作。全实例建模/SVF/link、逐实例durable、resume窗口重挂、U01其余字段/多目标、真实项目/模型、条件S10/Q、正式benchmark/portable仍单列未完成。\n\n---\n\n"
for filename in ("PROGRESS.md","DAG.md"):
    path=HERE/filename
    path.write_text(note+path.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps({"intaken_at":at,"paths":len(rows),"current_root_joint_passed":False,"receipt":str(out/"receipt.json")}),flush=True)
