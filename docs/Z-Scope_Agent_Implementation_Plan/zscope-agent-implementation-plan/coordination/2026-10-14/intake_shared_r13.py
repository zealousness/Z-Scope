"""Integrate only coordinator-authored, byte-stable validated source-root fix."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
accepted=ROOT/"artifacts/coordinator-shared-r13-source-roots-20261015"
proof=json.loads((accepted/"review.json").read_text(encoding="utf-8"))
assert proof["passed"] and proof["source_unchanged"]
baseline=json.loads((HERE/"followups-r12/coordinator-shared-r13-baseline.json").read_text(encoding="utf-8"))
branch=ROOT/".coordination/20261014/workspaces/coordinator-shared-r13"
out=ROOT/"artifacts/intake-coordinator-source-roots-r13-20261015"
out.mkdir(exist_ok=False)
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for name,sha in proof["changed_files"].items():
    target=ROOT/name
    assert (hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None)==baseline["files"].get(name)
    frozen=accepted/"source-before"/name
    assert hashlib.sha256(frozen.read_bytes()).hexdigest()==sha==hashlib.sha256((branch/name).read_bytes()).hexdigest()
    if target.exists():
        backup=out/"before"/name
        backup.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(target,backup)
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(frozen,target)
receipt={"at":at,"task_id":"coordinator/shared-source-root-r13","coordinator_authored":True,"coordinator_validation_passed":True,"independent_worker_acceptance":False,"accepted_files":proof["changed_files"],"verification_evidence":str((accepted/"review.json").relative_to(ROOT)).replace("\\","/"),"junit":proof["junit"],"integrated":True,"joint_verification":False,"whole_package_complete":False,"scope":proof["scope"]}
(out/"receipt.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
ledger_path=HERE/"tasks.json"
ledger=json.loads(ledger_path.read_text(encoding="utf-8"))
assert "COORD-SOURCE-ROOT-R13" not in {row["id"] for row in ledger["tasks"]}
ledger["tasks"].append({"id":"COORD-SOURCE-ROOT-R13","title":"Native source-root query namespace repair","owner":"coordinator","depends_on":["CURRENT-JOINT-R13"],"packages":["S01"],"write_paths":list(proof["changed_files"]),"status":"coordinator_validated_intaken_joint_pending","actual_execution_at":proof["commands"][0]["started_at"],"artifact_available":True,"independent_acceptance":False,"coordinator_validation":True,"integrated":True,"integrated_at":at,"intake_evidence":str((out/"receipt.json").relative_to(ROOT)).replace("\\","/"),"joint_verification":False,"whole_package_complete":False})
ledger["updated_at"]=at
ledger["current_accepted_stage"]["current_root_status"]="shared source-root repair intaken; current joint pending; previous R13 receipt historical"
left={row["id"] for row in ledger["tasks"]};done=set();layers=[]
while left:
    ready=[row["id"] for row in ledger["tasks"] if row["id"] in left and set(row["depends_on"])<=done]
    assert ready
    layers.append(ready);left.difference_update(ready);done.update(ready)
ledger["topological_layers"]=layers
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
doc=ROOT/"docs/modules/retrieval-backends.md"
text=doc.read_text(encoding="utf-8")
text=text.replace("tests:\n","tests:\n  - tests/test_native_source_roots.py\n",1)
text+="\n### Native 源码根与导航路径\n\nClang 精确构建事实使用提取器的 `source_root` 相对路径；`CodeIndex` 的构建列表、函数构建归属、program facts 和 compilation facts 查询先解析真实文件，再转换到该命名空间。导航输出仍按项目根目录表示。源码根是项目子目录时，项目相对路径、源码相对路径与绝对路径可查询同一真实实例；另一个同名文件和源码根外路径不能退化为 basename 匹配。`tests/test_native_source_roots.py` 使用真实 native 双编译变体与 ALT 独有 double_free 候选核对此边界，不代表完整 ScanSession、全消费者或真实项目效果验收。\n"
doc.write_text(text,encoding="utf-8",newline="\n")
print(json.dumps({"intake":str(out/"receipt.json"),"source_files":len(proof["changed_files"]),"joint_pending":True}))
