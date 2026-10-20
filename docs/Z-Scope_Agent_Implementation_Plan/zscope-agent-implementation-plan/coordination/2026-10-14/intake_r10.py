"""Intake only independently accepted immutable R10 owned bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys
from audit_followup_r10 import audit, ROOT, HERE

workspace_name, acceptance, output = sys.argv[1:4]
receipt_path=ROOT/"artifacts"/acceptance/"review.json"
receipt=json.loads(receipt_path.read_text(encoding="utf-8"))
assert receipt["independent_acceptance_passed"] and receipt["source_unchanged"]
ownership=audit(workspace_name)
assert not ownership["nonowned_changes"] and ownership["delivery_exists"]
branch=ROOT/".coordination/20261014/workspaces"/workspace_name
source=receipt_path.parent/"source-before"
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
for row in ownership["changes"]:
    assert row["owned"] and row["after"]==receipt["after_hashes"][row["path"]]
    assert sha(source/row["path"])==row["after"]
    assert sha(ROOT/row["path"])==row["before"],row["path"]
out=ROOT/"artifacts"/output
out.mkdir(exist_ok=False)
(out/"ownership-before.json").write_text(json.dumps(ownership,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
for row in ownership["changes"]:
    target=ROOT/row["path"]
    if target.exists():
        saved=out/"before"/row["path"]
        saved.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(target,saved)
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source/row["path"],target)
    assert sha(target)==row["after"]
proof={"task":ownership["task"],"task_id":receipt["task_id"],"accepted_receipt":str(receipt_path),
       "integrated_at":dt.datetime.now(dt.timezone.utc).isoformat(),"intake_source":str(source),
       "files":ownership["changes"],"all_bytes_verified":True,"independent_acceptance":True,
       "joint_verification":"pending current root","whole_package_complete":False}
(out/"receipt.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"task":proof["task"],"files":len(proof["files"]),"integrated_at":proof["integrated_at"],"receipt":str(out/"receipt.json")}))
