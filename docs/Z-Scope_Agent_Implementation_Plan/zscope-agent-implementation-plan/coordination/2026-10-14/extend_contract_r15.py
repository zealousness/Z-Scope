"""Transfer only concrete protocol producer/consumer fixes; retain original baseline."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
names=["zscope/core/candidates/cpp_domains/lifecycle_paths.py","zscope/core/candidates/cpp_domains/retained_slots.py","zscope/semantics/single_slot_pool.py","zscope/semantics/refcount_protocols.py","zscope/semantics/handle_protocols.py"]
baseline=json.loads((HERE/"followups-r12/contract-validation-r12-baseline.json").read_text(encoding="utf-8"))
original={row["path"]:row["sha256"] for row in baseline["files"]}
branch=ROOT/".coordination/20261014/workspaces/contract-validation-r12"
ledger_path=HERE/"tasks.json"
ledger=json.loads(ledger_path.read_text(encoding="utf-8"))
active=[r for r in ledger["tasks"] if r.get("bridge_task_id")=="task_2ba352c7a1" or r["id"]=="ASTRA-JOB-PROJECTION-R15"]
assert all(not set(names)&set(r.get("write_paths",[])) for r in active)
for name in names:
    assert hashlib.sha256((branch/name).read_bytes()).hexdigest()==original[name]
    assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==original[name]
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
out=HERE/"followups-r12/contract-validation-r12-ownership-extension.json"
assert not out.exists()
extension={"at":at,"coordinator_authorized":True,"write_paths":names,"previous_sha256":{name:original[name] for name in names},"reason":"Actual native compile/publication/reload to LifecyclePaths consumer accepts unknown/foreign contract USRs; protocol checkers also omit actual owner USR. Explicit single writer transfer; original baseline retained.","evidence":"artifacts/coordinator-contract-r12-final2-published-protocol-20261015/review.json","shared_root_integration_owner":"coordinator","original_baseline_preserved":True}
out.write_text(json.dumps(extension,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
row=next(r for r in ledger["tasks"] if r["id"]=="CONTRACT-VALIDATION-R12")
row["write_paths"]=list(dict.fromkeys(row["write_paths"]+names))
row["owns"]=row["write_paths"]
row["ownership_extension"]=out.relative_to(HERE).as_posix()
ledger["updated_at"]=at
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"transferred":names,"at":at}))
