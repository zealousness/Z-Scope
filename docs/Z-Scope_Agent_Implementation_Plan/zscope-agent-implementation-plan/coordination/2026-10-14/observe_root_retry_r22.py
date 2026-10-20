"""Observe the actual R22 run and record its execution, never a test pass."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
label="coordinator-r22-unchanged-union-20261016"
out=ROOT/"artifacts"/label
assert sys.platform=="linux"
processes={}
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit() or int(entry.name)==os.getpid():
        continue
    try:
        raw=(entry/"cmdline").read_bytes().decode("utf-8",errors="replace")
        if "observe_root_retry_r22.py" in raw:
            continue
        status=dict(line.split(":",1) for line in (entry/"status").read_text().splitlines() if ":" in line)
        processes[int(entry.name)]={"parent":int(status["PPid"]),"raw":raw,"state":status["State"].strip(),"executable":(entry/"comm").read_text().strip()}
    except (OSError,ValueError,KeyError):
        continue
selected={pid for pid,row in processes.items() if label in row["raw"] and ("verify_current_root_r22.py" in row["raw"] or "verify_joint_retry_with_clock_r22.py" in row["raw"])}
while True:
    children={pid for pid,row in processes.items() if row["parent"] in selected}
    if children<=selected:
        break
    selected|=children
safe=[{"pid":pid,**{k:processes[pid][k] for k in ("parent","state","executable")}} for pid in sorted(selected)]
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
receipt={"at":at,"processes":safe,"scope":"Current R22 coordinator descendants only; no argv/env or unrelated worker details"}
target=out/("process-observation-"+at.replace(":","").replace("+","_")+".json")
assert out.is_dir()
target.write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
row=next(r for r in ledger["tasks"] if r["id"]=="CURRENT-JOINT-R22")
if row["status"].startswith("one_full_"):
    assert safe and (out/"command-0.log").exists()
    row.update(status="actual_full_unchanged_product_retry_running_quality_pending",execution_observed_at=at,artifact_available=True,execution_evidence=target.relative_to(ROOT).as_posix(),checked_at=at)
    ledger["updated_at"]=at
    path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    path=HERE/"continuation-r6.json"
    continuation=json.loads(path.read_text(encoding="utf-8"))
    continuation.update(updated_at=at,current_joint=out.relative_to(ROOT).as_posix(),current_joint_status=row["status"],active_phase="R22 full unchanged-product retry after explicit parallel/serial probe; original timing assertion retained; no new implementation dispatch")
    path.write_text(json.dumps(continuation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(receipt),flush=True)
