"""Record dispatch and actual public execution, separately from acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
FOLLOWUPS = HERE / "followups-r10"
prepared = json.loads((FOLLOWUPS / "prepared.json").read_text(encoding="utf-8"))
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
rows = {row["id"]:row for row in ledger["tasks"]}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for task in prepared["tasks"]:
    if task["id"] not in rows:
        row = {"id":task["id"],"packages":["U01","S08"] if task["agent"]=="zcode" else ["U01","U02"],
               "title":task["id"],"depends_on":["CURRENT-JOINT-R9"],"whole_package_complete":False}
        ledger["tasks"].append(row)
        rows[row["id"]] = row
    row = rows[task["id"]]
    if "CURRENT-JOINT-R9" not in row["depends_on"]:
        row["depends_on"].append("CURRENT-JOINT-R9")
    row.update(owner=task["agent"],requested_model=task["model"],isolated_workspace=task["isolated_workspace"],
               write_paths=task["owns"],baseline_receipt=f"followups-r10/{task['workspace']}-baseline.json",
               status="dispatched_execution_pending",checked_at=at,independent_acceptance=False,
               integrated=False,joint_verification=False,whole_package_complete=False)
    if task["agent"] == "Astra":
        row.update(agent_kind="native_subagent",agent_task_id="/root/astra_v3_editor_r6",
                   requested_at="2026-10-14T23:04:34+08:00",execution_evidence="await native agent progress/delivery")
        continue
    response_path = HERE / "route-check" / ("bridge-response-"+task["workspace"]+".json")
    response = json.loads(response_path.read_text(encoding="utf-8"))
    assert response["ok"] and response["persisted"] and not response["reused"]
    row.update(agent_kind="agent_bridge",bridge_task_id=response["task_id"],bridge_session_id=response["session_id"],
               accepted_model=response["model"],request_id=response["request_id"],dispatch_evidence=str(response_path.relative_to(HERE)))
    statuses = []
    for p in (HERE/"route-check").glob("bridge-response-r10-current-*.json"):
        value = json.loads(p.read_text(encoding="utf-8"))
        if value.get("task_id") == response["task_id"]:
            statuses.append((p.stat().st_mtime,p,value))
    if statuses:
        _, status_path, status = max(statuses,key=lambda item:item[0])
        row.update(status="actual_execution_running" if status["status"]=="running" else status["status"],
                   actual_execution_at=status.get("started_at"),observed_model=status.get("observed_model"),
                   execution_evidence=str(status_path.relative_to(HERE)))
remaining, done, layers = set(rows), set(), []
while remaining:
    ready = [row["id"] for row in ledger["tasks"] if row["id"] in remaining and set(row["depends_on"])<=done]
    assert ready
    layers.append(ready); remaining.difference_update(ready); done.update(ready)
ledger.update(updated_at=at,topological_layers=layers)
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
snapshot = {"at":at,"root_joint":"artifacts/coordinator-r9-s01-s08-intaken-20261014/review.json",
            "root_result":{"passed":726,"failed":0,"skipped":0,"commands":6,"input_files":996},
            "tasks":[rows[task["id"]] for task in prepared["tasks"]],
            "scope":"Dispatched/actual execution only. No R10 source intaken or independently accepted.",
            "blocking":"Full ScanSession/queue/checkpoint/consumer migration pending; real model/project/formal/portable and conditional extensions separate."}
(FOLLOWUPS/"status.json").write_text(json.dumps(snapshot,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note = f"""## {at[:19]} +08:00 · R10 live execution, current root R9 remains accepted

- Current root finished 23:03:39: 726 passed / 0 failed/errors/skipped; 43 test files, six commands exit0, 996 current stable inputs. Receipt `artifacts/coordinator-r9-s01-s08-intaken-20261014/review.json`. S01 312 and S08 170 independent counts are separate, not summed. S01 worker task cancelled; only coordinator-repaired, independently tested source was intaken 22:56:34. S08 intaken 22:37:41.
- S01-SYMBOL Kimi `task_9579265ee7`, same session `sess_261a55289f`, started 23:04:34; actual tool activity observed. U01-MCP-JOBS ZCode `task_2f3f99db9b`, same U01 session `sess_a0adb99b15`, started 23:04:34; actual tool activity observed. Accepted pinned models K3/GLM5.3; observed final models still unavailable. Astra native `/root/astra_v3_editor_r6` continued as ASTRA-UX-R10; execution/delivery evidence pending. None independently accepted/intaken/jointly verified yet.
- Three disjoint copies `{', '.join(task['workspace'] for task in prepared['tasks'])}` derive from the same 996-file snapshot. Ownership and strict Linux/native/browser commands: `followups-r10/*-baseline.json`; task/status receipts `followups-r10/status.json`. Original Bridge owner80748 reused; fresh public coordinator policy/session check found no active owned session before dispatch; six other live instances were reported, not restarted or interfered with. No old S06 session queried/restored.
- Coordinator shared ScanSession/ParallelAnalyzer/CLI/Web/docs/static locks remain exclusive for later integration. Main blockers: ordinary scanner still calls old entry path/global modeling and does not consume persistent session scheduler; full S01 symbols/contracts and MCP persistent job migration now executing. U01 profile conflict dependencies, downstream S02-S07 and full UX remain open; real project/model effects, formal/portable evidence and S10/Q conditions are separate.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    path=HERE/name
    path.write_text(note+path.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE/"CHECKPOINT-R10.md").write_text(note,encoding="utf-8",newline="\n")
source=json.loads((ROOT/"artifacts/coordinator-r9-s01-s08-intaken-20261014/source-evidence.json").read_text(encoding="utf-8"))
assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in source["after"].items())
print(json.dumps({"at":at,"tasks":len(rows),"layers":len(layers),"current_root_unchanged":True,
                  "next":[{k:rows[task['id']].get(k) for k in ('id','bridge_task_id','agent_task_id','status')} for task in prepared['tasks']]}))
