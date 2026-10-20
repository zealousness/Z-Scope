"""Record R10 independent failures, accepted Astra intake and pending current joint."""
from pathlib import Path
import datetime as dt
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
rows={row["id"]:row for row in ledger["tasks"]}
for identifier, old_task, response_name, evidence in (
    ("S01-SYMBOL","task_9579265ee7","s01-symbol-r10-review1","artifacts/coordinator-s01-symbol-probes-r10-20261015/review.json"),
    ("U01-MCP-JOBS","task_2f3f99db9b","u01-mcp-r10-review1","artifacts/coordinator-mcp-strict-probe-r10-20261015/review.json"),
):
    row=rows[identifier]
    response=json.loads((HERE/"route-check"/("bridge-response-"+response_name+".json")).read_text(encoding="utf-8"))
    assert response["ok"]
    history=row.setdefault("execution_history",[])
    if not any(item.get("task_id")==old_task for item in history):
        history.append({"task_id":old_task,"status":"completed_delivery_independent_acceptance_failed",
                        "review":evidence,"independent_acceptance":False,"integrated":False})
    row.update(bridge_task_id=response["task_id"],bridge_session_id=response["session_id"],
               request_id=response["request_id"],accepted_model=response["model"],observed_model=None,
               status="repair_dispatched_independent_acceptance_pending",independent_acceptance=False,
               integrated=False,joint_verification=False,latest_failed_review=evidence,checked_at=at)
astra=rows["ASTRA-UX-R10"]
intake=json.loads((ROOT/"artifacts/intake-astra-ux-r10-20261015/receipt.json").read_text(encoding="utf-8"))
astra.update(status="independent_passed_integrated_joint_pending",independent_acceptance=True,
             integrated=True,joint_verification=False,checked_at=at,integrated_at=intake["integrated_at"],
             acceptance_evidence="artifacts/coordinator-astra-ux-r10-acceptance2-20261015/review.json",
             intake_evidence="artifacts/intake-astra-ux-r10-20261015/receipt.json",whole_package_complete=False)
ledger["current_accepted_stage"]["current_root_status"]="Astra intake and tool assertion repair changed root; R9 726 historical, R11 joint running"
ledger.update(updated_at=at)
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage={"at":at,"last_verified_root":"artifacts/coordinator-r9-s01-s08-intaken-20261014/review.json",
       "current_root_joint":"artifacts/coordinator-r11-astra-intaken-20261015","current_root_joint_status":"running",
       "tasks":[rows[name] for name in ("S01-SYMBOL","U01-MCP-JOBS","ASTRA-UX-R10")],
       "tool_description":"Baseline and S01 whole36 each35pass1fail, same baseline hashes; coordinator synchronized actual contract and strengthened default-symbol no-body assertion; targeted50pass; full joint pending."}
(HERE/"followups-r10/status-r11.json").write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"""## {at[:19]} +08:00 · R10 independent review and R11 repair

- Original owner80748 retained; task_9579265ee7 completed 10/14 23:28:14 observed K3, task_2f3f99db9b completed 23:12:53 observed GLM5.3. Astra stopped with delivery. All three had only owned changes; public metadata is not independent acceptance. S01 DELIVERY's 07:23 timestamp is inconsistent and not used.
- S01 independent probes: 1 pass / 5 failures / 0 skip, including actual native header edit still authorizing cached callees; missing owner file, alias owner mismatch, incomplete receipt and ignored callee_file also fail. No intake. Frozen failure receipt `artifacts/coordinator-s01-symbol-probes-r10-20261015/review.json`; same-session repair task_0afb819799 accepted.
- MCP independent 257 passed / 0 skip; compileall passed, mypy no-any-return failed provider.py:738. Four additional strict-schema probes fail: explicit null reaches real DB and two scan.run requests launch owners. No intake. Frozen receipts `artifacts/coordinator-mcp-r10-acceptance2-20261015/review.json` and `artifacts/coordinator-mcp-strict-probe-r10-20261015/review.json`; same-session repair task_feb229984d accepted. Missing final DELIVERY is part of feedback.
- Astra independent 88 passed / 0 failed/errors/skipped, compileall/mypy/Black pass, vendor/license read-only lock audit passes with only expected index.html difference. Three frozen owned files intaken 10/15 01:29:51; coordinator updated only index.html lock SHA. Full static verify and current-root joint pending at `artifacts/coordinator-r11-astra-intaken-20261015`. Old726 belongs before these changes.
- Tool description failure proved preexisting: root and delivered S01 full36 each35pass1fail, identical tool/test dispatch-baseline hashes. Evidence `artifacts/coordinator-tool-description-baseline-r10-20261015/review.json`. Coordinator repaired stale assertion to current symbols/text/files contract and strengthened no-body default result; targeted50 pass, full joint retains entire file. No test exclusion/xfail/standard downgrade.
- Full ScanSession/queue/checkpoint and contract-USR wiring remain open. Controlled scanner/report/assumption inputs do not establish real-project effects; formal/portable and conditional extensions remain separate. No old S06 session restored or dispatched.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    destination=HERE/name
    destination.write_text(note+destination.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE/"CHECKPOINT-R11.md").write_text(note,encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"root_joint":"running","repair_tasks":[rows[name]["bridge_task_id"] for name in ("S01-SYMBOL","U01-MCP-JOBS")],"astra":"independent_passed_intaken_joint_pending"}))
