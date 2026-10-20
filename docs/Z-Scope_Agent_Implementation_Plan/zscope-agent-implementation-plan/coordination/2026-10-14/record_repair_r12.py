"""Append distinct repair attempts and preserve rejected producer receipts."""
from pathlib import Path
import datetime as dt
import json
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
notes=[]
for kind in sys.argv[1:]:
    identity,label,proof_label={
        "contract":("CONTRACT-VALIDATION-R12","contract-validation-r12-repair","coordinator-contract-r12-final-boundary-20261015"),
        "mcp":("MCP-FINDINGS-R12","mcp-findings-r12-repair","coordinator-mcp-findings-r12-boundary-probes-20261015"),
        "main":("SCAN-SESSION-R12","scan-session-r12-repair","coordinator-scan-session-r12-native-owner-probes-20261015"),
        "contract_regressions":("CONTRACT-VALIDATION-R12","contract-validation-r12-regressions","coordinator-contract-r12-producer-regression-observation-20261015"),
        "main_r3":("SCAN-SESSION-R12","scan-session-r12-r3","coordinator-scan-session-r12-r2-refreshed-final-probes-20261015"),
        "contract_protocol":("CONTRACT-VALIDATION-R12","contract-validation-r12-protocol","coordinator-contract-r12-final2-published-protocol-20261015"),
        "contract_omission":("CONTRACT-VALIDATION-R12","contract-validation-r12-omission","coordinator-contract-r12-r3-omission-probes-20261015"),
    }[kind]
    row=next(row for row in ledger["tasks"] if row["id"]==identity)
    dispatch=json.loads((HERE/"route-check"/("bridge-response-"+label+".json")).read_text(encoding="utf-8"))
    assert dispatch["ok"] and dispatch["session_id"]==row["bridge_session_id"]
    assert dispatch["task_id"]!=row["bridge_task_id"]
    proof=json.loads((ROOT/"artifacts"/proof_label/"review.json").read_text(encoding="utf-8"))
    assert proof["returncode"]!=0
    prior={key:row.get(key) for key in ("bridge_task_id","actual_execution_at","bridge_finished_at","observed_model","producer_bridge_status","dispatch_evidence","request_id")}
    prior.update(independent_diagnostic=proof_label+"/review.json",diagnostic_junit=proof["junit"],independent_acceptance=False,source_inputs=len(proof["before"]))
    if kind=="contract_regressions":
        prior.update(observation_kind="producer_junit_not_independent_execution",exact_byte_regression_revalidation="pending")
    row.setdefault("execution_history",[]).append(prior)
    row.update(bridge_task_id=dispatch["task_id"],request_id=dispatch["request_id"],dispatch_evidence="route-check/bridge-response-"+label+".json",status="repair_dispatched_after_failed_independent_probe",checked_at=at,observed_model=None,producer_bridge_status="dispatch_accepted",source_artifacts_available=True,artifact_available=False,independent_acceptance=False,integrated=False,joint_verification=False)
    row.pop("bridge_finished_at",None)
    row.pop("actual_execution_at",None)
    nature="producer-observed (not independent execution)" if kind=="contract_regressions" else "independent diagnostic"
    notes.append(f'- {identity}: {dispatch["task_id"]}, same session/model, {proof["junit"]["tests"]} {nature} tests/{proof["junit"]["failures"]} failures; stable {len(proof["before"])} frozen inputs. Evidence artifacts/{proof_label}/review.json. Prior delivery/self-checks retained; no intake or full-package completion.')
ledger["updated_at"]=at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
accepted=ledger["current_accepted_stage"]
note=f"## {at} · Independent boundary failures; same-session repairs\n\n"+"\n".join(notes)+f"\n\nCurrent accepted root evidence: {accepted['source_evidence']}; {accepted['passed']} passed/0fail/error/skip. Counts are separate from diagnostics. No rejected backend bytes intaken. Original Bridge owner80748 and isolated ownership retained. Old S06 remains archived.\n\n---\n\n"
for name in ("PROGRESS.md","DAG.md"):
    target=HERE/name
    target.write_text(note+target.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"records":notes}))
