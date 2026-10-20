"""Record execution separately from independent acceptance and current root joint."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
tz=dt.timezone(dt.timedelta(hours=8))
at=dt.datetime.now(tz).isoformat()
source=json.loads((ROOT/"artifacts/coordinator-r15-mcp-queue-web-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))
assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in source["after"].items())
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
rows={r["id"]:r for r in ledger["tasks"]}
public=[]
for pattern in ("bridge-response-r12-current-kimi-*.json","bridge-response-r12-current-zcode-*.json","bridge-response-r12-current-mcp-*.json"):
    p=max((HERE/"route-check").glob(pattern),key=lambda p:p.stat().st_mtime_ns)
    data=json.loads(p.read_text(encoding="utf-8"));assert data["ok"]
    public.append({"path":p.relative_to(ROOT).as_posix(),"data":{k:data.get(k) for k in ("task_id","session_id","status","model","observed_model","started_at","finished_at","failure","warnings")}})
for identity in ("SCAN-SESSION-R12","CONTRACT-VALIDATION-R12","MCP-FINDINGS-R12"):
    row=rows[identity]
    observed=next(item for item in public if item["data"]["task_id"]==row["bridge_task_id"])
    data=observed["data"]
    assert data["session_id"]==row["bridge_session_id"] and data["model"]==row["requested_model"]
    row.update(producer_bridge_status=data["status"],actual_execution_at=data["started_at"],bridge_finished_at=data["finished_at"],observed_model=data["observed_model"],execution_evidence=observed["path"],checked_at=at)
    if not row.get("integrated"):
        row["status"]="repair_executing" if data["status"]=="running" else "producer_ended_independent_acceptance_pending"
    for prior in row.get("execution_history",[]):
        known={"task_658717aaa6":("2026-10-14T19:47:00.097027+00:00","volceapi/kimi-k3"),"task_2d639b45b8":("2026-10-14T19:55:52.767530+00:00","97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3")}.get(prior.get("bridge_task_id"))
        if known:
            prior.update(bridge_finished_at=known[0],observed_model=known[1],producer_bridge_status="completed")
rows["ASTRA-JOB-PROJECTION-R15"].update(status="actual_execution_observed",execution_observed_at=at,execution_evidence="followups-r12/astra-r15-execution.json")
astra={"at":at,"agent_task_id":"/root/astra_v3_editor_r6","round_id":"ASTRA-JOB-PROJECTION-R15","status":"actual_execution_observed","native_agent_report":"Read R15 snapshot and shared projection source. Investigating openJobResult response-binding checks and invalidation of displayed acceptance results on run/input changes. Actual HTTP/owner/resume reproduction pending; scanner/report synthetic.","independent_acceptance":False,"integrated":False,"whole_package_complete":False}
(HERE/"followups-r12/astra-r15-execution.json").write_text(json.dumps(astra,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
setup={"at":at,"classification":"retained diagnostic setup limitations; not accepted failures of delivered product","records":[{"artifact":"artifacts/coordinator-scan-session-r12-r2-refreshed-probes-20261015/review.json","reason":"Dependency refresh overlapped frozen snapshot; producer_current_matches_frozen=false. Superseded by stable final probe,8tests/2actualfailures."},{"artifact":"artifacts/coordinator-contract-r12-final2-boundary-20261015/protocol-results.xml","reason":"Manual supplemental invocation omitted native environment;2skipped, not acceptance. Full launcher subsequently set actual native tool and ran no-skip collection."},{"artifact":"artifacts/coordinator-contract-r12-final2-protocol-boundary-20261015/review.json","reason":"Legacy checker-direct positive fixture lacks published USR; failed before negative assertions. Corrected to actualcompile→publish→workbook reload. Valid new published-protocol collection13/2fail, positiveassertionspass."}],"valid_main_diagnostic":"artifacts/coordinator-scan-session-r12-r2-refreshed-final-probes-20261015/review.json","valid_contract_diagnostic":"artifacts/coordinator-contract-r12-final2-published-protocol-20261015/review.json"}
(HERE/"followups-r12/r15-probe-setup-review.json").write_text(json.dumps(setup,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
left,done,layers=set(rows),set(),[]
while left:
    ready=[r["id"] for r in ledger["tasks"] if r["id"] in left and set(r["depends_on"])<=done];assert ready
    layers.append(ready);left.difference_update(ready);done.update(ready)
ledger.update(updated_at=at,topological_layers=layers)
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
continuation_path=HERE/"continuation-r6.json"
continuation=json.loads(continuation_path.read_text(encoding="utf-8"))
continuation.update(updated_at=at,current_round={key:{"task_id":rows[key].get("bridge_task_id",rows[key].get("agent_task_id")),"status":rows[key]["status"]} for key in ("SCAN-SESSION-R12","CONTRACT-VALIDATION-R12","MCP-FINDINGS-R12","ASTRA-JOB-PROJECTION-R15")},current_root_status="R15 1206 passed/6commands0/current1009 bytes; Kimi/ZCode repairs and Astra new UI work isolated, not intaken")
continuation_path.write_text(json.dumps(continuation,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"""## {at} · R15 green; isolated next round actually executing

- Current root remains exact R15 bytes:1206/0failure/error/skip,81testfiles,six commands0,1009hashes current. Finished03:57:29; artifacts/coordinator-r15-mcp-queue-web-intaken-20261015/review.json. No Kimi/contract/Astra new bytes intaken.
- Kimi task_2ba352c7a1 started04:04:15, requested K3/current observation pending final model evidence. Same session/directory,5ownedfiles;8accepted readonlydependencies refreshed only after quiescence. Prior task_658717aaa6 independent8probe/2fail at04:03:01:batchresume name-only report and foreign owner deleting legitimate queue. Valid evidence artifacts/coordinator-scan-session-r12-r2-refreshed-final-probes-20261015/review.json. New real-owner deadline probe prepared for next frozen verification; not yet run or counted.
- ZCode task_07fdfa490a started04:08:13, requestedGLM5.3/current observation pending final. Prior task_2d639b45b8 self892/0 and independent11boundarypassed, but actualnative compile/publication/workbook→LifecyclePaths consumer accepts unknown/foreignUSR:13probe/2fail at04:06:11, artifacts/coordinator-contract-r12-final2-published-protocol-20261015/review.json. Five specific protocol producer/consumer files transferred to this single writer by ownership-extension receipt; originalbaseline preserved. No intake.
- Astra /root/astra_v3_editor_r6, new ASTRA-JOB-PROJECTION-R15, independent1009-inputsnapshot, actualsource review observed. Reproduce responsebinding and displayed-result invalidation over actualHTTP/owner/resume; scanner/report synthetic. UI-onlyownership, vendor/license/lock read-only. No new acceptance or intake.
- Shared root integration/independentacceptance remain coordinator-owned; no overlapping write paths, originalBridgeowner80748 retained. Kimi/contract delivery and native/owner/USR regression are actual gates; durable per-instance cross-run recovery and remaining S01 consumers remain unaccepted. No realproject/model/formal/portable effects; three LLM environment variables absent in verified WSL environment. S10/Q conditionalextensions separate; oldS06 archived untouched.
- Setup-only/mixedsnapshot/omittednativeenv observations are explicitly classified in followups-r12/r15-probe-setup-review.json and never counted as acceptance. All validfailures preserved and same-session repairs use no approval/model bypass.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    p=HERE/name;p.write_text(note+p.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE/"CHECKPOINT-R15-ONGOING.md").write_text(note,encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"root_current":True,"round":continuation["current_round"]},ensure_ascii=False))
