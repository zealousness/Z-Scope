"""Persist current acceptance gates and active task IDs without changing product bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
tz=dt.timezone(dt.timedelta(hours=8));at=dt.datetime.now(tz).isoformat()
root=json.loads((ROOT/"artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))
assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==sha for p,sha in root["after"].items())
p=HERE/"tasks.json";ledger=json.loads(p.read_text(encoding="utf-8"));rows={r["id"]:r for r in ledger["tasks"]}
for identity,label in (("SCAN-SESSION-R12","kimi"),("SCAN-CHECKPOINT-R17","kimi_checkpoint"),("CONTRACT-VALIDATION-R12","zcode"),("MCP-FINDINGS-R12","mcp")):
    row=rows[identity]
    public=max((HERE/"route-check").glob(f"bridge-response-r12-current-{label}-*.json"),key=lambda f:f.stat().st_mtime_ns)
    data=json.loads(public.read_text(encoding="utf-8"));assert data["ok"] and data["task_id"]==row["bridge_task_id"]
    row.update(producer_bridge_status=data["status"],actual_execution_at=data["started_at"],bridge_finished_at=data["finished_at"],observed_model=data["observed_model"],execution_evidence=public.relative_to(ROOT).as_posix(),checked_at=at)
    if identity in {"SCAN-CHECKPOINT-R17","CONTRACT-VALIDATION-R12"} and data["status"]=="running":
        row["status"]="actual_execution_observed_independent_acceptance_pending"
api_path=ROOT/"artifacts/coordinator-bound-events-r17-same-bytes-20261015/review.json"
api=json.loads(api_path.read_text(encoding="utf-8"));assert api["coordinator_validation_passed"]
prior=json.loads((ROOT/"artifacts/coordinator-bound-events-r17-20261015/review.json").read_text(encoding="utf-8"))
assert api["before"]==prior["after"] and api["source_unchanged"]
timeline=json.loads((ROOT/"artifacts/coordinator-bound-events-r17-20261015/deadline-timeline.json").read_text(encoding="utf-8"))
backward=[(a["seq"],b["seq"],b["epoch"]-a["epoch"]) for a,b in zip(timeline["events"],timeline["events"][1:]) if b["epoch"]<a["epoch"]]
clock=json.loads((api_path.parent/"clock-observations.json").read_text(encoding="utf-8"))
review={"at":at,"same_product_and_test_inputs":True,"prior_result":prior["junit"],"retry_result":api["junit"],"backward_sql_event_timestamps":backward,"clock_changes_during_passing_retry":clock["clock_changes"],"clock_problem_resolved":False,"test_parameters_or_timeouts_changed":False,"product_fix_from_clock_failure":False,"scope":"Absolute wall-clock deadline had not been reached in the retained failure despite the test's relative sleep assumption. Same-byte full retry and all quality checks passed; original failure remains. No runtime clock changes and no formal timing or real-project effect acceptance."}
clock_path=ROOT/"artifacts/coordinator-bound-events-r17-clock-review-20261015.json"
assert not clock_path.exists();clock_path.write_text(json.dumps(review,indent=2)+"\n",encoding="utf-8",newline="\n")
rows["COORD-BOUND-EVENTS-R17"].update(clock_review=clock_path.relative_to(ROOT).as_posix(),coordinator_validation=True,independent_acceptance=False,integrated=False,joint_verification=False,whole_package_complete=False)
ledger["updated_at"]=at
p.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
p=HERE/"continuation-r6.json";d=json.loads(p.read_text(encoding="utf-8"))
d.update(updated_at=at,current_round={key:{"task_id":rows[key].get("bridge_task_id"),"status":rows[key]["status"]} for key in ("SCAN-SESSION-R12","SCAN-CHECKPOINT-R17","CONTRACT-VALIDATION-R12","MCP-FINDINGS-R12")},active_phase="RootR16 current; MainR3 independent423 waiting contract; API195 coordinator validated; Kimi checkpointR17 and ZCode omissionR4 executing",whole_packages_complete=False)
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"""## {at} · Current R16 green; dependency-based R17 work executing

- Root remains exact R16:1207/0failure/error/skip,81testfiles,six commands0,1009current hashes. Actual finish04:31:42,verified14:29:59. Final artifacts/coordinator-r16-astra-projection-intaken-20261015/review.json. Astra R15 independent89/intaken/currentjoint passed; all complete-package flags remain false.
- Main ScanSession task_2ba352c7a1: ended04:18:25,observedK3. Coordinator readonly Java/C++ resume test migration64/0 plus4commands0 at14:41:55; full independent423/0 plus4commands0 and1008stable inputs at14:51:13, artifacts/coordinator-scan-session-r12-r3-acceptance-20261015/review.json. Not intaken: waits contractR4 and combined joint. No count summation or fullS01/S08 claim.
- Contract task_07fdfa490a: ended04:32:47/DELIVERY04:38,observedGLM5.3,self943pass but independent16/3fail at14:35:20. Evidence artifacts/coordinator-contract-r12-r3-omission-probes-20261015/review.json:omitted unknown USR can borrow pinned contract, including actualnative mixed overload with only one published record. Extra retention file violation retained in original-audit and prospective ownership decision; no unaccepted bytes intaken. Same-session repair task_04ef519648 started14:36:47, actually executing, no new independent acceptance.
- COORD-BOUND-EVENTS-R17: coordinator-authored/validated,not independent-worker acceptance. ActualSQL/service resume,foreign/currentowner/input/plan/path/log/checkpoint and atomic handoff tests. Initial20 targeted passed; initial broad195 had194pass/1clock-sensitive deadline failure. SQL timeline has backwards wall-clock events before the absolute deadline. Exact same1010input bytes full retry195/0 plus4commands0 at15:06:44; read-only sampler still observedclock corrections. Originalfailures and clock review retained; no code/test/timeout or hostclock adjustment. API not root-intaken; scanner use remains separate.
- Kimi new task_c0099a15bb,SCAN-CHECKPOINT-R17,started15:23:04,actualexecution observed; requestedK3/observedmodel pending. Fresh1013-inputscan-checkpoint-r17 workspace overlays acceptedMainR3+readonlytestmigration+validatedAPI only. ZCode active version not copied. Six writable files,sharedstore/owner/queue/Runner/contracts/UI/native/docs readonly. Oldproducer directories remain frozen. Current root not changed; parent integration/joint gates remain.
- OriginalBridgeowner80748 retained,no duplicate service or oldS06 operation. Root integration is batched after necessary independent gates. Remaining fullinstance durable recovery,semantic/SVF/link consumers,U01 config/entrypoint consumers and allrealproject/model/formal/portable effects stay separate. WSL runtime rechecked at14:56:43; receipt artifacts/coordinator-runtime-r17-20261015.json; nativeSHAunchanged,threeLLM envflagsfalse; no real-model readiness claim. S10/Q conditional extensions not expanded.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    p=HERE/name;p.write_text(note+p.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE/"CHECKPOINT-R17-PHASE.md").write_text(note,encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"root_current":True,"main_independent_passed":423,"api_coordinator_validated":195,"active_tasks":[rows[key]["bridge_task_id"] for key in ("SCAN-CHECKPOINT-R17","CONTRACT-VALIDATION-R12")]}))
