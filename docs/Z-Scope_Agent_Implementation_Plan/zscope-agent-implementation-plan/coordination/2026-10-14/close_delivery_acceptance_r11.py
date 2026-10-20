"""Link immutable intake events to the final current-root joint receipt."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
relative="artifacts/coordinator-r11-all-intaken-20261015/review.json"
joint=json.loads((ROOT/relative).read_text(encoding="utf-8"))
assert joint["passed"]==1123 and joint["quality_commands_passed"]==6 and joint["skipped"]==0
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for label in ("intake-s01-symbol-r11-20261015","intake-mcp-r11-20261015","intake-astra-ux-r10-20261015"):
    out=ROOT/"artifacts"/label
    intake=json.loads((out/"receipt.json").read_text(encoding="utf-8"))
    matches={row["path"]:hashlib.sha256((ROOT/row["path"]).read_bytes()).hexdigest()==row["after"] for row in intake["files"]}
    assert all(matches.values())
    proof={"verified_at":at,"intake_event":"receipt.json","task_id":intake["task_id"],
           "independent_acceptance":True,"integrated":True,"joint_verification":True,
           "joint_receipt":relative,"joint_finished_at":joint["finished_at"],
           "joint_result":{"passed":1123,"failed":0,"errors":0,"skipped":0,"commands":6},
           "accepted_owned_bytes_match_current_root":matches,"whole_package_complete":False}
    (out/"joint-receipt.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"continuation-r6.json"
stage=json.loads(path.read_text(encoding="utf-8"))
ledger_path=HERE/"tasks.json"
ledger=json.loads(ledger_path.read_text(encoding="utf-8"))
rows={row["id"]:row for row in ledger["tasks"]}
ledger["reserved"].update(current_status="user_confirmed_completed_archived",action="do_not_query_restore_dispatch_resume_or_duplicate_historical_session")
rows["RESERVED-CALLER-WAKE"].update(status="user_confirmed_completed_archived_reserved_do_not_touch",
                                    confirmation_basis="Original human handoff states S06-R02 completed and archived; not queried in this run.",
                                    new_independent_acceptance_claim=False)
rows["S06-ASYNC"].update(status="queued_dependency_existing_archived_slice_preserved",
                        blocking_basis="Broader S04/S01-link prerequisites and unsupported async scope; archived S06-R02 is not an external wait.")
ledger["updated_at"]=at
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage.update(updated_at=at,active_phase="R11 delivery acceptance/intake/joint handled; full packages remain open",
             current_joint="artifacts/coordinator-r11-all-intaken-20261015",current_joint_status="passed_current_all_intaken_bounded_slices",
             current_joint_result={"passed":1123,"failed":0,"errors":0,"skipped":0,"quality_commands_passed":6},
             last_verified_root_joint=joint["source_evidence"],
             next_task_rows=[rows[name] for name in ("S01-SYMBOL","U01-MCP-JOBS","ASTRA-UX-R10")])
path.write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
status_path=HERE/"followups-r10/status-r11.json"
status=json.loads(status_path.read_text(encoding="utf-8"))
status.update(at=at,delivery_acceptance_phase="handled",tasks=[rows[name] for name in ("S01-SYMBOL","U01-MCP-JOBS","ASTRA-UX-R10")])
status_path.write_text(json.dumps(status,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
source=json.loads((ROOT/"artifacts/coordinator-r11-all-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))
assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in source["after"].items())
proof={"at":at,"phase":"R11 delivery acceptance handled","final_joint":relative,
       "root_source_unchanged_after_bookkeeping":True,"bound_input_files":len(source["after"]),
       "remaining":["Complete ScanSession precise-instance and durable queue/checkpoint/remaining wiring",
                    "Native callee-USR contract propagation and validation thread context",
                    "Broader graph/link consumers and accurate served/blocked diagnostics",
                    "MCP findings projection and full U01/UX dependencies",
                    "Real-project/model effects, formal/portable evidence and conditional S10/Q scope"],
       "old_s06":"Human-confirmed archived; not queried/restored/dispatched","whole_packages_complete":False}
(ROOT/"artifacts/coordinator-r11-all-intaken-20261015/closure.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(proof))
