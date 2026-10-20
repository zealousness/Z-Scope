"""Mark exact accepted intakes and explicitly invalidate prior current-root claims."""
from pathlib import Path
import datetime as dt
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
rows={row["id"]:row for row in ledger["tasks"]}
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for identifier, acceptance, intake, model, finished in (
    ("S01-SYMBOL","coordinator-s01-symbol-r11-acceptance-20261015","intake-s01-symbol-r11-20261015","volceapi/kimi-k3","2026-10-15T01:44:30.851322+08:00"),
    ("U01-MCP-JOBS","coordinator-mcp-r11-acceptance-20261015","intake-mcp-r11-20261015","97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3","2026-10-15T01:43:29.819824+08:00"),
):
    review=json.loads((ROOT/"artifacts"/acceptance/"review.json").read_text(encoding="utf-8"))
    receipt=json.loads((ROOT/"artifacts"/intake/"receipt.json").read_text(encoding="utf-8"))
    assert review["independent_acceptance_passed"] and review["source_unchanged"] and receipt["all_bytes_verified"]
    rows[identifier].update(status="independent_passed_integrated_bounded_slice_joint_pending",producer_status="completed",
                            observed_model=model,worker_finished_at=finished,artifact_available=True,
                            independent_acceptance=True,integrated=True,joint_verification=False,
                            acceptance_evidence=f"artifacts/{acceptance}/review.json",intake_evidence=f"artifacts/{intake}/receipt.json",
                            independent_result=review["junit"],integrated_at=receipt["integrated_at"],checked_at=at,whole_package_complete=False)
ledger["current_accepted_stage"]["current_root_status"]="S01/MCP intaken and docs synchronized; previous776 historical; final joint pending"
ledger["updated_at"]=at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage={"at":at,"last_verified_root":"artifacts/coordinator-r11-astra-intaken-20261015/review.json",
       "current_root_joint":"artifacts/coordinator-r11-all-intaken-20261015","current_root_joint_status":"running",
       "tasks":[rows[name] for name in ("S01-SYMBOL","U01-MCP-JOBS","ASTRA-UX-R10")]}
(HERE/"followups-r10/status-r11.json").write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"""## {at[:19]} +08:00 · S01/MCP independently accepted and intaken, final joint pending

- S01 task_0afb819799 completed01:44:30 observed K3; independent461 passed/0fail/0error/0skip, compileall/mypy/Black pass, all inputs stable. Coordinator refreshed only the proven-stale read-only tool test after producer stop with explicit dependency receipt; complete file included. Four frozen owned files intaken01:49:57. Receipt `artifacts/coordinator-s01-symbol-r11-acceptance-20261015/review.json` / `artifacts/intake-s01-symbol-r11-20261015/receipt.json`.
- MCP task_feb229984d completed01:43:29 observed GLM5.3; independent262 passed/0fail/0error/0skip, all three quality commands pass, full inputs stable. Four owned frozen files intaken01:49:57. Receipt `artifacts/coordinator-mcp-r11-acceptance-20261015/review.json` / `artifacts/intake-mcp-r11-20261015/receipt.json`.
- Astra independent88/three-file intake01:29:51 plus index-only lock update already passed same-root776/six commands at01:38:51. That collection is historical after these new intakes. Final expanded union runs at `artifacts/coordinator-r11-all-intaken-20261015`; no current final-pass claim yet. Independent and historical counts never summed.
- User/module/architecture/21 docs synchronized before capture; no runtime prompt/native/rule default/old S06 change. Full ScanSession/queue/checkpoint/contract-USR/broader graph/link and MCP findings remain pending; controlled fixtures do not establish real-project effect. No new dispatch or Bridge service; original owner80748 retained.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    p=HERE/name
    p.write_text(note+p.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps({"at":at,"s01":461,"mcp":262,"current_joint":"pending final expanded collection","whole_package_complete":False}))
