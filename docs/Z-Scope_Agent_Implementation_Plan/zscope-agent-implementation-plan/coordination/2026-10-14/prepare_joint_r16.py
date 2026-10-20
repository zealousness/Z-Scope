"""Preserve all R15 checks and make the accepted Astra R15 intake explicit."""
from pathlib import Path
import datetime as dt
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
target=HERE/"verify_current_root_r16.py"
assert not target.exists()
source=(HERE/"verify_current_root_r15.py").read_text(encoding="utf-8")
source=source.replace('"CONTRACT-VALIDATION-R12": ["test_validation_thread_context", "test_contract_usr_boundary"]','"CONTRACT-VALIDATION-R12": ["test_validation_thread_context", "test_contract_usr_boundary", "test_contract_protocol_usr_boundary"]')
source=source.replace('"SCAN-SESSION-R12": ["test_scan_session_native_boundary", "test_scan_session_crash_resume"]','"SCAN-SESSION-R12": ["test_scan_session_native_boundary", "test_scan_session_crash_resume", "test_scan_session_queue_fencing", "test_scan_session_deadline"]')
source=source.replace('"r12_integrated_tasks": sorted(integrated & set(ROUND_TESTS)),','"r12_integrated_tasks": sorted(integrated & set(ROUND_TESTS)),\n    "astra_job_projection_r15_integrated": "ASTRA-JOB-PROJECTION-R15" in integrated,')
target.write_text(source,encoding="utf-8",newline="\n")
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
row={"id":"CURRENT-JOINT-R16","title":"Current Astra report-binding projection intake joint","owner":"coordinator","depends_on":["CURRENT-JOINT-R15","ASTRA-JOB-PROJECTION-R15"],"packages":["U01","U02"],"status":"intaken_current_root_joint_pending","evidence":"artifacts/coordinator-r16-astra-projection-intaken-20261015","whole_package_complete":False,"checked_at":at}
assert not any(r["id"]==row["id"] for r in ledger["tasks"])
ledger["tasks"].append(row)
ledger["current_accepted_stage"].update(is_current_root=False,current_root_status="Astra R15 three files/JS lock and interface documentation intaken; new R16 joint pending; prior1206 is historical")
ledger["updated_at"]=at
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
p=HERE/"continuation-r6.json"
d=json.loads(p.read_text(encoding="utf-8"))
d.update(updated_at=at,latest_joint_attempt=row["evidence"],latest_joint_attempt_passed=False,current_root_status="R16 intake complete/current joint pending; R15 pass is historical",prior_pass_is_current_root=False,current_joint_status="historical_prior_root_after_new_intake")
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note=f"## {at} · Astra R15 accepted/intaken; current R16 joint pending\n\nAstra /root/astra_v3_editor_r6 independent89/0fail/error/skip plus4test-qualitycommands0,1009stable inputs, finished04:17:52.741893. Intake artifacts/intake-astra-job-projection-r15-20261015/receipt.json:3files plus only JS SHA in staticlock; interface module behavior updated. Current root changed, priorR15 1206 is historical until fresh joint. RootR16 preserves all81files/sixcommands/defaultfd/ext4TMPDIR; no backend unaccepted bytes intaken. Kimi/ZCode remain isolated; archivedS06 untouched.\n\n---\n\n"
for name in ("PROGRESS.md","DAG.md"):
    p=HERE/name;p.write_text(note+p.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(target)
