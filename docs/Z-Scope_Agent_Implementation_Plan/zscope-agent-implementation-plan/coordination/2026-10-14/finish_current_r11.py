"""Publish a strict current-source R11 receipt without closing full work packages."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
out=ROOT/"artifacts"/sys.argv[1]
source=json.loads((out/"source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"]
assert len(source["commands"])==6 and all(row["returncode"]==0 for row in source["commands"])
assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in source["after"].items())
suites=ET.parse(out/"results.xml").getroot().findall("testsuite")
assert suites and all(suite.get(key)=="0" for suite in suites for key in ("failures","errors","skipped"))
count=sum(int(suite.get("tests","0")) for suite in suites)
assert count>=726 and source["test_file_count"]>=45
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished=dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
evidence=str((out/"source-evidence.json").relative_to(ROOT)).replace("\\","/")
proof={"verified_at":at,"finished_at":finished,"passed":count,"failed":0,"errors":0,"skipped":0,
       "quality_commands_passed":6,"pytest_file_count":source["test_file_count"],"bound_input_files":len(source["after"]),
       "current_bytes_match":True,"source_evidence":evidence,"intaken_features":source["intaken_features"],
       "pytest_capture":source["pytest_capture"],"temporary_directory":source["temporary_directory"],
       "commands":source["commands"],"whole_package_complete":False,
       "scope":"Actual native instance/reference-consumer fixtures; real Linux SQLite/HTTP/MCP/owner/browser over controlled scanner/report/assumption data. Full ScanSession/queue/checkpoint/contract-USR migration and real-project/formal/portable effects remain separate."}
assert not (out/"review.json").exists()
(out/"review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
path=HERE/"tasks.json"
ledger=json.loads(path.read_text(encoding="utf-8"))
rows={row["id"]:row for row in ledger["tasks"]}
for identifier,feature in (("ASTRA-UX-R10","astra_ux_r10"),("S01-SYMBOL","s01_symbol_consumers"),("U01-MCP-JOBS","mcp_persistent_jobs")):
    if not source["intaken_features"].get(feature):
        continue
    row=rows[identifier]
    assert row["independent_acceptance"] and row["integrated"], identifier
    row.update(status="independent_passed_integrated_joint_passed_bounded_slice",joint_verification=True,
               joint_evidence=evidence,checked_at=at,whole_package_complete=False)
if "CURRENT-JOINT-R11" not in rows:
    row={"id":"CURRENT-JOINT-R11","packages":["S01","S08","U01","U02"],"title":"Current R11 intake and quality",
         "owner":"coordinator","depends_on":["CURRENT-JOINT-R9","ASTRA-UX-R10"],"whole_package_complete":False}
    ledger["tasks"].append(row); rows[row["id"]]=row
row=rows["CURRENT-JOINT-R11"]
for feature,identifier in (("s01_symbol_consumers","S01-SYMBOL"),("mcp_persistent_jobs","U01-MCP-JOBS")):
    if source["intaken_features"].get(feature) and identifier not in row["depends_on"]:
        row["depends_on"].append(identifier)
row.update(status="passed_current_intaken_slice",evidence=evidence,finished_at=finished,
           result={"passed":count,"failed":0,"errors":0,"skipped":0},quality_checks="six commands exit0")
ledger["current_accepted_stage"]={"source_evidence":evidence,"passed":count,"failed":0,"skipped":0,
                                  "quality_commands":6,"bound_input_files":len(source["after"]),
                                  "intaken_features":source["intaken_features"],"current_root_status":"accepted current byte set; full packages open"}
ledger["updated_at"]=at
for identifier in ("HTTP-INTEGRATION","U01-ENTRYPOINTS","ASTRA-V3-EDITOR"):
    rows[identifier].update(joint_evidence=evidence,checked_at=at)
rows["HTTP-INTEGRATION"].update(current_evidence=evidence,current_tests={"passed":count,"failed":0,"skipped":0,"do_not_add_prior_counts":True})
remaining,done,layers=set(rows),set(),[]
while remaining:
    ready=[row["id"] for row in ledger["tasks"] if row["id"] in remaining and set(row["depends_on"])<=done]
    assert ready
    layers.append(ready); remaining.difference_update(ready); done.update(ready)
ledger["topological_layers"]=layers
path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage={"at":at,"current_root_joint":str(out.relative_to(ROOT)).replace("\\","/"),"current_root_joint_status":"passed",
       "result":proof,"tasks":[rows[name] for name in ("S01-SYMBOL","U01-MCP-JOBS","ASTRA-UX-R10")]}
(HERE/"followups-r10/status-r11.json").write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
lock_path=ROOT/"artifacts/intake-astra-ux-r10-20261015/static-lock-update.json"
lock=json.loads(lock_path.read_text(encoding="utf-8")); lock.update(full_verify=True,joint_evidence=evidence)
lock_path.write_text(json.dumps(lock,indent=2)+"\n",encoding="utf-8",newline="\n")
repair_path=ROOT/"artifacts/coordinator-tool-description-repair-r10-20261015/repair.json"
repair=json.loads(repair_path.read_text(encoding="utf-8")); repair.update(joint_verified=True,joint_evidence=evidence,
    after_sha256=hashlib.sha256((ROOT/"tests/test_function_info_tool.py").read_bytes()).hexdigest())
repair_path.write_text(json.dumps(repair,indent=2)+"\n",encoding="utf-8",newline="\n")
accepted_lines=[]
for identifier,feature in (("S01-SYMBOL","s01_symbol_consumers"),("U01-MCP-JOBS","mcp_persistent_jobs")):
    if source["intaken_features"].get(feature):
        accepted=rows[identifier]
        accepted_lines.append(f"- {identifier} repair `{accepted['bridge_task_id']}` independently passed {accepted['independent_result']['tests']} / 0 fail/error/skip plus quality, four frozen owned files intaken {accepted['integrated_at']}; now included in this joint receipt, bounded slice only. Acceptance `{accepted['acceptance_evidence']}`, intake `{accepted['intake_evidence']}`.")
accepted_text="\n".join(accepted_lines)
note=f"""## {at[:19]} +08:00 · Current R11 joint passed

- Finished {finished}: `{out.relative_to(ROOT).as_posix()}` — {count} passed / 0 failed/errors/skipped, {source['test_file_count']} test files, six commands exit0, {len(source['after'])} bound input hashes stable and current. Receipt `{(out/'review.json').relative_to(ROOT).as_posix()}`. Default fd/ext4 temporary-file fix retained; counts never added to older collections.
- Intaken features: `{json.dumps(source['intaken_features'])}`. Astra independent88/3-file intake01:29:51 and coordinator index.html-only lock update are included. The complete function-info file and tool registry now run in this collection; original baseline failure and coordinator test-contract repair are preserved separately. No test exclusion, xfail or reduced requirement.
{accepted_text}
- S01 initial task_9579265ee7 failed five independent receipt/cache probes; repair task_0afb819799 remains separately tracked. MCP initial task_2f3f99db9b had257 passing tests but mypy failure and four strict-boundary failures; repair task_feb229984d remains separately tracked. Feature flags above, not task completion labels, show which accepted bytes this collection covers.
- Full ScanSession/queue/checkpoint/callee-contract-USR and broader graph migration still pending. Shared validation directly calls ValidationRunner.run rather than Analyzer.run; merely passing instance_scope to its constructor would not by itself bind contract context. Controlled inputs are not real-project effect acceptance. Formal/portable and S10/Q conditions separate; old S06 remains untouched.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    destination=HERE/name
    destination.write_text(note+destination.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE/"CHECKPOINT-R11.md").write_text(note,encoding="utf-8",newline="\n")
assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in source["after"].items())
print(json.dumps({"passed":count,"files":source["test_file_count"],"commands":6,"inputs":len(source["after"]),"finished_at":finished,"receipt":str(out/"review.json")}))
