"""Reconcile completed R16 with current bytes; keep unaccepted backend tasks open."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
OUT=ROOT/"artifacts/coordinator-r16-astra-projection-intaken-20261015"
source=json.loads((OUT/"source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and len(source["commands"])==6
assert all(row["returncode"]==0 for row in source["commands"])
assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in source["after"].items())
assert hashlib.sha256((OUT/"launcher.py").read_bytes()).hexdigest()==source["launcher_sha256"]
suites=ET.parse(OUT/"results.xml").getroot().findall("testsuite")
assert suites and all(suite.get(k)=="0" for suite in suites for k in ("failures","errors","skipped"))
count=sum(int(s.get("tests","0")) for s in suites)
assert count==1207 and source["test_file_count"]==81 and len(source["after"])==1009
assert source["astra_job_projection_r15_integrated"]
intake_path=ROOT/"artifacts/intake-astra-job-projection-r15-20261015/receipt.json"
intake=json.loads(intake_path.read_text(encoding="utf-8"))
assert intake["independent_acceptance"] and all(source["after"][p]==h for p,h in intake["accepted_files"].items())
tz=dt.timezone(dt.timedelta(hours=8))
at=dt.datetime.now(tz).isoformat()
finished=dt.datetime.fromisoformat(source["captured_at"]).astimezone(tz).isoformat()
evidence=(OUT/"source-evidence.json").relative_to(ROOT).as_posix()
features=dict(source["intaken_features"],measured_remaining=True,astra_queue_ux_r12=True,native_source_roots=True,mcp_findings_r12=True,queue_web_r14=True,astra_job_projection_r15=True)
proof={"verified_at":at,"finished_at":finished,"passed":count,"failed":0,"errors":0,"skipped":0,"quality_commands_passed":6,"quality_commands":6,"pytest_file_count":81,"bound_input_files":1009,"current_bytes_match":True,"is_current_root":True,"source_evidence":evidence,"commands":source["commands"],"pytest_capture":source["pytest_capture"],"temporary_directory":source["temporary_directory"],"intaken_features":features,"whole_package_complete":False,"scope":"Current bounded root with accepted Astra R15 report binding/invalidation, prior MCP/queue/Web/source-root and UI slices. Real native fixtures and actual HTTP/SQLite/owner/browser over controlled scanner/report inputs. Neither task_2ba352c7a1 nor task_07fdfa490a is intaken. No real-project/model/formal/portable effect acceptance; separate collections are not added."}
def write(p,d):
    p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
assert not (OUT/"review.json").exists()
write(OUT/"review.json",proof)
write(intake_path.with_name("joint-receipt.json"),dict(intake,joint_verification=True,joint_evidence=evidence,joint_finished_at=finished))
lock_path=intake_path.with_name("static-lock-update.json")
lock=json.loads(lock_path.read_text(encoding="utf-8"));lock.update(full_verify=True,joint_evidence=evidence)
write(lock_path,lock)
ledger_path=HERE/"tasks.json"
ledger=json.loads(ledger_path.read_text(encoding="utf-8"));rows={r["id"]:r for r in ledger["tasks"]}
assert not rows["SCAN-SESSION-R12"]["integrated"] and not rows["CONTRACT-VALIDATION-R12"]["integrated"]
rows["ASTRA-JOB-PROJECTION-R15"].update(status="independent_passed_integrated_joint_passed_bounded_slice",joint_verification=True,joint_evidence=evidence,joint_finished_at=finished,checked_at=at)
rows["CURRENT-JOINT-R16"].update(status="passed_current_intaken_slice",evidence=evidence,finished_at=finished,result={"passed":count,"failed":0,"errors":0,"skipped":0},quality_checks="six commands exit0",checked_at=at)
ledger["current_accepted_stage"]=dict(proof,current_root_status="R16 1207 passed/current1009 hashes; ScanSession/contract deliveries unaccepted; full packages open")
ledger["updated_at"]=at
left,done,layers=set(rows),set(),[]
while left:
    ready=[r["id"] for r in ledger["tasks"] if r["id"] in left and set(r["depends_on"])<=done];assert ready
    layers.append(ready);left.difference_update(ready);done.update(ready)
ledger["topological_layers"]=layers;write(ledger_path,ledger)
p=HERE/"continuation-r6.json";d=json.loads(p.read_text(encoding="utf-8"))
d.update(updated_at=at,current_joint=OUT.relative_to(ROOT).as_posix(),current_joint_finished_at=finished,current_joint_status="passed_current_intaken_bounded_slices",current_joint_result={"passed":count,"failed":0,"errors":0,"skipped":0,"quality_commands_passed":6,"source_inputs":1009},current_root_status=ledger["current_accepted_stage"]["current_root_status"],latest_joint_attempt=(OUT/"review.json").relative_to(ROOT).as_posix(),latest_joint_attempt_passed=True,prior_pass_is_current_root=True,last_verified_root_joint=evidence,active_phase="R16 passed/current bytes; inventory completed backend deliveries before independent verification",whole_packages_complete=False)
write(p,d)
note=f"""## {at} · R16 final receipt reconciled against current root

- Actual finish {finished}:1207passed/0failure/error/skip,81testfiles,six commands exit0,1009input hashes stable during run and matching current root. Receipt artifacts/coordinator-r16-astra-projection-intaken-20261015/review.json. Defaultfd/ext4TMPDIR retained. R15 1206 remains historical, not substituted.
- Astra /root/astra_v3_editor_r6 R15 independent89/0 plusquality,3files intaken04:19,JS-only staticlock delta,now currentjoint passed. ActualHTTP/SQLite/owner/browser,scanner/report synthetic; no completeU01/U02 or realproject claim.
- Kimi task_2ba352c7a1 and ZCode task_07fdfa490a ended; neither has independent delivery acceptance/intake. Inventory and ownership checks first, no duplicate dispatch. OldS06 untouched; original Bridgeowner80748 retained.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    p=HERE/name;p.write_text(note+p.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE/"CHECKPOINT-R16.md").write_text(note,encoding="utf-8",newline="\n")
print(json.dumps({"passed":count,"finished_at":finished,"verified_at":at,"receipt":str(OUT/"review.json")}))
