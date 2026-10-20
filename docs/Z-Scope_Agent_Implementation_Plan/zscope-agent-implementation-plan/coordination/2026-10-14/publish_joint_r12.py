"""Publish a same-byte R12 accounting joint receipt; unfinished migrations stay open."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts" / sys.argv[1]
source = json.loads((out / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and len(source["commands"]) == 6
assert all(row["returncode"] == 0 for row in source["commands"])
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name,sha in source["after"].items())
suites = ET.parse(out / "results.xml").getroot().findall("testsuite")
assert suites and all(suite.get(key) == "0" for suite in suites for key in ("failures","errors","skipped"))
count = sum(int(suite.get("tests","0")) for suite in suites)
assert count >= 1132 and source["test_file_count"] >= 72
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
evidence = str((out / "source-evidence.json").relative_to(ROOT)).replace("\\", "/")
intake = json.loads((ROOT / "artifacts/intake-coordinator-remaining-r12-20261015/receipt.json").read_text(encoding="utf-8"))
assert all(source["after"].get(name) == sha for name,sha in intake["files"].items())
proof = {"verified_at":at,"finished_at":finished,"passed":count,"failed":0,"errors":0,"skipped":0,
    "quality_commands_passed":6,"pytest_file_count":source["test_file_count"],"bound_input_files":len(source["after"]),"current_bytes_match":True,
    "source_evidence":evidence,"intaken_features":dict(source["intaken_features"],measured_remaining=True),"pytest_capture":source["pytest_capture"],"temporary_directory":source["temporary_directory"],"commands":source["commands"],"whole_package_complete":False,
    "scope":"Current accepted bounded slices plus coordinator remaining accounting. Real native fixtures; real SQLite/owner/MCP/HTTP/browser over controlled scanner/report inputs. New full ScanSession/USR-contract/thread migration tasks are not intaken; their native pre-fix failure probes remain open and are not called passed. No real-project/formal/portable effect claim."}
assert not (out / "review.json").exists()
(out / "review.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
rows = {row["id"]:row for row in ledger["tasks"]}
rows["COORD-REMAINING-R12"].update(status="coordinator_validated_integrated_joint_passed",joint_verification=True,joint_evidence=evidence,checked_at=at)
if "CURRENT-JOINT-R12" not in rows:
    row = {"id":"CURRENT-JOINT-R12","title":"Current R12 measured remaining joint and quality","owner":"coordinator","packages":["S01","S08","U01","U02"],"depends_on":["CURRENT-JOINT-R11","COORD-REMAINING-R12"],"whole_package_complete":False}
    ledger["tasks"].append(row); rows[row["id"]] = row
rows["CURRENT-JOINT-R12"].update(status="passed_current_intaken_slice",evidence=evidence,finished_at=finished,result={"passed":count,"failed":0,"errors":0,"skipped":0},quality_checks="six commands exit0")
ledger["current_accepted_stage"] = {"source_evidence":evidence,"passed":count,"failed":0,"errors":0,"skipped":0,"quality_commands":6,"bound_input_files":len(source["after"]),"intaken_features":proof["intaken_features"],"current_root_status":"accepted current bounded byte set; R12 ScanSession/contract/UI deliveries pending; full packages open"}
ledger["updated_at"] = at
left, done, layers = set(rows), set(), []
while left:
    ready = [r["id"] for r in ledger["tasks"] if r["id"] in left and set(r["depends_on"]) <= done]
    assert ready
    layers.append(ready); left.difference_update(ready); done.update(ready)
ledger["topological_layers"] = layers
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
companion = dict(intake,joint_verification=True,joint_evidence=evidence,joint_finished_at=finished)
(ROOT / "artifacts/intake-coordinator-remaining-r12-20261015/joint-receipt.json").write_text(json.dumps(companion,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note = f"""## {at} · Current R12 accounting joint passed

- Finished {finished}: {count} passed / 0 failed/errors/skipped, {source['test_file_count']} files, six commands exit0, {len(source['after'])} bound input hashes stable/current. Receipt {(out/'review.json').relative_to(ROOT).as_posix()}. Same unchanged fd capture/ext4 temp; independent/historical counts never added.
- Four coordinator remaining accounting files are intaken and covered; original190 validation is a separate collection. Business questions/queue counts/unknown and partial on remaining/failed work now verified in current root with existing UI/MCP/native slices.
- Kimi task_1cee9c8e9d (full ScanSession/queue/checkpoint), ZCode task_315195c1a1 (USR contracts/validation threads) and native Astra R12 remain separate ongoing tasks until delivery, independent acceptance and intake. New pre-fix native ScanSession/validation-thread probes fail in current root and remain open migration requirements; this accounting collection does not claim those unfinished migrations passed.
- Full packages, broader graph/link/modeling consumers, MCP findings projection and real project/model/formal/portable/conditional effects remain open. Original owner80748 retained; archived S06 untouched.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE / "CHECKPOINT-R12.md").write_text(note,encoding="utf-8",newline="\n")
print(json.dumps({"passed":count,"files":source["test_file_count"],"inputs":len(source["after"]),"finished_at":finished,"receipt":str(out / "review.json")}))
