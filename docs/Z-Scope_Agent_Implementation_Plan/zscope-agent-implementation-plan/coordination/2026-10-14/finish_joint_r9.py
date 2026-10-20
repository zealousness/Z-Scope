"""Publish an unchanged, zero-skip current-root collection without closing packages."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts" / sys.argv[1]
source = json.loads((OUT / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"]
assert len(source["commands"]) == 6 and all(row["returncode"] == 0 for row in source["commands"])
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name, sha in source["after"].items())
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
assert suites and all(suite.get(key) == "0" for suite in suites for key in ("errors", "failures", "skipped"))
count = sum(int(suite.get("tests", "0")) for suite in suites)
assert count >= 635 and source["test_file_count"] >= 34
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
evidence = (OUT / "source-evidence.json").relative_to(ROOT).as_posix()
review = {"verified_at": at, "finished_at": finished, "passed": count, "failed": 0,
          "errors": 0, "skipped": 0, "quality_commands_passed": 6,
          "pytest_file_count": source["test_file_count"], "bound_input_files": len(source["after"]),
          "current_bytes_match": True, "pytest_capture": source["pytest_capture"],
          "temporary_directory": source["temporary_directory"], "source_evidence": evidence,
          "intaken_features": source["intaken_features"], "scope": source["scope"],
          "whole_package_complete": False, "commands": source["commands"]}
assert not (OUT / "review.json").exists()
(OUT / "review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
rows = {row["id"]: row for row in ledger["tasks"]}
for identifier, feature, acceptance, intake in (
    ("S08-SESSION-SCHEDULER", "s08_session_consumer", "coordinator-s08-r3-final-acceptance-20261014", "intake-s08-r3-r9-20261014"),
    ("S01-INST-EXEC", "s01_instance_api", "coordinator-s01-r4-final-acceptance-20261014", "intake-s01-r4-r9-20261014"),
):
    if not source["intaken_features"][feature]:
        continue
    accepted = json.loads((ROOT / "artifacts" / acceptance / "review.json").read_text(encoding="utf-8"))
    intaken = json.loads((ROOT / "artifacts" / intake / "receipt.json").read_text(encoding="utf-8"))
    assert accepted["independent_acceptance_passed"] and intaken["all_bytes_verified"]
    row = rows[identifier]
    row.update(status="independent_passed_integrated_joint_passed_slice", checked_at=at,
               independent_acceptance=True, integrated=True, joint_verification=True,
               acceptance_evidence=f"artifacts/{acceptance}/review.json",
               intake_evidence=f"artifacts/{intake}/receipt.json", integrated_at=intaken["integrated_at"],
               joint_evidence=evidence, whole_package_complete=False)
    if identifier == "S01-INST-EXEC":
        row.update(worker_status="cancelled", repair_author="coordinator",
                   coordinator_repair="artifacts/coordinator-s01-context-repair-r9-20261014/repair.json")
        repair_path = ROOT / row["coordinator_repair"]
        repair = json.loads(repair_path.read_text(encoding="utf-8"))
        repair.update(joint_verification=True, joint_evidence=evidence)
        repair_path.write_text(json.dumps(repair,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
for identifier in ("U01-ENTRYPOINTS", "ASTRA-V3-EDITOR", "HTTP-INTEGRATION"):
    rows[identifier].update(joint_evidence=evidence, checked_at=at)
rows["HTTP-INTEGRATION"].update(current_evidence=evidence, current_tests={"passed":count,"failed":0,"skipped":0,"do_not_add_prior_counts":True})
if "CURRENT-JOINT-R9" not in rows:
    row = {"id":"CURRENT-JOINT-R9", "packages":["S01","S08","U01","U02"],
           "title":"Current-root producer intake and six-command verification", "owner":"coordinator",
           "depends_on":["CURRENT-JOINT-R7","S08-SESSION-SCHEDULER"], "whole_package_complete":False}
    ledger["tasks"].append(row)
    rows[row["id"]] = row
joint = rows["CURRENT-JOINT-R9"]
if source["intaken_features"]["s01_instance_api"] and "S01-INST-EXEC" not in joint["depends_on"]:
    joint["depends_on"].append("S01-INST-EXEC")
joint.update(status="passed_current_intaken_slice", evidence=evidence, finished_at=finished,
             result={"passed":count,"failed":0,"errors":0,"skipped":0}, quality_checks="six commands exit0")
remaining, done, layers = set(rows), set(), []
while remaining:
    ready = [row["id"] for row in ledger["tasks"] if row["id"] in remaining and set(row["depends_on"]) <= done]
    assert ready, "cycle or unknown dependency"
    layers.append(ready)
    remaining.difference_update(ready)
    done.update(ready)
ledger.update(updated_at=at, topological_layers=layers,
              current_accepted_stage={"source_evidence":evidence,"passed":count,"failed":0,"skipped":0,
              "quality_commands":6,"bound_input_files":len(source["after"]),"intaken_features":source["intaken_features"],
              "scope":"Accepted APIs/standalone consumers, not full ScanSession/scanner/consumer migration or real-project effect"})
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage_path = HERE / "continuation-r6.json"
stage = json.loads(stage_path.read_text(encoding="utf-8"))
stage.update(updated_at=at,current_joint=OUT.relative_to(ROOT).as_posix(),
             current_joint_status="passed_current_intaken_slice",current_joint_result=joint["result"],
             last_verified_root_joint=evidence,
             next_task_rows=[rows[name] for name in ("S01-INST-EXEC","S08-SESSION-SCHEDULER","U01-ENTRYPOINTS","ASTRA-V3-EDITOR")])
stage_path.write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note = f"""## {at[:19]} +08:00 · R9 current-root receipt

- Finished {finished}: `{OUT.relative_to(ROOT).as_posix()}` — {count} passed / 0 failed / 0 errors / 0 skipped; {source['test_file_count']} test files, six commands exit0, {len(source['after'])} input hashes stable and current. Default pytest fd capture retained; independent ext4 `/tmp` fixes the verified DrvFS ENOENT. Previous counts are separate collections.
- Intaken features: `{json.dumps(source['intaken_features'])}`. S08 `task_a110e5866a`: independent 170/0/0skip + four quality commands, seven files intaken 22:37:41. Bridge completed 22:18:19 but native finalization continued afterward; stable tested bytes, not Bridge metadata or stale DELIVERY.md, authorize intake. S01 `task_6e14411a6c` cancelled 22:48:19 for concrete native payload review; coordinator context repair and independent acceptance are tracked separately. Whole S01/S08 packages remain open.
- Remaining shared integration: ScanSession must schedule all precise instances, wire durable queue/checkpoints/stop into the complete scanner, and migrate graph/semantic/CLI/MCP consumers. Existing UI/owner tests use controlled scanner and synthetic reports; real-project/model effects, formal benchmark and conditional extensions are separate.
- Original Bridge owner PID80748 retained; no service restart, duplicate dispatch, or old S06-R02 restoration. Owner/writer quiescence checked before the coordinator repair. Kimi/API timeout is not asserted; no model transfer used to bypass a review.

---

"""
for name in ("PROGRESS.md","DAG.md"):
    p = HERE / name
    p.write_text(note+p.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
(HERE / "CHECKPOINT-R9.md").write_text(note,encoding="utf-8",newline="\n")
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name, sha in source["after"].items())
print(json.dumps({"passed":count,"quality_commands":6,"files":source["test_file_count"],"inputs":len(source["after"]),"finished_at":finished,"receipt":str(OUT/"review.json")}))
