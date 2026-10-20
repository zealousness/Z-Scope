"""Preserve the completed six-command Root trial as failed, never a pass."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-r21-verified-environment-20261015"
source = json.loads((out / "source-evidence.json").read_text(encoding="utf-8"))
assert len(source["commands"]) == 6 and source["commands"][0]["returncode"] == 1
assert all(r["returncode"] == 0 for r in source["commands"][1:])
assert source["before"] == source["after"] and source["direct_source_unchanged"]
assert all(hashlib.sha256((ROOT/p).read_bytes()).hexdigest() == h for p,h in source["after"].items())
suites = ET.parse(out / "results.xml").getroot().findall("testsuite")
junit = {k: sum(int(s.get(k, "0")) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
assert junit == {"tests": 2539, "failures": 1, "errors": 0, "skipped": 0}
failure = [c for c in ET.parse(out / "results.xml").getroot().iter("testcase") if c.find("failure") is not None]
assert len(failure) == 1 and failure[0].get("name") == "test_run_tickets_parallel_keeps_stable_report_order"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"verified_at": at, "finished_at": source["captured_at"], "passed": 2538, "junit": junit, "commands_executed": 6, "quality_checks_passed": 5, "joint_verification_passed": False, "source_inputs": len(source["after"]), "source_unchanged": True, "native_unchanged": source["native_before"] == source["native_after"], "launcher_unchanged": source["launcher_before"] == source["launcher_after"], "failure": {"classname": failure[0].get("classname"), "name": failure[0].get("name"), "text": failure[0].find("failure").text}, "clock_problem_resolved": False, "next_gate": "Probe actual worker overlap and end-to-end initialization/IO before any change or rerun; preserve original 0.18s assertion", "whole_packages_complete": False}
target = out / "review.json"
assert not target.exists()
target.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "CURRENT-JOINT-R21")
row.update(status="failed_current_union_single_parallel_timing_assertion_five_quality_checks_passed", joint_verification=False, independent_acceptance=False, is_current_root=False, evidence=target.relative_to(ROOT).as_posix(), result={"passed":2538,"failed":1,"errors":0,"skipped":0}, finished_at=source["captured_at"], checked_at=at)
ledger["current_accepted_stage"].update(is_current_root=False, latest_failed_trial=target.relative_to(ROOT).as_posix())
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, current_joint_status=row["status"], latest_joint_attempt=target.relative_to(ROOT).as_posix(), latest_joint_attempt_passed=False, prior_pass_is_current_root=False, active_phase="Diagnose parallel micro-timing failure; no test weakening or next development dispatch")
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at":at,"passed":2538,"failed":1,"quality_checks_passed":5,"evidence":str(target)}),flush=True)
