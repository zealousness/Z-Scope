"""Preserve the failed full joint, including exact bytes and real SQL evidence."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-r18-queue-receipt-repaired-20261015"
source = json.loads((out / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and source["before"] == source["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None and int(suite.get("failures", "0")) > 0
failed = [{"class": case.get("classname"), "name": case.get("name"), "failure": case.find("failure").get("message")} for case in suite.findall("testcase") if case.find("failure") is not None]
timeline = json.loads((out / "deadline-timeline-live.json").read_text(encoding="utf-8"))
fixture = timeline["fixtures"][0]
events = fixture["events"]
epochs = [dt.datetime.fromisoformat(r["at"]).timestamp() for r in events]
backwards = [{"from_seq": events[i-1]["seq"], "to_seq": events[i]["seq"], "delta_seconds": epochs[i]-epochs[i-1]} for i in range(1,len(events)) if epochs[i] < epochs[i-1]]
stop_epoch = fixture["jobs"][0]["stop_at_epoch"]
proof = {"verified_at": dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), "finished_at": source["captured_at"], "junit": dict(suite.attrib), "failed_cases": failed, "current_bytes_match": True, "source_unchanged": True, "source_evidence": (out / "source-evidence.json").relative_to(ROOT).as_posix(), "commands_executed": len(source["commands"]), "commands": source["commands"], "independent_or_joint_passed": False, "clock_evidence": {"backward_sql_event_deltas": backwards, "stop_at_epoch": stop_epoch, "last_event_epoch": epochs[-1], "last_event_before_absolute_deadline": epochs[-1] < stop_epoch, "receipt": (out / "deadline-timeline-live.json").relative_to(ROOT).as_posix(), "clock_problem_resolved": False, "product_or_test_changed_for_clock": False}, "scope": "Current full selected joint failed; no current-root pass. Historical passing counts do not substitute. A same-byte retry will preserve every case/timeout/capture setting and observe clocks only."}
assert not (out / "review.json").exists()
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "CURRENT-JOINT-R18")
row.setdefault("attempt_history", []).append({"review": (out / "review.json").relative_to(ROOT).as_posix(), "result": dict(suite.attrib), "status": "failed_clock_evidence_retained"})
row.update(status="failed_full_joint_clock_evidence_retained_same_byte_retry_pending", evidence=(out / "review.json").relative_to(ROOT).as_posix(), checked_at=proof["verified_at"])
ledger["updated_at"] = proof["verified_at"]
ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"finished_at": proof["finished_at"], "junit": proof["junit"], "failed_cases": failed, "clock_evidence": proof["clock_evidence"]}, ensure_ascii=False), flush=True)
