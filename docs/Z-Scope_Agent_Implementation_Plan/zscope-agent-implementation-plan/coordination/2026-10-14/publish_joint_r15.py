"""Publish current R15 bytes and chained intake receipts without package closure."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r15-mcp-queue-web-intaken-20261015"
source = json.loads((OUT / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and len(source["commands"]) == 6
assert all(row["returncode"] == 0 for row in source["commands"])
assert all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha for name, sha in source["after"].items())
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
assert suites and all(suite.get(key) == "0" for suite in suites for key in ("failures", "errors", "skipped"))
count = sum(int(suite.get("tests", "0")) for suite in suites)
assert count == 1206 and source["test_file_count"] == 81 and len(source["after"]) == 1009
tz = dt.timezone(dt.timedelta(hours=8))
at = dt.datetime.now(tz).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(tz).isoformat()
evidence = (OUT / "source-evidence.json").relative_to(ROOT).as_posix()
receipt_names = {
    "COORD-SOURCE-ROOT-R13": "artifacts/intake-coordinator-source-roots-r13-20261015/receipt.json",
    "MCP-FINDINGS-R12": "artifacts/intake-mcp-findings-r12-20261015/receipt.json",
    "COORD-QUEUE-RECEIPTS-R14": "artifacts/intake-coordinator-queue-web-r14-20261015/receipt.json",
}
receipts = {key: json.loads((ROOT / name).read_text(encoding="utf-8")) for key, name in receipt_names.items()}
helper = "zscope/reporting/job_result_projection.py"
for key, receipt in receipts.items():
    for name, sha in receipt["accepted_files"].items():
        if key == "MCP-FINDINGS-R12" and name == helper:
            staged = ROOT / ".coordination/20261014/workspaces/mcp-findings-r12" / name
            assert hashlib.sha256(staged.read_bytes()).hexdigest() == sha
            assert source["after"][name] == receipts["COORD-QUEUE-RECEIPTS-R14"]["accepted_files"][name]
        else:
            assert source["after"][name] == sha
proof = {
    "verified_at": at, "finished_at": finished, "passed": count, "failed": 0, "errors": 0, "skipped": 0,
    "quality_commands_passed": 6, "pytest_file_count": 81, "bound_input_files": 1009,
    "current_bytes_match": True, "source_evidence": evidence, "commands": source["commands"],
    "pytest_capture": source["pytest_capture"], "temporary_directory": source["temporary_directory"],
    "intaken_task_ids": ["task_e4ab0da557", "coordinator/shared-source-root-r13", "coordinator/shared-queue-web-r14"],
    "whole_package_complete": False,
    "scope": "Current bounded root slices including prior Astra/remaining accounting, native source-root queries, MCP findings and Web/queue receipts. Real native fixtures and actual Linux HTTP/MCP/SQLite/owner over controlled scanner/report inputs. ScanSession/USR-contract R12 deliveries are not intaken. No real-project/model/formal/portable effect acceptance. Counts are separate from earlier collections.",
    "prior_failed_joint": "artifacts/coordinator-r14-source-roots-intaken-20261015/review.json",
    "prior_failure_note": "R14 local HTTP connect timeout was not reproduced in unchanged focused probes or R15; its original failure remains recorded. No test timeout or capture relaxation.",
}
assert not (OUT / "review.json").exists()
def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
write(OUT / "review.json", proof)
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
rows = {row["id"]: row for row in ledger["tasks"]}
for key in receipts:
    rows[key].update(status="independent_passed_integrated_joint_passed_bounded_slice" if key == "MCP-FINDINGS-R12" else "coordinator_validated_integrated_joint_passed_bounded_slice", joint_verification=True, joint_evidence=evidence, joint_finished_at=finished, checked_at=at)
    companion = dict(receipts[key], joint_verification=True, joint_evidence=evidence, joint_finished_at=finished)
    if key == "MCP-FINDINGS-R12":
        companion["subsequent_shared_helper_delta"] = receipt_names["COORD-QUEUE-RECEIPTS-R14"]
    write((ROOT / receipt_names[key]).with_name("joint-receipt.json"), companion)
row = {"id": "CURRENT-JOINT-R15", "title": "Current source-root/MCP/queue/Web intake joint", "owner": "coordinator", "packages": ["S01", "S08", "U01", "U02"], "depends_on": ["CURRENT-JOINT-R13", *receipts], "status": "passed_current_intaken_slice", "evidence": evidence, "finished_at": finished, "result": {"passed": count, "failed": 0, "errors": 0, "skipped": 0}, "quality_checks": "six commands exit0", "whole_package_complete": False}
assert row["id"] not in rows
ledger["tasks"].append(row); rows[row["id"]] = row
ledger["current_accepted_stage"] = dict(proof, current_root_status="accepted current R15 bounded byte set; full packages and unaccepted ScanSession/contract deliveries remain open")
ledger["updated_at"] = at
left, done, layers = set(rows), set(), []
while left:
    ready = [r["id"] for r in ledger["tasks"] if r["id"] in left and set(r["depends_on"]) <= done]
    assert ready
    layers.append(ready); left.difference_update(ready); done.update(ready)
ledger["topological_layers"] = layers
write(ledger_path, ledger)
continuation_path = HERE / "continuation-r6.json"
continuation = json.loads(continuation_path.read_text(encoding="utf-8"))
continuation.update(current_joint=OUT.relative_to(ROOT).as_posix(), current_joint_finished_at=finished, current_joint_status="passed_current_intaken_bounded_slices", current_joint_result={"passed": count, "failed": 0, "errors": 0, "skipped": 0, "quality_commands_passed": 6, "source_inputs": 1009}, current_root_status="R15 current bytes passed; ScanSession and contract deliveries unaccepted", latest_joint_attempt=(OUT / "review.json").relative_to(ROOT).as_posix(), latest_joint_attempt_passed=True, prior_pass_is_current_root=True, last_verified_root_joint=evidence, active_phase="R15 passed; independent ScanSession/contract acceptance pending", updated_at=at, whole_packages_complete=False)
continuation["current_round"] = {key: {"task_id": rows[key]["bridge_task_id"], "status": rows[key]["status"]} for key in ("SCAN-SESSION-R12", "CONTRACT-VALIDATION-R12", "MCP-FINDINGS-R12")}
write(continuation_path, continuation)
note = f"""## {at} · R15 current root joint passed

- Finished {finished}: 1206 passed / 0 failed/errors/skipped, 81 test files, six test/quality commands exit0, 1009 input hashes stable and current. Receipt: {(OUT / 'review.json').relative_to(ROOT).as_posix()}. Default fd capture and independent ext4 temporary directory; no test standard relaxed.
- MCP task_e4ab0da557: independent358 passed, intaken03:39:13, now joint passed. Coordinator source-root218 and queue/Web285 validations remain explicitly coordinator-authored; their separate collections are not added to1206. MCP helper's subsequent coordinator delta has a separate chained receipt. Prior Astra bounded UI intake remains covered.
- R14 HTTP connect timeout failure and unchanged focused probes remain preserved; current R15 includes that testcase and passes. No capture FileNotFoundError recurrence.
- Kimi task_658717aaa6 and ZCode task_2d639b45b8 deliveries still require independent acceptance/intake. They are absent from this current root joint. Full S01/S08/U01/U02, real-project/model/formal/portable effects, conditional extensions and external waits remain open. Original Bridge owner80748 reused; archived S06 untouched.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CHECKPOINT-R15.md").write_text(note, encoding="utf-8", newline="\n")
print(json.dumps({"passed": count, "finished_at": finished, "receipt": str(OUT / "review.json")}))
