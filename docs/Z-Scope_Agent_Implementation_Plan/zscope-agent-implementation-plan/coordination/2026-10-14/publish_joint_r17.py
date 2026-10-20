"""Publish only a fully passed R17 collection bound to current root bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts" / (sys.argv[1] if len(sys.argv)>1 else "coordinator-r17-batch-intaken-20261015")
source = json.loads((out / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and source["before"] == source["after"]
assert len(source["commands"]) == 6 and all(r["returncode"] == 0 for r in source["commands"])
assert source["native_before"] == source["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
assert source["launcher_before"] == source["launcher_after"] == hashlib.sha256((out / "launcher.py").read_bytes()).hexdigest()
assert source["pytest_capture"] == "fd (unchanged default)" and source["temporary_directory"].startswith("/tmp/")
assert source["test_file_count"] >= 81 and len(source["after"]) >= 1009
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in source["after"].items())
suites = ET.parse(out / "results.xml").getroot().findall("testsuite")
assert suites and all(s.get(k) == "0" for s in suites for k in ("failures", "errors", "skipped"))
count = sum(int(s.get("tests", "0")) for s in suites)
assert count > 1207
intake_path = ROOT / "artifacts/intake-batch-r17-20261015/receipt.json"
intake = json.loads(intake_path.read_text(encoding="utf-8"))
assert all(source["after"][r["path"]] == r["after"] for r in intake["files"])
fixture = json.loads((ROOT / "artifacts/intake-demand-fixture-r19-20261015/receipt.json").read_text(encoding="utf-8"))
assert source["after"][fixture["path"]] == fixture["after_sha256"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
evidence = (out / "source-evidence.json").relative_to(ROOT).as_posix()
proof = {"verified_at": at, "finished_at": finished, "passed": count, "failed": 0, "errors": 0, "skipped": 0, "quality_commands_passed": 6, "quality_commands": 6, "pytest_file_count": source["test_file_count"], "bound_input_files": len(source["after"]), "source_evidence": evidence, "current_bytes_match": True, "is_current_root": True, "whole_package_complete": False, "pytest_capture": source["pytest_capture"], "commands": source["commands"], "native_tool_sha256": source["native_after"], "scope": "Current bounded R17 root: MainR3 exact instances, ContractR5 native USR/scoped effect queries and outer validation threads, whole-plan checkpoint with current authority/publication fencing and verifiable SQLite answers, coordinator bound receipt API; prior UI/MCP/owner/browser slices retained. Actual native fixtures and HTTP/SQLite/owner/browser with controlled model/scanner boundaries. Per-instance durable recovery, complete model/SVF/link and all consumers remain open. No real-project/model accuracy, formal benchmark or portable smoke; separate test counts are not summed."}
def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert not (out / "review.json").exists()
write(out / "review.json", proof)
write(intake_path.with_name("joint-receipt.json"), {**intake, "joint_verification_passed": True, "joint_finished_at": finished, "joint_evidence": evidence})
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
for identity in ("SCAN-SESSION-R12", "CONTRACT-VALIDATION-R12", "SCAN-CHECKPOINT-R17", "COORD-BOUND-EVENTS-R17"):
    assert rows[identity]["integrated"]
    rows[identity].update(status="accepted_intaken_joint_passed_bounded_slice", joint_verification=True, joint_evidence=evidence, joint_finished_at=finished, whole_package_complete=False, checked_at=at)
rows["CURRENT-JOINT-R17"].update(status="passed_current_intaken_slice", evidence=evidence, finished_at=finished, result={"passed": count, "failed": 0, "errors": 0, "skipped": 0}, quality_checks="six commands exit0", checked_at=at)
ledger["current_accepted_stage"] = {**proof, "current_root_status": f"R17 {count} passed/current {len(source['after'])} hashes; new R18 parallel work not intaken; whole packages open"}
ledger["updated_at"] = at
write(path, ledger)
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, current_joint=out.relative_to(ROOT).as_posix(), current_joint_finished_at=finished, current_joint_status="passed_current_intaken_bounded_slices", current_joint_result={"passed": count, "failed": 0, "errors": 0, "skipped": 0, "quality_commands_passed": 6, "source_inputs": len(source["after"])}, current_root_status=ledger["current_accepted_stage"]["current_root_status"], latest_joint_attempt=(out / "review.json").relative_to(ROOT).as_posix(), latest_joint_attempt_passed=True, prior_pass_is_current_root=True, last_verified_root_joint=evidence, active_phase="R17 joint passed; accept isolated R18 deliveries without whole-package claims", whole_packages_complete=False)
write(path, continuation)
note = f"## {at} · R17 current-root joint passed\n\nActual finish {finished}: {count} passed, zero failures/errors/skips, {source['test_file_count']} test files, six commands exit0. {len(source['after'])} input hashes and native/launcher stable; default fd/ext4 retained. Evidence {evidence}. Intake 29 files: artifacts/intake-batch-r17-20261015/joint-receipt.json. R16 1207 historical. R18 development and DSH/Astra deliveries remain separate; no whole-package/real-project/formal/portable claim.\n\n---\n\n"
for filename in ("PROGRESS.md", "DAG.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"passed": count, "finished_at": finished, "receipt": str(out / "review.json")}))
