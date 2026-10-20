"""Publish a fully passed current R18 root, retaining every failed prior attempt."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts" / (sys.argv[1] if len(sys.argv)>1 else "coordinator-r18-queue-receipt-repaired-20261015")
def read(path):
    return json.loads(path.read_text(encoding="utf-8"))
def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
source = read(out / "source-evidence.json")
assert source["direct_source_unchanged"] and source["before"] == source["after"]
assert len(source["commands"]) == 6 and all(r["returncode"] == 0 for r in source["commands"])
assert source["native_before"] == source["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
assert source["launcher_before"] == source["launcher_after"] == hashlib.sha256((out / "launcher.py").read_bytes()).hexdigest()
assert source["pytest_capture"] == "fd (unchanged default)" and source["temporary_directory"].startswith("/tmp/")
assert source["astra_instance_native_ui_r18_integrated"]
assert source["test_file_count"] >= 132
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
suites = ET.parse(out / "results.xml").getroot().findall("testsuite")
assert suites and all(s.get(k) == "0" for s in suites for k in ("failures", "errors", "skipped"))
count = sum(int(s.get("tests", "0")) for s in suites)
assert count >= 2079
intake_path = ROOT / "artifacts/intake-ui-doc-r18-20261015/receipt.json"
intake = read(intake_path)
migration = read(ROOT / "artifacts/intake-ui-queue-receipt-r19-20261015/receipt.json")
for row in intake["files"]:
    expected = migration["after_sha256"] if row["path"] == migration["path"] else row["after"]
    assert source["after"][row["path"]] == expected
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
evidence = (out / "source-evidence.json").relative_to(ROOT).as_posix()
proof = {"verified_at": at, "finished_at": finished, "passed": count, "failed": 0, "errors": 0, "skipped": 0, "quality_commands_passed": 6, "quality_commands": 6, "pytest_file_count": source["test_file_count"], "bound_input_files": len(source["after"]), "source_evidence": evidence, "current_bytes_match": True, "is_current_root": True, "whole_package_complete": False, "pytest_capture": source["pytest_capture"], "native_tool_sha256": source["native_after"], "commands": source["commands"], "intaken_features": {"r17_exact_instances_contracts_whole_plan_checkpoint": True, "astra_native_instance_ui_r18": True, "fixed_bound_lightweight_metadata": True, "identity_module_docs": True, "new_inner_validation_context_r18": False, "new_config_stop_at_r18": False}, "scope": "Current selected 132-plus-file joint, preserving entire R17 collection and adding real native dual-macro ScanSession/owner/SQLite/bound-HTTP desktop/mobile UI plus metadata/queue-receipt checks. Old synthetic/control model/scanner fixtures retain their limits. Not the full repository test collection, complete S01/S08/U01, actual project/model accuracy, formal benchmark or portable smoke. New inner-context and config-stop-at branches remain isolated and unaccepted."}
assert not (out / "review.json").exists()
extra_path = ROOT / "artifacts/coordinator-current-native-replay-r19-20261015/review.json"
extra = read(extra_path)
proof["additional_current_root_native_replay"] = {"review": extra_path.relative_to(ROOT).as_posix(), "junit": extra["junit"], "passed": extra["passed"], "status": "27 passed/1 old hot-baseline assertion failed; isolated S07 diagnosis pending", "included_in_this_132_file_collection": False}
proof["all_current_root_validation_passed"] = False
proof["clock_problem_resolved"] = False
if (out / "clock-observations.json").is_file():
    proof["clock_observations"] = (out / "clock-observations.json").relative_to(ROOT).as_posix()
write(out / "review.json", proof)
write(intake_path.with_name("joint-receipt.json"), {**intake, "joint_verification_passed": True, "joint_finished_at": finished, "joint_evidence": evidence, "test_queue_receipt_migration": migration})
path = HERE / "tasks.json"
ledger = read(path)
rows = {r["id"]: r for r in ledger["tasks"]}
for identity in ("ASTRA-INSTANCE-UI-R18", "DOC-IDENTITY-R18"):
    assert rows[identity]["integrated"] and rows[identity]["independent_acceptance"]
    rows[identity].update(status="independent_accepted_intaken_joint_passed_bounded_slice", joint_verification=True, joint_evidence=evidence, joint_finished_at=finished, whole_package_complete=False, checked_at=at)
rows["CURRENT-JOINT-R18"].update(status="passed_current_intaken_slice", evidence=evidence, finished_at=finished, result={"passed": count, "failed": 0, "errors": 0, "skipped": 0}, quality_checks="six commands exit0", checked_at=at)
ledger["current_accepted_stage"] = {**proof, "current_root_status": f"R18 selected {count}/six commands passed/current {len(source['after'])} input hashes; extra current native replay27/1 remains unresolved, inner-context and config-stop-at branches not intaken; whole packages open"}
ledger["updated_at"] = at
write(path, ledger)
path = HERE / "continuation-r6.json"
continuation = read(path)
continuation.update(updated_at=at, current_joint=out.relative_to(ROOT).as_posix(), current_joint_finished_at=finished, current_joint_status="passed_current_intaken_bounded_slices", current_joint_result={"passed": count, "failed": 0, "errors": 0, "skipped": 0, "quality_commands_passed": 6, "source_inputs": len(source["after"])}, current_root_status=ledger["current_accepted_stage"]["current_root_status"], latest_joint_attempt=(out / "review.json").relative_to(ROOT).as_posix(), latest_joint_attempt_passed=True, prior_pass_is_current_root=True, last_verified_root_joint=evidence, active_phase="Current R18 UI/doc root passed; isolate and independently repair remaining context/deadline boundaries", whole_packages_complete=False)
write(path, continuation)
note = f"## {at} · R18 current selected joint passed\n\nActual finish {finished}: {count} passed, zero failures/errors/skips, {source['test_file_count']} test files, six commands exit0. {len(source['after'])} input hashes/native/launcher stable. Evidence {evidence}. Extra current-root native replay remains27/1 at artifacts/coordinator-current-native-replay-r19-20261015/review.json and is outside this132-file collection; all current-root validation is NOT complete. The R18 prior failure2078/1 and unresolved clock changes remain, and native UI queue locator migration preserves original assertions with actual job/run/input SQL receipt checks. R17 2069 is historical after UI/doc intake. Inner context and config-stop-at delivery/repair receipts remain separate and unaccepted; whole packages and real-project/formal/portable effects remain open. Counts from independent collections are not added.\n\n---\n\n"
for filename in ("PROGRESS.md", "DAG.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"passed": count, "finished_at": finished, "receipt": str(out / "review.json")}))
