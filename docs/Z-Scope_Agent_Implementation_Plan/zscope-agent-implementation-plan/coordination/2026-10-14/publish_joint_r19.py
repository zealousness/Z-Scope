"""Publish the R19 selected union without hiding the additional CLI gate."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r19-all-intaken-20261015"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

source = read(OUT / "source-evidence.json")
assert source["direct_source_unchanged"] and source["before"] == source["after"]
assert len(source["commands"]) == 6 and all(r["returncode"] == 0 for r in source["commands"])
assert source["native_before"] == source["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
assert source["launcher_before"] == source["launcher_after"] == hashlib.sha256((OUT / "launcher.py").read_bytes()).hexdigest()
assert source["pytest_capture"] == "fd (unchanged default)" and source["temporary_directory"].startswith("/tmp/")
assert source["r19_all_independent_collections_preserved"] and source["test_file_count"] >= 132
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
assert suites and all(s.get(k) == "0" for s in suites for k in ("failures", "errors", "skipped"))
count = sum(int(s.get("tests", "0")) for s in suites)
assert count >= 2314
intake_path = ROOT / "artifacts/intake-batch-r19-20261015/receipt.json"
intake = read(intake_path)
assert len(intake["files"]) == 22
for row in intake["files"]:
    assert source["after"][row["path"]] == row["after"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
evidence = (OUT / "source-evidence.json").relative_to(ROOT).as_posix()
gate_path = ROOT / "artifacts/coordinator-current-job-cli-window-r20-corrected-probes-20261015/review.json"
gate = read(gate_path)
assert gate["source_unchanged"] and gate["junit"]["tests"] == gate["junit"]["failures"] == "2"
assert set(gate["after"]) <= set(source["after"])
assert all(source["after"][p] == h for p, h in gate["after"].items())
assert not (OUT / "review.json").exists()
proof = {"verified_at": at, "finished_at": finished, "passed": count, "failed": 0, "errors": 0, "skipped": 0, "quality_commands_passed": 6, "quality_commands": 6, "pytest_file_count": source["test_file_count"], "bound_input_files": len(source["after"]), "source_evidence": evidence, "current_bytes_match": True, "is_current_root": True, "whole_package_complete": False, "pytest_capture": source["pytest_capture"], "native_tool_sha256": source["native_after"], "commands": source["commands"], "r19_all_independent_collections_preserved": True, "intaken_features": source["r19_integrated_tasks"], "additional_job_cli_gate": {"review": gate_path.relative_to(ROOT).as_posix(), "junit": gate["junit"], "finished_at": gate["finished_at"], "status": "two valid additional integration failures; isolated task_492e7a7037 dispatched, not accepted or intaken", "included_in_this_union": False}, "all_current_root_validation_passed": False, "clock_problem_resolved": False, "clock_observations": (OUT / "clock-observations.json").relative_to(ROOT).as_posix(), "scope": "Full R18 selected collection plus every test collection and frozen boundary probe from the three R19 independent deliveries, preserving native UI and six quality commands. This is not the full repository collection. Additional real Job owner-to-CLI effective-window gate failed outside this union, so overall current validation remains open. Accepted parent slices remain accepted. No full S01/S07/S08/U01, real-project/model accuracy, formal benchmark or portable smoke conclusion; independent test counts are not added."}
write(OUT / "review.json", proof)
write(intake_path.with_name("joint-receipt.json"), {**intake, "joint_verification_passed": True, "joint_finished_at": finished, "joint_evidence": evidence, "additional_job_cli_gate_passed": False})
path = HERE / "tasks.json"
ledger = read(path)
rows = {r["id"]: r for r in ledger["tasks"]}
for identity in source["r19_integrated_tasks"]:
    assert rows[identity]["integrated"] and rows[identity]["independent_acceptance"]
    rows[identity].update(status="independent_accepted_intaken_joint_passed_bounded_slice", joint_verification=True, joint_evidence=evidence, joint_finished_at=finished, whole_package_complete=False, checked_at=at)
rows["CURRENT-JOINT-R19"].update(status="selected_union_passed_additional_job_cli_gate_failed", evidence=evidence, finished_at=finished, result={"passed": count, "failed": 0, "errors": 0, "skipped": 0}, quality_checks="six commands exit0", all_current_root_validation_passed=False, additional_gate=proof["additional_job_cli_gate"], checked_at=at)
ledger["current_accepted_stage"] = {**proof, "current_root_status": f"R19 selected union {count}/six commands passed/current {len(source['after'])} input hashes; extra Job owner-to-CLI gate0/2 requires isolated repair; whole packages open"}
ledger["updated_at"] = at
write(path, ledger)
path = HERE / "continuation-r6.json"
continuation = read(path)
continuation.update(updated_at=at, current_joint=OUT.relative_to(ROOT).as_posix(), current_joint_finished_at=finished, current_joint_status="selected_union_passed_additional_job_cli_gate_failed", current_joint_result={"passed": count, "failed": 0, "errors": 0, "skipped": 0, "quality_commands_passed": 6, "source_inputs": len(source["after"])}, current_root_status=ledger["current_accepted_stage"]["current_root_status"], latest_joint_attempt=(OUT / "review.json").relative_to(ROOT).as_posix(), latest_joint_attempt_passed=True, prior_pass_is_current_root=True, last_verified_root_joint=evidence, active_phase="R19 union six commands passed; isolated actual Job owner-to-CLI effective-window consumer repair pending", additional_job_cli_gate=proof["additional_job_cli_gate"], whole_packages_complete=False)
write(path, continuation)
note = f"## {at} · R19 selected union passed; extra real CLI gate open\n\nActual final proof {finished}: {count} passed, zero failures/errors/skips, {source['test_file_count']} test files, six commands exit0; {len(source['after'])} source/native/launcher hashes stable. All three independent collections and entire R18 selected union preserved. Evidence {evidence}. Additional real owner/SQL/CLI/shared-token window probes failed2/2 at21:21:38 (explicit request ignored for actual CLI budget; resumed cleared SQL window reapplied from config), outside this selected union. Isolated repair task_492e7a7037 dispatched21:26:07, no delivery/independent acceptance/intake yet. Thus all current-root validation is not passed. Parent slices 1ef444cf29/4e43cb393d/7118aeca55 remain independently accepted/intaken and now selected-union passed; no count addition and no whole-package claim. Earlier valid failures and unresolved host clock observations retained. No real-project/model/formal/portable conclusion.\n\n---\n\n"
for filename in ("PROGRESS.md", "DAG.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"passed": count, "finished_at": finished, "test_files": source["test_file_count"], "receipt": str(OUT / "review.json"), "extra_gate_passed": False}), flush=True)
