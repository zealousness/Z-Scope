"""Publish only an unchanged, complete R20 union and retain earlier failures."""
from pathlib import Path
from collections import Counter
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016"
OLD = ROOT / "artifacts/coordinator-r19-all-intaken-20261015"
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
assert all(source[k] for k in ("r19_all_independent_collections_preserved", "r20_all_independent_collections_preserved", "r20_owner_cli_window_integrated", "r20_first_cause_integrated"))
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
assert {str((HERE / name).relative_to(ROOT)) for name in ("test_slot.py", "verify_joint_with_clock_r21.py")} <= set(source["after"])
clock = read(OUT / "clock-observations.json")
assert not clock["clock_adjusted"] and not clock["test_or_timeout_modified"]
assert clock["launcher_before"] == clock["launcher_after"] == source["launcher_after"]
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
assert suites and all(s.get(k) == "0" for s in suites for k in ("failures", "errors", "skipped"))
count = sum(int(s.get("tests", "0")) for s in suites)
assert count >= 2539 and source["test_file_count"] >= 154
# Preserve every previous JUnit case, including parameter identities, in
# addition to the launcher's complete test-file/source inventory proof.
old_cases = Counter((c.get("classname"), c.get("name")) for c in ET.parse(OLD / "results.xml").getroot().iter("testcase"))
new_cases = Counter((c.get("classname"), c.get("name")) for c in ET.parse(OUT / "results.xml").getroot().iter("testcase"))
assert old_cases <= new_cases, list((old_cases - new_cases).items())[:10]
failed_cases = Counter((c.get("classname"), c.get("name")) for c in ET.parse(ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015/results.xml").getroot().iter("testcase"))
assert failed_cases <= new_cases, list((failed_cases - new_cases).items())[:10]
r21_cases = Counter((c.get("classname"), c.get("name")) for c in ET.parse(ROOT / "artifacts/coordinator-r21-verified-environment-20261015/results.xml").getroot().iter("testcase"))
assert r21_cases <= new_cases
probe_path = ROOT / "artifacts/subagent-parallel-probe-r22-20261016/review.json"
assert hashlib.sha256(probe_path.read_bytes()).hexdigest() == source["parallel_probe_sha256"]
assert source["parallel_timing_assertion_unchanged"]
assert source["after"]["tests/test_subagents_parallel.py"] == "1a7e5a43ce8ae095a9e802e16f307a9f0640c7b61ba5c4c68c439bee36c48699"
runtime = read(OUT / "runtime-preflight.json")
assert runtime["passed"] and runtime["ext4_unlinked_fd_truncate"] and runtime["temporary_mount"][1] == "ext4"
assert all(runtime["tools"][n] for n in ("clang", "clang++", "gcc", "cmake", "clangd", "node"))
assert runtime["native_sha256"] == source["native_after"]
fixture_intake = read(ROOT / source["fixture_intake"])
assert fixture_intake["isolated_acceptance_passed"] and fixture_intake["independent_static_review_passed"] and not fixture_intake["product_changed"]
assert len(fixture_intake["files"]) == 2
for r in fixture_intake["files"]:
    assert source["after"][r["path"]] == r["after"]
intake_path = ROOT / "artifacts/intake-job-cli-window-r20-20261015/receipt.json"
intake = read(intake_path)
assert len(intake["files"]) == 9
for r in intake["files"]:
    assert source["after"][r["path"]] == r["after"]
assert len(intake["launcher_updates"]) == 1
for r in intake["launcher_updates"]:
    assert r["before"] == "7f67c4a69c51eaffc452c681f3443a461a8ca9c76474dc3f8622575aa20396d6"
    assert source["after"][r["path"]] == r["after"] == "7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158"
reviews = {}
for identity, label in (("U01-JOB-CLI-WINDOW-R20", "coordinator-job-cli-window-r20-final-acceptance-20261015"), ("U01-FIRST-CAUSE-R20", "coordinator-first-cause-r20-final-acceptance-20261015")):
    review = read(ROOT / "artifacts" / label / "review.json")
    assert review["independent_acceptance_passed"] and review["source_unchanged"] and review["independent_probes_unchanged"]
    assert len(review["commands"]) == 4 and all(r["returncode"] == 0 for r in review["commands"])
    assert all(review["junit"][k] == "0" for k in ("errors", "failures", "skipped"))
    assert all(source["after"][p] == h for p, h in review["delivered_hashes"].items())
    reviews[identity] = {"task_id": review["task_id"], "review": "artifacts/" + label + "/review.json", "finished_at": review["finished_at"], "junit": review["junit"]}
required_probes = {"test_job_cli_effective_window_boundary.py", "test_job_cli_window_identity_boundary.py", "test_job_cli_window_snapshot_boundary.py", "test_job_cli_window_store_binding_boundary.py", "test_stop_first_cause_observation_boundary.py"}
pytest_files = {Path(p).name for p in source["commands"][0]["command"] if p.endswith(".py")}
assert required_probes <= pytest_files
prior_source = read(OLD / "source-evidence.json")
overrides = {r["path"]: r["after"] for r in intake["files"]}
overrides.update({r["path"]: r["after"] for r in intake["launcher_updates"]})
overrides.update({r["path"]: r["after"] for r in fixture_intake["files"]})
assert all(source["after"][p] == overrides.get(p, h) for p, h in prior_source["after"].items())
assert not (OUT / "review.json").exists()
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
evidence = (OUT / "source-evidence.json").relative_to(ROOT).as_posix()
proof = {"verified_at": at, "finished_at": finished, "passed": count, "failed": 0, "errors": 0, "skipped": 0, "commands_passed": 6, "commands_expected": 6, "pytest_file_count": source["test_file_count"], "bound_input_files": len(source["after"]), "source_evidence": evidence, "current_bytes_match": True, "is_current_root": True, "whole_packages_complete": False, "pytest_capture": source["pytest_capture"], "native_tool_sha256": source["native_after"], "commands": source["commands"], "all_prior_junit_cases_preserved": True, "all_independent_collections_preserved": True, "additional_job_cli_and_first_cause_gates_included_and_passed": True, "all_current_selected_validation_passed": True, "full_repository_suite_run": False, "independent_deliveries": reviews, "intake_receipt": intake_path.relative_to(ROOT).as_posix(), "clock_problem_resolved": False, "clock_observations": (OUT / "clock-observations.json").relative_to(ROOT).as_posix(), "scope": "Entire prior R19 selected union plus both R20 independent collections and all original effective-window/identity/SQL snapshot/nonfinite/store/first-cause probes. Six unchanged strict Linux commands; native and browser collection retained. Original failures, failed network continuations, MCP revisionConflict timing history and host clock observations retained. No full S01/S07/S08/U01, full repository, actual LLM/real-project accuracy, formal benchmark or portable smoke acceptance. Independent counts are not added."}
proof.update(runtime_preflight=runtime, fixture_intake=source["fixture_intake"], preserved_failed_trial="artifacts/coordinator-r20-job-cli-intaken-20261015/review.json", all_current_root_validation_passed=False, additional_ui_audit={"logical_task": "ASTRA-UX-REMAINING-AUDIT-R21", "artifact_directory": "artifacts/astra-ux-remaining-audit-r21-20261015", "coordinator_static_review_confirmed": True, "product_changed": False, "independent_failure_probe_run": False, "issues": ["UI stop-window/default-config and process-only wording lags implemented runtime", "acceptance._coverage_gaps maps every false scan coverage to analysis-unwired even when instance analysis exists"], "status": "next batch remediation; separate from this passing selected union"})
write(OUT / "review.json", proof)
write(intake_path.with_name("joint-receipt.json"), {**intake, "joint_verification_passed": True, "joint_finished_at": finished, "joint_evidence": evidence})
path = HERE / "tasks.json"
ledger = read(path)
rows = {r["id"]: r for r in ledger["tasks"]}
for identity in source["r19_integrated_tasks"] + list(reviews):
    row = rows[identity]
    assert row["integrated"] and row["independent_acceptance"]
    row.update(status="independent_accepted_intaken_current_joint_passed_bounded_slice", joint_verification=True, joint_evidence=evidence, joint_finished_at=finished, whole_package_complete=False, checked_at=at)
    if identity in reviews:
        row["consecutive_failed_actual_deliveries"] = 0
rows["CURRENT-JOINT-R22"].update(status="current_complete_selected_union_six_commands_passed", artifact_available=True, independent_acceptance=True, joint_verification=True, is_current_root=True, evidence=evidence, finished_at=finished, result={"passed": count, "failed": 0, "errors": 0, "skipped": 0}, quality_checks="six commands exit0", all_current_selected_validation_passed=True, all_current_root_validation_passed=False, additional_ui_audit=proof["additional_ui_audit"], full_repository_suite_run=False, checked_at=at)
rows["COORD-ROOT-FIXTURES-R21"].update(status="reviewed_test_fixtures_intaken_current_joint_passed", joint_verification=True, joint_evidence=evidence, joint_finished_at=finished, checked_at=at)
rows["CURRENT-JOINT-R19"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R22")
rows["CURRENT-JOINT-R20"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R22", failure_receipt="artifacts/coordinator-r20-job-cli-intaken-20261015/review.json")
rows["CURRENT-JOINT-R21"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R22", failure_receipt="artifacts/coordinator-r21-verified-environment-20261015/review.json")
ledger["current_accepted_stage"] = {**proof, "current_root_status": f"R22 selected full union {count}/six commands passed, including all new SQL/identity/first-cause gates; separate UI wording/projection defects and whole packages/real-project effects open"}
ledger["updated_at"] = at
write(path, ledger)
path = HERE / "continuation-r6.json"
continuation = read(path)
continuation.update(updated_at=at, current_joint=OUT.relative_to(ROOT).as_posix(), current_joint_finished_at=finished, current_joint_status="current_complete_selected_union_six_commands_passed", current_joint_result={"passed": count, "failed": 0, "errors": 0, "skipped": 0, "commands_passed": 6, "source_inputs": len(source["after"])}, current_root_status=ledger["current_accepted_stage"]["current_root_status"], latest_joint_attempt=(OUT / "review.json").relative_to(ROOT).as_posix(), latest_joint_attempt_passed=True, prior_pass_is_current_root=True, last_verified_root_joint=evidence, active_phase="R22 current union passed; remaining full-package dependency work requires explicit ownership partition", whole_packages_complete=False)
for key in ("native_active_job_cli", "native_active_first_cause"):
    if key in continuation:
        continuation[key].update(status="completed_independently_accepted_intaken_current_joint_passed", integrated=True, independent_acceptance=True, joint_evidence=evidence)
write(path, continuation)
note = f"## {at} · R22 current selected full union passed\n\nActual final proof {finished}: {count} passed, zero failures/errors/skips, {source['test_file_count']} test files, six commands exit0, {len(source['after'])} source inputs stable with native/launcher. Entire prior R19 JUnit and both R20 independent collections preserved; all original owner-window/identity/SQL snapshot/nonfinite/store and cancellation-observation probes included. Evidence {evidence}; intake9 files with backups and exact SHA in {intake_path.relative_to(ROOT).as_posix()}. Producers: {reviews['U01-JOB-CLI-WINDOW-R20']['task_id']} and {reviews['U01-FIRST-CAUSE-R20']['task_id']}. Historical GLM first-delivery3 failures, network-only continuation failures, original MCP optimistic-conflict timing result and unresolved wall-clock observations retained. No count addition, full repository, whole packages, real-project/model/formal/portable claim.\n\n---\n\n"
for filename in ("PROGRESS.md", "DAG.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"passed": count, "finished_at": finished, "test_files": source["test_file_count"], "receipt": str(OUT / "review.json"), "additional_gates_passed": True}), flush=True)
