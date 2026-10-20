"""Publish only a complete, stable R23 collection with all prior cases retained."""
from pathlib import Path
from collections import Counter
import copy
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016"

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def cases(p):
    return Counter((c.get("classname"), c.get("name")) for c in ET.parse(p).getroot().iter("testcase"))

source = read(OUT / "source-evidence.json")
assert not (OUT / "review.json").exists()
assert source["before"] == source["after"] and source["direct_source_unchanged"]
assert len(source["commands"]) == 6 and all(r["returncode"] == 0 for r in source["commands"])
assert all(sha(ROOT / p) == h for p, h in source["after"].items())
assert source["native_before"] == source["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
assert sha(Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")) == source["native_after"]
assert source["launcher_before"] == source["launcher_after"] == sha(OUT / "launcher.py")
assert source["pytest_capture"] == "fd (unchanged default)" and source["temporary_directory"].startswith("/tmp/") and source["test_slot_wrappers"] == 1
runtime = read(OUT / "runtime-preflight.json")
assert runtime == source["runtime_preflight"] and runtime["passed"] and runtime["ext4_unlinked_fd_truncate"]
assert runtime["coordinator_test_slot"] == source["test_slot"] and source["test_slot"]["exclusive_lock_already_held"]
assert runtime["temporary_mount"][1] == "ext4" and runtime["wsl_process_inspection"] is False
assert all(runtime["tools"][n] for n in ("clang", "clang++", "gcc", "cmake", "clangd", "node"))
assert source["parallel_timing_assertion_unchanged"]
assert source["after"]["tests/test_subagents_parallel.py"] == "1a7e5a43ce8ae095a9e802e16f307a9f0640c7b61ba5c4c68c439bee36c48699"
clock = read(OUT / "clock-observations.json")
assert not clock["clock_adjusted"] and not clock["test_or_timeout_modified"]
assert clock["launcher_before"] == clock["launcher_after"] == source["launcher_after"]
assert clock["test_slot"] == source["test_slot"]
intake_path = ROOT / source["intake_receipt"]
intake = read(intake_path)
assert sha(intake_path) == source["intake_sha256"] and intake["independent_acceptance_passed"] and intake["resource_lock_verified"]
assert len(intake["files"]) == 11
assert all(source["after"][p] == h for p, h in intake["expected_root"].items())
prior_dir = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016"
prior = read(prior_dir / "source-evidence.json")
assert sha(prior_dir / "source-evidence.json") == source["r22_source_sha256"]
expected = dict(prior["after"])
for row in intake["files"]:
    assert expected.get(row["path"]) == row["before"]
    if row["before"] is not None:
        assert sha(ROOT / row["backup"]) == row["before"]
    expected[row["path"]] = row["after"]
assert expected == intake["expected_root"]
old_commands = copy.deepcopy([r["command"] for r in prior["commands"]])
old_tests = [p for p in old_commands[0] if p.endswith(".py")]
additions = ["tests/test_coverage_gap_provenance.py", "tests/test_ux_capability_boundaries_ui.py"]
python = source["commands"][0]["command"][0]
old_commands[0] = [python, "-m", "pytest", "-q", *old_tests, *additions, f"--junitxml={OUT / 'results.xml'}"]
old_commands[4] += additions
for command in old_commands:
    command[0] = python
assert [r["command"] for r in source["commands"]] == old_commands
assert source["test_file_count"] == 171 and len(old_tests) == 169 and source["r22_ordered_collection_preserved"]
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
assert suites and all(int(s.get(k, "0")) == 0 for s in suites for k in ("failures", "errors", "skipped"))
count = sum(int(s.get("tests", "0")) for s in suites)
new_cases = cases(OUT / "results.xml")
assert count == sum(new_cases.values()) and count >= 2539
references = [
    "artifacts/coordinator-r19-all-intaken-20261015/results.xml",
    "artifacts/coordinator-r20-job-cli-intaken-20261015/results.xml",
    "artifacts/coordinator-r21-verified-environment-20261015/results.xml",
    "artifacts/coordinator-r22-unchanged-union-20261016/results.xml",
    "artifacts/coordinator-coverage-projection-r21-final-20261016/results.xml",
    "artifacts/coordinator-ui-r23-independent-20261016/results.xml",
    ".coordination/20261014/workspaces/astra-stop-coverage-ux-r21/artifacts/stop-coverage-ux-r21/self/final-01/pytest.xml",
]
for path in references:
    missing = cases(ROOT / path) - new_cases
    assert not missing, (path, list(missing.items())[:5])
for key in ("ui_review", "projection_review"):
    assert sha(ROOT / intake[key]) == intake[key + "_sha256"]
assert read(ROOT / intake["ui_review"])["independent_acceptance_passed"]
projection = read(ROOT / intake["projection_review"])
assert projection["projection_dependency_checks_passed"] and projection["source_unchanged_during_verification"] and projection["root_current_bytes_unchanged"]
assert projection["independent_acceptance"] is False
assert projection["junit"]["tests"] == 117 and all(projection["junit"][k] == 0 for k in ("failures", "errors", "skipped"))
assert len(projection["commands"]) == 4 and all(r["returncode"] == 0 for r in projection["commands"])
projection_static_path = ROOT / "artifacts/coverage-projection-review-r21-20261016/final-staged-review.json"
assert sha(projection_static_path) == intake["projection_static_review_sha256"] == "48e37b0422b43a02f4e784fef7fedb7caec13a2a5252ff0011d268014fa3aa59"
projection_static = read(projection_static_path)
assert projection_static["source_review_passed"] and all(source["after"][p] == h for p, h in projection_static["delivered_hashes"].items())
static = read(ROOT / "artifacts/root-launcher-review-r23-20261016/final-review.json")
assert static["source_review_passed"] and static["tests_executed"] == 0
for p, h in static["reviewed_hashes"].items():
    assert source["after"][p] == h == sha(ROOT / p)
guard = read(OUT / "publication-guard.json")
assert guard["live_source_matches"] and guard["review_sha256"] == sha(ROOT / "artifacts/root-launcher-review-r23-20261016/final-review.json")
assert guard["source_evidence_sha256"] == sha(OUT / "source-evidence.json")
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
finished = dt.datetime.fromisoformat(source["captured_at"]).astimezone(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = {"verified_at": at, "finished_at": finished, "passed": count, "failed": 0, "errors": 0, "skipped": 0,
    "commands_passed": 6, "commands_expected": 6, "commands": source["commands"], "pytest_file_count": 171,
    "bound_input_files": len(source["after"]), "source_evidence": (OUT / "source-evidence.json").relative_to(ROOT).as_posix(),
    "current_bytes_match": True, "is_current_root": True, "all_current_selected_validation_passed": True,
    "all_current_root_validation_passed": False, "full_repository_suite_run": False, "whole_packages_complete": False,
    "all_prior_junit_cases_preserved": True, "all_independent_collections_preserved": True, "junit_reference_paths": references,
    "intake_receipt": intake_path.relative_to(ROOT).as_posix(), "intake_changed_files": 11,
    "ui_independent_review": intake["ui_review"], "projection_independent_review": intake["projection_review"],
    "pytest_capture": source["pytest_capture"], "runtime_preflight": runtime, "native_tool_sha256": source["native_after"],
    "clock_problem_resolved": False, "clock_observations": (OUT / "clock-observations.json").relative_to(ROOT).as_posix(),
    "historical_failures_retained": references[1:3], "launchers_independently_reviewed": True,
    "scope": source["scope"]}
write(OUT / "review.json", proof)
write(intake_path.with_name("joint-receipt.json"), {**intake, "joint_verification_passed": True, "joint_finished_at": finished, "joint_evidence": proof["source_evidence"]})
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
for key in ("ASTRA-STOP-COVERAGE-UX-R21", "COORD-COVERAGE-PROJECTION-R21"):
    assert rows[key]["integrated"] and rows[key]["independent_acceptance"]
    rows[key].update(status="independent_accepted_intaken_current_joint_passed_bounded_slice", joint_verification=True, joint_evidence=proof["source_evidence"], joint_finished_at=finished, checked_at=at, whole_package_complete=False)
rows["CURRENT-JOINT-R23"].update(status="current_complete_selected_union_six_commands_passed", artifact_available=True, independent_acceptance=True, joint_verification=True, evidence=(OUT / "review.json").relative_to(ROOT).as_posix(), finished_at=finished, result={"passed": count, "failed": 0, "errors": 0, "skipped": 0}, checked_at=at)
rows["CURRENT-JOINT-R22"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R23")
ledger.update(updated_at=at, current_accepted_stage=proof, current_root_status=f"R23 {count}/six strict commands passed; selected union171, full packages and real-project effects open")
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, current_joint=OUT.relative_to(ROOT).as_posix(), current_joint_finished_at=finished, current_joint_status="R23 complete selected union six commands passed", current_joint_result={"passed": count, "failed": 0, "errors": 0, "skipped": 0, "commands_passed": 6}, latest_joint_attempt=(OUT / "review.json").relative_to(ROOT).as_posix(), latest_joint_attempt_passed=True, prior_pass_is_current_root=True, active_phase="S01/S08 contracts and remaining dependency work; real-project effects open", whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"## {at} · R23 UI/projection integrated and current selected union passed\n\nActual final proof {finished}: {count} passed, zero failure/error/skip, all171 files and six commands retained. Intake11 changes with backups; all prior R22/independent JUnit identities preserved without adding counts. Evidence {proof['source_evidence']}. UI producer /root/astra_instance_ui_r18; independent UI receipt {intake['ui_review']}. Native dual-macro/owner/SQLite/HTTP/desktop-mobile evidence is a bounded fixture; other reports/scanners are synthetic. Host clock issue, full packages, actual LLM/real-project accuracy, formal and portable acceptance remain open. S01/S08 revision design source review failed; no backend implementation dispatched from those drafts.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R23.md").write_text(note, encoding="utf-8", newline="\n")
print(json.dumps({"passed": count, "finished_at": finished, "files": 171, "commands": 6, "receipt": (OUT / "review.json").relative_to(ROOT).as_posix()}), flush=True)
