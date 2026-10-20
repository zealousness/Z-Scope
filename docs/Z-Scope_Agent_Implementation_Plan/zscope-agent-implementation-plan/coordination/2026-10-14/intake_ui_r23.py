"""Intake only independently accepted frozen bytes, preserving backups."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

prepared = read(ROOT / "artifacts/coordinator-recovery-r23-20261016/prepared.json")
stage = ROOT / prepared["coordinator_workspace"]
prior = read(ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/source-evidence.json")["after"]
expected = {r["path"]: r["sha256"] for r in prepared["files"]}
ui_path = ROOT / "artifacts/coordinator-ui-r23-independent-20261016/review.json"
ui = read(ui_path)
assert ui["independent_acceptance_passed"] and ui["resource_lock_verified"]
assert ui["root_unchanged"] and ui["source_unchanged"] and ui["producer_frozen_outputs_unchanged"]
assert ui["before"] == ui["after"] == expected
assert len(ui["commands"]) == 9 and all(r["returncode"] == 0 for r in ui["commands"])
assert all(ui["junit"][k] == 0 for k in ("failures", "errors", "skipped"))
assert ui["all_13_producer_test_files_and_junit_identities_preserved"]
projection_path = ROOT / "artifacts/coordinator-coverage-projection-r21-final-20261016/review.json"
projection = read(projection_path)
assert projection["projection_dependency_checks_passed"] and projection["source_unchanged_during_verification"] and projection["root_current_bytes_unchanged"]
assert projection["independent_acceptance"] is False
assert projection["junit"]["tests"] == 117 and all(projection["junit"][k] == 0 for k in ("failures", "errors", "skipped"))
assert len(projection["commands"]) == 4 and all(r["returncode"] == 0 for r in projection["commands"])
static_path = ROOT / "artifacts/coverage-projection-review-r21-20261016/final-staged-review.json"
assert sha(static_path) == "48e37b0422b43a02f4e784fef7fedb7caec13a2a5252ff0011d268014fa3aa59"
projection_static = read(static_path)
assert projection_static["source_review_passed"] and all(expected[p] == h for p, h in projection_static["delivered_hashes"].items())
launcher_review = read(ROOT / "artifacts/root-launcher-review-r23-20261016/final-review.json")
assert launcher_review["source_review_passed"] and launcher_review["tests_executed"] == 0
required_helpers = {str((HERE / name).relative_to(ROOT)) for name in (
    "intake_ui_r23.py", "verify_current_root_r23.py", "verify_joint_with_clock_r23.py",
    "root_runtime_preflight_r23.py", "publish_joint_r23.py", "publish_current_root_checked_r23.py",
)}
assert set(launcher_review["reviewed_hashes"]) == required_helpers
assert all(sha(ROOT / p) == h for p, h in launcher_review["reviewed_hashes"].items())
assert all(sha(ROOT / p) == h for p, h in prior.items()), "Root drift requires reconciliation"
assert all(sha(stage / p) == h for p, h in expected.items()), "Accepted stage drift"
producer = ROOT / ".coordination/20261014/workspaces/astra-stop-coverage-ux-r21"
producer_expected = dict(expected)
producer_expected["requirements/portable/web-assets.lock.json"] = prepared["asset_lock"]["before"]
assert all(sha(producer / p) == h for p, h in producer_expected.items()), "Frozen producer source drift"
assert all(sha(producer / p) == h for p, h in prepared["producer_hashes"].items())
changes = {p for p, h in expected.items() if prior.get(p) != h}
assert changes == {
    "zscope/reporting/acceptance.py", "tests/test_coverage_gap_provenance.py",
    "docs/modules/interfaces-reporting.md", "tests/test_agent_integration_boundaries.py",
    "tests/fixtures/agent_workbench_ui.cjs", "tests/fixtures/instance_coverage_ui.cjs",
    "tests/fixtures/ux_capability_boundaries_ui.cjs", "tests/test_ux_capability_boundaries_ui.py",
    "zscope/web/static/dashboard_workbench.js", "zscope/web/static/index.html",
    "requirements/portable/web-assets.lock.json",
}
assert len(expected) == 1059 and len(prior) == 1056
assert all(not (ROOT / p).exists() for p in changes - set(prior)), "New path already exists"
out = ROOT / "artifacts/intake-ui-projection-r23-20261016"
out.mkdir(exist_ok=False)
files = []
for p in sorted(changes):
    target = ROOT / p
    before = sha(target)
    assert before == prior.get(p)
    backup = out / "backups" / p
    if before is not None:
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(target.read_bytes())
        assert sha(backup) == before
    files.append({"path": p, "before": before, "after": expected[p], "backup": backup.relative_to(ROOT).as_posix() if before is not None else None})
write(out / "intent.json", {"files": files, "expected_root": expected, "ui_review_sha256": sha(ui_path), "projection_review_sha256": sha(projection_path)})
for row in files:
    target = ROOT / row["path"]
    assert sha(target) == row["before"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((stage / row["path"]).read_bytes())
    assert sha(target) == row["after"]
assert all(sha(ROOT / p) == h for p, h in expected.items())
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
receipt = {"finished_at": at, "files": files, "expected_root": expected, "source_inputs": len(expected), "frozen_producer_source_inputs_checked": len(producer_expected), "independent_acceptance_passed": True, "ui_review": ui_path.relative_to(ROOT).as_posix(), "ui_review_sha256": sha(ui_path), "projection_review": projection_path.relative_to(ROOT).as_posix(), "projection_review_sha256": sha(projection_path), "projection_static_review_sha256": sha(static_path), "resource_lock_verified": True, "joint_verification_passed": False, "whole_packages_complete": False}
write(out / "receipt.json", receipt)
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
for key in ("ASTRA-STOP-COVERAGE-UX-R21", "COORD-COVERAGE-PROJECTION-R21"):
    rows[key].update(status="independent_accepted_intaken_current_joint_pending", artifact_available=True, independent_acceptance=True, integrated=True, joint_verification=False, intake_evidence=(out / "receipt.json").relative_to(ROOT).as_posix(), checked_at=at)
rows["ASTRA-STOP-COVERAGE-UX-R21"].update(independent_evidence=receipt["ui_review"], independent_finished_at=ui["finished_at"])
rows["CURRENT-JOINT-R22"].update(is_current_root=False, superseded_by="CURRENT-JOINT-R23", historical_pass_retained=True)
assert "CURRENT-JOINT-R23" not in rows
ledger["tasks"].append({"id": "CURRENT-JOINT-R23", "status": "ui_projection_intaken_complete_union_pending", "depends_on": ["ASTRA-STOP-COVERAGE-UX-R21", "COORD-COVERAGE-PROJECTION-R21"], "is_current_root": True, "artifact_available": False, "independent_acceptance": False, "integrated": True, "joint_verification": False, "whole_package_complete": False, "checked_at": at})
ledger.update(updated_at=at, current_root_status="R23 UI/projection intake11; current complete selected union pending; R22 historical")
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, current_joint_status="R23 intake complete; current joint pending", prior_pass_is_current_root=False, latest_joint_attempt_passed=False, active_phase="R23 full preserved collection and six quality commands pending", whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
print(json.dumps({"finished_at": at, "changed_files": len(files), "root_inputs": len(expected), "receipt": (out / "receipt.json").relative_to(ROOT).as_posix(), "joint_passed": False}), flush=True)
