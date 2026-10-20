"""Freeze the checked four-file coordinator dependency before UI dispatch."""
from pathlib import Path
from collections import Counter
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
def read(p):
    return json.loads(p.read_text(encoding="utf-8"))
def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
branch = ROOT / ".coordination/20261014/workspaces/astra-stop-coverage-ux-r21"
out = ROOT / "artifacts/coordinator-coverage-projection-r21-final-20261016"
proof = read(out / "review.json")
assert proof["projection_dependency_checks_passed"] and proof["junit"] == {"tests": 117, "failures": 0, "errors": 0, "skipped": 0}
assert len(proof["commands"]) == 4 and all(r["returncode"] == 0 for r in proof["commands"])
assert proof["before"] == proof["after"] and proof["root_current_bytes_unchanged"]
review_path = ROOT / "artifacts/coverage-projection-review-r21-20261016/final-staged-review.json"
assert sha(review_path) == "48e37b0422b43a02f4e784fef7fedb7caec13a2a5252ff0011d268014fa3aa59"
review = read(review_path)
assert review["source_review_passed"] and review["blocking_findings"] == [] and review["tests_executed"] == 0
assert review["root_unchanged"] and not review["product_changed"]
files = review["delivered_hashes"]
assert len(files) == 4
assert all(sha(branch / p) == h == proof["after"][p] for p, h in files.items())
assert all(sha(branch / p) == h for p, h in proof["after"].items())
gate = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016"
root_source = read(gate / "source-evidence.json")["after"]
assert read(gate / "review.json")["is_current_root"]
assert all(sha(ROOT / p) == h for p, h in root_source.items())
prior = ROOT / "artifacts/coordinator-coverage-projection-r21-after-20261016/results.xml"
def cases(path):
    return Counter((c.get("classname"), c.get("name")) for c in ET.parse(path).getroot().iter("testcase"))
assert cases(prior) <= cases(out / "results.xml")
first = read(ROOT / "artifacts/coordinator-coverage-projection-r21-before-20261016/review.json")
assert first["junit"]["failures"] == 4
assert first["after"]["tests/test_coverage_gap_provenance.py"] == files["tests/test_coverage_gap_provenance.py"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
dependency = {"captured_at": at, "logical_task": "COORD-COVERAGE-PROJECTION-R21", "coordinator_checks_passed": True, "independent_static_review_passed": True, "independent_functional_execution": False, "root_intaken": False, "root_joint_verification": False, "evidence": (out / "review.json").relative_to(ROOT).as_posix(), "static_review": review_path.relative_to(ROOT).as_posix(), "static_review_sha256": sha(review_path), "files": [{"path": p, "previous_sha256": root_source.get(p), "sha256": h, "readonly": True} for p, h in files.items()]}
path = HERE / "followups-r12/astra-stop-coverage-ux-r21-dependencies.json"
assert not path.exists()
write(path, dependency)
baseline_path = HERE / "followups-r12/astra-stop-coverage-ux-r21-baseline.json"
baseline = read(baseline_path)
assert baseline["dispatch_state"] == "not_dispatched_waiting_coordinator_projection_dependency"
baseline.update(dispatch_state="not_dispatched_checked_reviewed_dependency_ready", dependency_receipt=path.relative_to(HERE).as_posix(), dependency_ready_at=at)
baseline["task"]["depends_on"].append("ASTRA-COVERAGE-PROJECTION-REVIEW-R21")
write(baseline_path, baseline)
ledger = read(HERE / "tasks.json")
assert "COORD-COVERAGE-PROJECTION-R21" not in {r["id"] for r in ledger["tasks"]}
common = {"artifact_available": True, "independent_acceptance": False, "integrated": False, "joint_verification": False, "root_product_changed": False, "whole_package_complete": False, "checked_at": at}
ledger["tasks"].append({**common, "id": "COORD-COVERAGE-PROJECTION-R21", "depends_on": ["CURRENT-JOINT-R22", "ASTRA-UX-REMAINING-AUDIT-R21"], "owner": "Coordinator", "agent_kind": "coordinator", "status": "isolated_checks_and_independent_source_review_passed_readonly_dependency_not_intaken", "producer_status": "completed", "worker_finished_at": proof["finished_at"], "coordinator_checks_passed": True, "independent_static_review": True, "evidence": dependency["evidence"], "source_review": dependency["static_review"], "owns": list(files), "result": proof["junit"], "preserved_before_failure": "artifacts/coordinator-coverage-projection-r21-before-20261016/review.json", "preserved_old_assertion_failure": "artifacts/coordinator-coverage-projection-r21-integration_before-20261016/review.json"})
ledger["tasks"].append({**common, "id": "ASTRA-COVERAGE-PROJECTION-REVIEW-R21", "depends_on": ["COORD-COVERAGE-PROJECTION-R21"], "owner": "Astra", "agent_kind": "native_subagent", "agent_task_id": "/root/astra_first_cause_r20", "status": "four_file_readonly_final_review_passed_initial_block_preserved", "producer_status": "completed", "actual_execution_at": review["review_started_at"], "worker_finished_at": review["review_finished_at"], "independent_static_review": True, "tests_executed": 0, "evidence": dependency["static_review"], "initial_block_evidence": "artifacts/coverage-projection-review-r21-20261016/review.json"})
rows = {r["id"]: r for r in ledger["tasks"]}
pending, done, layers = set(rows), set(), []
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
ledger.update(updated_at=at, topological_layers=layers)
write(HERE / "tasks.json", ledger)
print(json.dumps({"at": at, "dependency_files": len(files), "checked": 117, "independent_static_review": True, "root_product_changed": False, "ui_dispatched": False}), flush=True)
