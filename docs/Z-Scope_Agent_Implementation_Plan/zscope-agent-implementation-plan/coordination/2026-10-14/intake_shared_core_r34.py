"""Intake only the independently green core slice; the job defect remains a separate gate."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import os
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("Stage intake requires Linux and unoptimized Python")
if Path.cwd().resolve() != ROOT:
    raise RuntimeError("Stage intake must be launched from the fixed repository root")
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-shared-style-r34"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
BASE = ROOT / "artifacts/coordinator-shared-style-r34-20261017"
OUT = ROOT / "artifacts/stage-core-intake-r34-20261017"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot(directory):
    return {p.relative_to(directory).as_posix(): sha(p) for p in directory.rglob("*") if p.is_file() and p.relative_to(directory).parts[0] != "artifacts" and not any(v in {"__pycache__", ".pytest_cache", ".mypy_cache"} for v in p.parts) and p.suffix != ".pyc" and p.name != "DELIVERY.md"}


old_intake = ROOT / "artifacts/review-revision-stage-intake-r33-20261017/receipt.json"
old = read(old_intake)
before = snapshot(STAGE)
assert len(before) == 1078 and before == old["complete_inputs_after"]
frozen = read(BASE / "input-freeze.json")
candidate = snapshot(WORK)
assert len(candidate) == 1082 and candidate == frozen["complete_inputs"]
independent = read(BASE / "independent/review.json")
assert independent["bounded_combined_repair_independent_and_full_quality_passed"]
assert independent["junit"] == dict(tests=150, failures=0, errors=0, skipped=0)
assert len(independent["commands"]) == 7 and all(v["returncode"] == 0 for v in independent["commands"])
assert all(independent["gates"].values())
source = ROOT / "artifacts/coordinator-shared-style-source-review-r34-20261017/review.json"
audit = read(source)
assert audit["source_review_passed"] and audit["style_only_source_review_passed"] and audit["launcher_static_review_passed"] and not audit["blocking_findings"]
reviews = {
    "artifacts/stage-final-repair-source-review-r33-20261017/context-b5dd-source-review.json": "bounded_module_source_review_passed",
    "artifacts/stage-final-repair-source-review-r33-20261017/cost-usage-f0f5-source-review.json": "bounded_cost_module_source_review_passed",
    "artifacts/stage-final-repair-source-review-r33-20261017/policy-candidate-e631-source-review.json": "source_review_passed",
    "artifacts/stage-final-repair-source-review-r33-20261017/docs-v2-source-review.json": "source_review_passed",
    "artifacts/stage-final-repair-source-review-r33-20261017/shared-five-module-boundary-review.json": "bounded_shared_boundary_source_review_passed",
    "artifacts/coordinator-session-cost-source-review-r33-20261017/launcher-v3-session-bc0c-source-review.json": "bounded_session_handoff_source_review_passed",
}
for path, key in reviews.items():
    value = read(ROOT / path)
    assert value[key] and not value["blocking_findings"]
root_inputs = old["root_inputs"]
assert len(root_inputs) == 1065 and all(sha(ROOT / p) == v for p, v in root_inputs.items())
paths = {p: v for p, v in candidate.items() if before.get(p) != v}
expected = {"docs/modules/configuration-state.md", "docs/modules/execution-orchestration.md", "docs/modules/retrieval-backends.md", "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12/test_scan_checkpoint_dependency_boundary.py", "tests/test_instance_analysis.py", "tests/test_instance_currentness_revocation_r33.py", "tests/test_instance_recovery_cost_r33.py", "tests/test_instance_semantics_integration.py", "tests/test_native_classifier_currentness_r33.py", "tests/test_session_preentry_cost_r33.py", "zscope/core/analysis/analyzer.py", "zscope/orchestration/instance_semantics_context.py", "zscope/orchestration/parallel_analyzer.py", "zscope/orchestration/scan_session.py"}
assert set(paths) == expected and before | paths == candidate
refs = dict(read(BASE / "independent/preflight.json")["references_sha256"])
for p in [Path(__file__), old_intake, BASE / "independent/review.json", BASE / "independent/results.xml", source, *(ROOT / v for v in reviews)]:
    key, digest = str(p), sha(p)
    assert key not in refs or refs[key] == digest
    refs[key] = digest
assert all(sha(Path(p)) == v for p, v in refs.items())
OUT.mkdir(exist_ok=False)
for p in paths:
    target = STAGE / p
    if target.exists():
        backup = OUT / "before" / p
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target, backup)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(WORK / p, target)
after = snapshot(STAGE)
assert after == candidate and len(after) == 1082
assert all(sha(ROOT / p) == v for p, v in root_inputs.items())
assert all(sha(Path(p)) == v for p, v in refs.items())
receipt = dict(actual_task="/root", integrated_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), stage_intake=True, paths=paths, complete_inputs_before=before, complete_inputs_after=after, root_inputs=root_inputs, root1065_unchanged=True, reference_sha256=refs, bounded_independent_acceptance_passed=True, bounded_shared_source_review_passed=True, selected150_and_seven_isolated_quality_commands_passed=True, stage_full_quality_passed=False, stage_joint_validation_passed=False, root_intake=False, whole_package_complete=False, known_separate_blockers=["job runtime output namespace self-invalidates strict include search", "legacy checkpoint contract test adaptation pending actual validation"], old_cost_failed_deliveries_preserved=1, old_s01_failed_deliveries_preserved=3)
(OUT / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(integrated_at=receipt["integrated_at"], paths=14, stage_inputs=1082, bounded=True, joint_passed=False, root_intake=False)))
