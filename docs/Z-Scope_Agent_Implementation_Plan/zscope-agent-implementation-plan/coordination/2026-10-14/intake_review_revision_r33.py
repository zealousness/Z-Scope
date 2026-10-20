"""Integrate independently checked Review compatibility without claiming full Stage quality."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
STAGE=ROOT/".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORK=ROOT/".coordination/20261014/workspaces/coordinator-contract-tests-r33"
OUT=ROOT/"artifacts/review-revision-stage-intake-r33-20261017"
BASE=ROOT/"artifacts/coordinator-review-revision-repair-r33-20261017"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot():
    return {p.relative_to(STAGE).as_posix():sha(p) for p in STAGE.rglob("*") if p.is_file() and p.relative_to(STAGE).parts[0]!="artifacts" and not any(v in {"__pycache__",".pytest_cache",".mypy_cache"} for v in p.parts) and p.suffix!=".pyc" and p.name!="DELIVERY.md"}


regression=read(BASE/"regression/review.json")
assert regression["bounded_revision_regression_and_target_quality_passed"]
assert regression["junit"]==dict(tests=271,failures=0,errors=0,skipped=0)
assert not regression["full_isolated_zscope_quality_passed"]
source=ROOT/"artifacts/coordinator-review-revision-audit-r33-20261017/review.json"
assert read(source)["bounded_revision_compatibility_source_review_passed"]
legacy_source=ROOT/"artifacts/coordinator-contract-tests-source-review-r33-20261017/review.json"
assert read(legacy_source)["source_review_passed"]
legacy=read(ROOT/"artifacts/coordinator-contract-tests-r33-20261017/preparation.json")
base=read(ROOT/"artifacts/coordinator-stage-repairs-r33-20261017/supplemental-inputs.json")["candidates"]["stage-currentness-repair-r33"]["complete_candidate_baseline"]
before=snapshot()
assert len(before)==1077 and before==base
root=read(ROOT/"artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root)==1065 and all(sha(ROOT/p)==digest for p,digest in root.items())
product="zscope/core/validation/review_checks.py"
test="tests/test_review_current_revisions_r33.py"
candidate=read(BASE/"candidate.json")
frozen=read(BASE/"test-freeze.json")
paths=legacy["candidate_sha256"]|{product:candidate["candidate_sha256"],test:frozen["fixed_test_sha256"]}
assert len(paths)==6 and all(sha(WORK/p)==digest for p,digest in paths.items())
assert all(before[p]==legacy["before_sha256"][p] for p in legacy["owned_paths"])
assert before[product]=="01c5eaa7bdcb0f2d3072155f98d3a5eb4dcff467e46ad6a9e49814e24c6bb8fe" and test not in before
OUT.mkdir(exist_ok=False)
for p in paths:
    target=STAGE/p
    if target.exists():
        backup=OUT/"before"/p
        backup.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(target,backup)
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(WORK/p,target)
after=snapshot()
assert after==before|paths and len(after)==1078
assert all(sha(ROOT/p)==digest for p,digest in root.items())
refs=[Path(__file__),BASE/"regression/review.json",BASE/"regression/results.xml",BASE/"green/review.json",BASE/"green/results.xml",BASE/"candidate.json",BASE/"test-freeze.json",source,legacy_source,ROOT/"artifacts/coordinator-contract-tests-r33-20261017/preparation.json",HERE/"followups-r12/coordinator-instance-integration-r24-ownership-extension-08.json",HERE/"followups-r12/coordinator-instance-integration-r24-ownership-extension-09.json"]
receipt=dict(actual_task="/root",integrated_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),stage_intake=True,paths=paths,complete_inputs_before=before,complete_inputs_after=after,root_inputs=root,root1065_unchanged=True,reference_sha256={str(p):sha(p) for p in refs},bounded_independent_review_and_legacy_regression_passed=True,selected_271_all_passed=True,target_compileall_review_mypy_and_new_test_black_passed=True,full_stage_quality_passed=False,selected_stage_joint_checks_passed=False,root_intake=False,whole_package_complete=False,known_remaining_full_quality_blocker="old Parallel:492; frozen cost repair not yet accepted/integrated")
(OUT/"receipt.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(integrated_at=receipt["integrated_at"],paths=len(paths),complete_stage_inputs=len(after),root_intake=False)))
