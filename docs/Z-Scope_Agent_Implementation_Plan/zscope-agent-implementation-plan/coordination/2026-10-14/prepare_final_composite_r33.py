"""Freeze latest independently source-reviewed modules in one complete candidate."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
STAGE=ROOT/".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORK=ROOT/".coordination/20261014/workspaces/coordinator-final-composite-r33"
OUT=ROOT/"artifacts/coordinator-final-composite-r33-20261017"
read=lambda path:json.loads(path.read_text(encoding="utf-8"))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
base=read(ROOT/"artifacts/coordinator-stage-repairs-r33-20261017/supplemental-inputs.json")["candidates"]["stage-currentness-repair-r33"]["complete_candidate_baseline"]
assert len(base)==1077 and all(sha(STAGE/path)==digest for path,digest in base.items())
reviews=[ROOT/"artifacts/stage-final-repair-source-review-r33-20261017/context-b5dd-source-review.json",ROOT/"artifacts/stage-final-repair-source-review-r33-20261017/cost-usage-f0f5-source-review.json",ROOT/"artifacts/coordinator-review-revision-audit-r33-20261017/review.json",ROOT/"artifacts/stage-repair-product-source-review-r33-20261017/entry-closure-source-review.json"]
assert all(path.is_file() for path in reviews)
assert all(not read(path).get("blocking_findings") for path in reviews)
assert read(reviews[1])["bounded_cost_module_source_review_passed"]
assert read(reviews[2])["bounded_revision_compatibility_source_review_passed"]
assert not WORK.exists() and not OUT.exists()
WORK.mkdir()
OUT.mkdir()
for path in base:
    target=WORK/path
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(STAGE/path,target)
context=ROOT/".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33/input-set-candidate-source"
cost=ROOT/".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/usage-green-source"
closure=ROOT/"artifacts/coordinator-entry-workflow-repair-r33-20261017/candidate"
revision=ROOT/"artifacts/coordinator-review-revision-repair-r33-20261017"
overrides={
    "zscope/orchestration/instance_semantics_context.py":(context/"instance_semantics_context.py","b5dd96fa64c07db65fbd46340b9137418a6a0a6f5be290d5e1e0f21fed93e17b"),
    "tests/test_instance_currentness_revocation_r33.py":(context/"test_instance_currentness_revocation_r33.py","a2e0ef2afaa32256410028ef14c4f257dad11d25d5b8324566e676ab737f11d1"),
    "zscope/orchestration/parallel_analyzer.py":(cost/"parallel_analyzer.py","f0f5edb9a858a8855401d9eb637306609626cc1aa8769f60927df1c07032d989"),
    "tests/test_instance_recovery_cost_r33.py":(cost/"test_instance_recovery_cost_r33.py","52ca4ea839ef8b8880615852f3b16888d7b4b51ed93e846e42a6d1da10fbdc44"),
    "zscope/core/analysis/analyzer.py":(closure/"zscope/core/analysis/analyzer.py","9e735f7bbf0e52832d9747873dafa4317e35ab88b2df4dc3c4b333873c531889"),
    "tests/test_instance_semantics_integration.py":(closure/"tests/test_instance_semantics_integration.py","2ca8e017e4a1120e2d5446160bffde248f56f04b4da3f92d45555c28876a8f6a"),
    "zscope/core/validation/review_checks.py":(revision/"candidate/zscope/core/validation/review_checks.py","daca98462b8b31457732ab96d9a4ba6a75ccba1544f81297a59785780502848f"),
    "tests/test_review_current_revisions_r33.py":(revision/"test_review_current_revisions_r33.py","f249b7e2c81075ebf48cfa692c51601fff1e03b84ce4336f5263fbca71c4a3ee"),
    "tests/test_native_classifier_currentness_r33.py":(ROOT/"artifacts/coordinator-native-classifier-probes-r33-20261017/test_native_classifier_currentness_r33.py","1b4f5f39f3508de6094cbc9838f9939c57e637ca51cf5909c91c5e3fa663a178"),
}
for path,(source,digest) in overrides.items():
    assert sha(source)==digest,(str(source),sha(source),digest)
    shutil.copyfile(source,WORK/path)
expected=base|{path:digest for path,(_source,digest) in overrides.items()}
assert len(expected)==1081 and all(sha(WORK/path)==digest for path,digest in expected.items())
root_inputs=read(ROOT/"artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs)==1065 and all(sha(ROOT/path)==digest for path,digest in root_inputs.items())
refs=[Path(__file__),*reviews,context/"receipt.json",cost/"receipt.json",revision/"test-freeze.json"]
receipt=dict(actual_task="/root",prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),complete_before_probe_style=expected,source_review_sha256={str(path):sha(path) for path in refs},root_inputs=root_inputs,workspace=WORK.relative_to(ROOT).as_posix(),coordinator_owned_probe_style_path="tests/test_native_classifier_currentness_r33.py",source_from_frozen_artifacts=True,shared_Session_Wiki_handoff_pending=True,stage_intake=False,root_intake=False)
(OUT/"preparation.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(inputs=len(expected),workspace=receipt["workspace"])))
