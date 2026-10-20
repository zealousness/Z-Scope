"""Freeze the current shared candidates for original-job diagnostic probes only."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
SOURCE=ROOT/".coordination/20261014/workspaces/coordinator-final-composite-r33"
WORK=ROOT/".coordination/20261014/workspaces/shared-job-probes-r34"
OUT=ROOT/"artifacts/shared-job-probes-r34-20261017"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=read(ROOT/"artifacts/coordinator-final-composite-r33-20261017/input-freeze-v2.json")["complete_inputs"]
assert len(base)==1081 and all(sha(SOURCE/p)==digest for p,digest in base.items())
assert not WORK.exists()
WORK.mkdir()
for p in base:
    target=WORK/p
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(SOURCE/p,target)
contract=ROOT/".coordination/20261014/workspaces/coordinator-contract-tests-r33"
legacy=read(ROOT/"artifacts/coordinator-contract-tests-r33-20261017/preparation.json")["candidate_sha256"]
session=ROOT/"artifacts/coordinator-session-cost-r33-20261017"
session_candidate=read(session/"candidate.json")["candidate_sha256"]
session_test=read(session/"test-freeze-v2.json")
docs=ROOT/"artifacts/coordinator-shared-docs-v2-r33-20261017"
doc_candidate=read(docs/"candidate.json")["candidate_sha256"]
overrides={p:(contract/p,digest) for p,digest in legacy.items()}
overrides|={p:(session/"candidate"/p,digest) for p,digest in session_candidate.items()}
overrides[session_test["fixed_test_path"]]=(session/"fixed-test-v2.py",session_test["fixed_test_sha256"])
overrides|={p:(docs/"candidate"/p,digest) for p,digest in doc_candidate.items()}
for p,(source,digest) in overrides.items():
    assert sha(source)==digest
    target=WORK/p
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(source,target)
expected=base|{p:digest for p,(_source,digest) in overrides.items()}
assert len(expected)==1082 and all(sha(WORK/p)==digest for p,digest in expected.items())
root=read(ROOT/"artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root)==1065 and all(sha(ROOT/p)==digest for p,digest in root.items())
refs=[Path(__file__),ROOT/"artifacts/coordinator-final-composite-r33-20261017/input-freeze-v2.json",ROOT/"artifacts/coordinator-stage-repairs-r33-20261017/phase2-checkpoint.json",ROOT/"artifacts/stage-final-repair-source-review-r33-20261017/shared-five-module-boundary-review.json",ROOT/"artifacts/stage-final-repair-source-review-r33-20261017/docs-v2-source-review.json",session/"green2/review.json",session/"candidate.json",session/"test-freeze-v2.json"]
OUT.mkdir(exist_ok=False)
receipt=dict(actual_coordinator_task="/root",prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),probe_owner_task="/root/stage_cost_repair_r33",workspace=str(WORK.relative_to(ROOT)),complete_inputs=expected,root_inputs=root,reference_sha256={str(p):sha(p) for p in refs},product_and_original_tests_readonly=True,allowed_writes=["own diagnostic artifact directory only"],required_original_test_ids=["tests/test_scan_session_jobs.py::test_job_scan_runs_exact_instances_on_the_queue","tests/test_scan_checkpoint_resume.py::test_tampered_checkpoint_bytes_are_not_reused"],diagnostic_original_guard_results_must_be_preserved=True,first_cause_not_yet_confirmed=True,stage_intake=False,root_intake=False)
(OUT/"preparation.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
(HERE/"followups-r12/coordinator-instance-integration-r24-ownership-extension-12.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(workspace=receipt["workspace"],inputs=len(expected))))
