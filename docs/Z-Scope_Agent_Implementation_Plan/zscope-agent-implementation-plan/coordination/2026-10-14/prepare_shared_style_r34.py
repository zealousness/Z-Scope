"""Prepare a fresh combined candidate; preserve the failed Black run unchanged."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
SOURCE=ROOT/".coordination/20261014/workspaces/shared-job-probes-r34"
WORK=ROOT/".coordination/20261014/workspaces/coordinator-shared-style-r34"
OUT=ROOT/"artifacts/coordinator-shared-style-r34-20261017"
read=lambda p:json.loads(p.read_text(encoding="utf-8"))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
probe=read(ROOT/"artifacts/shared-job-probes-r34-20261017/preparation.json")
base=probe["complete_inputs"]
assert len(base)==1082 and all(sha(SOURCE/p)==digest for p,digest in base.items())
old=read(ROOT/"artifacts/coordinator-final-composite-r33-20261017/independent/review.json")
assert old["junit"]==dict(tests=148,failures=0,errors=0,skipped=0) and not old["bounded_combined_repair_independent_and_full_quality_passed"]
assert [r["returncode"] for r in old["commands"]]==[0,0,0,0,0,1,0]
assert all(old["gates"].values())
WORK.mkdir(exist_ok=False)
OUT.mkdir(exist_ok=False)
for p in base:
    target=WORK/p
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(SOURCE/p,target)
assert all(sha(WORK/p)==digest for p,digest in base.items())
owned=["zscope/core/analysis/analyzer.py","docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12/test_scan_checkpoint_dependency_boundary.py"]
for p in owned:
    backup=OUT/"before"/p
    backup.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(WORK/p,backup)
refs=read(ROOT/"artifacts/coordinator-final-composite-r33-20261017/preparation.json")["source_review_sha256"]
for p,digest in probe["reference_sha256"].items():
    assert p not in refs or refs[p]==digest
    refs[p]=digest
for p in (Path(__file__),ROOT/"artifacts/shared-job-probes-r34-20261017/preparation.json",ROOT/"artifacts/coordinator-final-composite-r33-20261017/independent/review.json",ROOT/"artifacts/coordinator-final-composite-r33-20261017/independent/results.xml",ROOT/"artifacts/coordinator-session-cost-r33-20261017/green2/results.xml",ROOT/"artifacts/coordinator-session-cost-r33-20261017/green2/review.json",ROOT/"artifacts/coordinator-session-cost-r33-20261017/regression/review.json"):
    refs[str(p)]=sha(p)
assert all(sha(Path(p))==digest for p,digest in refs.items())
receipt=dict(actual_task="/root",prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),workspace=str(WORK.relative_to(ROOT)),complete_before_style=base,root_inputs=probe["root_inputs"],source_review_sha256=refs,style_only_paths=owned,original_148_black_failed_receipt_preserved=True,stage_intake=False,root_intake=False)
(OUT/"preparation.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps(dict(inputs=1082,style_paths=owned)))
