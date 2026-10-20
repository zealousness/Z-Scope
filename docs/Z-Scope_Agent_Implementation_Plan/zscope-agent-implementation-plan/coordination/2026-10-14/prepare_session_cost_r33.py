"""Isolate a shared Session handoff probe on statically accepted dependencies."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-session-cost-r33"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-session-cost-r33-20261017"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
base = read(ROOT / "artifacts/coordinator-stage-repairs-r33-20261017/supplemental-inputs.json")["candidates"]["stage-currentness-repair-r33"]["complete_candidate_baseline"]
assert len(base) == 1077 and all(sha(STAGE / path) == digest for path,digest in base.items())
cost_review = ROOT / "artifacts/stage-final-repair-source-review-r33-20261017/cost-usage-f0f5-source-review.json"
assert read(cost_review)["bounded_cost_module_source_review_passed"]
assert not WORK.exists() and not (OUT / "preparation.json").exists()
WORK.mkdir()
for path in base:
    target = WORK / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGE / path, target)
overrides = {
    "zscope/orchestration/parallel_analyzer.py": (ROOT / ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/usage-candidate-source/parallel_analyzer.py", "f0f5edb9a858a8855401d9eb637306609626cc1aa8769f60927df1c07032d989"),
    "zscope/orchestration/instance_semantics_context.py": (ROOT / ".coordination/20261014/workspaces/coordinator-native-composite-r33/zscope/orchestration/instance_semantics_context.py", "d78ed827bf8ecea033df961260e0ec481adea722fad244d9e69e1c48ca438798"),
    "zscope/core/analysis/analyzer.py": (ROOT / "artifacts/coordinator-entry-workflow-repair-r33-20261017/candidate/zscope/core/analysis/analyzer.py", "9e735f7bbf0e52832d9747873dafa4317e35ab88b2df4dc3c4b333873c531889"),
}
for path,(source,digest) in overrides.items():
    assert sha(source) == digest
    shutil.copyfile(source, WORK / path)
test = "tests/test_session_preentry_cost_r33.py"
shutil.copyfile(OUT / "test_session_preentry_cost_r33.py", WORK / test)
expected = base | {path:digest for path,(_source,digest) in overrides.items()} | {test:sha(WORK / test)}
assert len(expected) == 1078 and all(sha(WORK / path)==digest for path,digest in expected.items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs)==1065 and all(sha(ROOT / path)==digest for path,digest in root_inputs.items())
ownership = dict(actual_task="/root", owner="coordinator", observed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), workspace=WORK.relative_to(ROOT).as_posix(), added_paths=["zscope/orchestration/scan_session.py",test], readonly_dependencies={path:digest for path,(_source,digest) in overrides.items()}, active_native_worker_files_disjoint=True, stage_write=False, root_write=False)
extension = HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-10.json"
assert not extension.exists()
extension.write_text(json.dumps(ownership, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
receipt = dict(actual_task="/root", prepared_at=ownership["observed_at"], complete_baseline=expected, root_inputs=root_inputs, readonly_source_review=str(cost_review.relative_to(ROOT)), readonly_source_review_sha256=sha(cost_review), controlled_wiki_callback=True, actual_session_handlers_and_native_factory=True, real_client_response_record_API=True, provider_requests=False, real_Wiki_or_project_effect_acceptance=False, stage_intake=False, root_intake=False)
(OUT / "preparation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(inputs=len(expected), workspace=WORK.relative_to(ROOT).as_posix())))
