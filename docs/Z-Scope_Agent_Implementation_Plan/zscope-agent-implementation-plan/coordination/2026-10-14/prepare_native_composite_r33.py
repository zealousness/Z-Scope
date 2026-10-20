"""Freeze complete isolated inputs for independent currentness/consumer checks."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-native-composite-r33"
CONTEXT = ROOT / ".coordination/20261014/workspaces/stage-currentness-repair-r33"
BRIDGE = ROOT / ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33/bridge-v3-source"
OUT = ROOT / "artifacts/coordinator-native-composite-r33-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


override = ROOT / "artifacts/coordinator-entry-workflow-repair-r33-20261017/stage-currentness-repair-r33-override.json"
review = ROOT / "artifacts/stage-repair-product-source-review-r33-20261017/bridge-v3-source-review.json"
assert read(review)["bounded_dependency_source_review_passed"]
assert not read(review)["blocking_findings"]
base = read(override)["complete_candidate_baseline"]
assert len(base) == 1077
inputs = base | {
    "zscope/orchestration/instance_semantics_context.py": "d78ed827bf8ecea033df961260e0ec481adea722fad244d9e69e1c48ca438798",
    "tests/test_instance_currentness_revocation_r33.py": "91d5b133e9c41b5fe9f296d060da80463f4612af967621489d6b6eeff7cfeca0",
}
assert all(sha(CONTEXT / path) == digest for path, digest in inputs.items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert not WORK.exists() and not OUT.exists()
WORK.mkdir()
OUT.mkdir()
for path in inputs:
    target = WORK / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CONTEXT / path, target)
bridge_inputs = {
    "zscope/orchestration/parallel_analyzer.py": ("parallel_analyzer.py", "64c3b98718b88f131443ada77a1b0266bc06f4d3862e9fe381459646ce1e927b"),
    "tests/test_instance_recovery_cost_r33.py": ("test_instance_recovery_cost_r33.py", "fc0afbcd25bf86248c8763444851dfa2f73e75a4ecca47b2c43451ec51847aa8"),
}
for path, (source, digest) in bridge_inputs.items():
    assert sha(BRIDGE / source) == digest
    shutil.copyfile(BRIDGE / source, WORK / path)
    inputs[path] = digest
assert len(inputs) == 1079
assert all(sha(WORK / path) == digest for path, digest in inputs.items())
assert all(sha(CONTEXT / path) == digest for path, digest in (base | {
    "zscope/orchestration/instance_semantics_context.py": inputs["zscope/orchestration/instance_semantics_context.py"],
    "tests/test_instance_currentness_revocation_r33.py": inputs["tests/test_instance_currentness_revocation_r33.py"],
}).items())
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
write(OUT / "preparation.json", dict(actual_task="/root", prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), workspace=WORK.relative_to(ROOT).as_posix(), complete_inputs=inputs, reference_sha256={str(path): sha(path) for path in (Path(__file__), override, review, BRIDGE / "receipt.json")}, root_inputs=root_inputs, source_from_frozen_and_idle_producers=True, source_review_passed=True, independent_behavior_acceptance=False, stage_intake=False, root_intake=False))
print(json.dumps(dict(prepared=str(WORK), inputs=len(inputs))))
