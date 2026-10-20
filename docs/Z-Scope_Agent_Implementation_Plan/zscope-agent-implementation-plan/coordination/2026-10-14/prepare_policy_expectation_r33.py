"""Correct one superseded metadata expectation with all other assertions retained."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
WORK = ROOT / ".coordination/20261014/workspaces/stage-currentness-repair-r33"
COMPOSITE = ROOT / ".coordination/20261014/workspaces/coordinator-final-composite-r33"
OUT = ROOT / "artifacts/coordinator-policy-expectation-r33-20261017"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def write(p, value):
    assert not p.exists()
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


contract = ROOT / "artifacts/design-contract-r23-20261016/contracts.json"
policy = "builtin_current_manual_advisory_no_inferred.v1"
assert read(contract)["versions"]["s01_authority_policy"] == policy
path = "tests/test_instance_analysis.py"
before = (STAGE / path).read_text(encoding="utf-8")
needle = 'assert outcome.semantics == "defaults_only"'
assert before.count(needle) == 1
after = before.replace(needle, f'assert outcome.semantics == "{policy}"')
# Normalizing only the policy literal proves every other AST node is retained.
assert ast.dump(ast.parse(before)) == ast.dump(ast.parse(after.replace(f'assert outcome.semantics == "{policy}"', needle)))
OUT.mkdir(exist_ok=False)
candidate = OUT / "candidate" / path
candidate.parent.mkdir(parents=True)
candidate.write_text(after, encoding="utf-8", newline="\n")
previous = ROOT / "artifacts/coordinator-native-composite-r33-20261017/context-v3-readonly-override.json"
baseline = read(previous)["complete_candidate_baseline"]
owned = {"zscope/orchestration/instance_semantics_context.py", "tests/test_instance_currentness_revocation_r33.py"}
assert len(baseline) == 1077
assert all(sha(WORK / p) == digest for p,digest in baseline.items() if p not in owned)
assert sha(WORK / path) == sha(STAGE / path)
frozen = ROOT / "artifacts/coordinator-final-composite-r33-20261017/input-freeze.json"
fdata = read(frozen)
assert all(sha(COMPOSITE / p) == digest for p,digest in fdata["complete_inputs"].items())
assert sha(COMPOSITE / path) == sha(STAGE / path)
for destination in (WORK / path, COMPOSITE / path):
    shutil.copyfile(candidate, destination)
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
receipt = dict(actual_task="/root", copied_at=when, candidate_path=str(candidate.relative_to(ROOT)), path=path, before_sha256=sha(STAGE / path), candidate_sha256=sha(candidate), contract_path=str(contract.relative_to(ROOT)), contract_sha256=sha(contract), only_policy_literal_changed=True, all_other_AST_nodes_exact=True, original_failed_755_run_preserved=True, previous_override=str(previous.relative_to(ROOT)), previous_override_sha256=sha(previous), complete_candidate_baseline=baseline | {path:sha(candidate)}, producer_owned_sha256={p:sha(WORK / p) for p in owned}, readonly_to_producer=True, producer_workspace=str(WORK.relative_to(ROOT)), stage_intake=False, root_intake=False)
write(OUT / "context-readonly-override.json", receipt)
write(OUT / "candidate.json", receipt)
write(ROOT / "artifacts/coordinator-final-composite-r33-20261017/input-freeze-v2.json", fdata | dict(frozen_at=when, complete_inputs=fdata["complete_inputs"] | {path:sha(candidate)}, previous_freeze_sha256=sha(frozen), policy_expectation_receipt_sha256=sha(OUT / "candidate.json")))
write(HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-11.json", dict(actual_task="/root", owner="coordinator", added_paths=[path, "tests/test_native_classifier_currentness_r33.py"], copies_only_in_idle_isolated_workspaces=True, stage_write=False, root_write=False))
print(json.dumps(dict(test_sha256=sha(candidate), override=str((OUT/"context-readonly-override.json").relative_to(ROOT)))))
