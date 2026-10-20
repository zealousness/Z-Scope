"""Copy one statically reviewed frozen dependency to an idle producer workspace."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/stage-currentness-repair-r33"
OUT = ROOT / "artifacts/coordinator-native-composite-r33-20261017"
BRIDGE = ROOT / ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33"
OLD = ROOT / "artifacts/coordinator-entry-workflow-repair-r33-20261017/stage-currentness-repair-r33-override.json"
REVIEW = ROOT / "artifacts/stage-repair-product-source-review-r33-20261017/bridge-v3-source-review.json"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
previous, review, check = read(OLD), read(REVIEW), read(BRIDGE / "bridge-v3-check/receipt.json")
assert review["bounded_dependency_source_review_passed"] and not review["blocking_findings"]
assert all(check[name] for name in ("source_unchanged", "readonly_matches", "configurations_unchanged", "extra_unchanged", "root_unchanged", "override_unchanged"))
assert check["commands"][0]["returncode"] == 0 and len(check["case_counter"]) == 4 and check["skipped"] == 0
path = "zscope/orchestration/parallel_analyzer.py"
expected = "64c3b98718b88f131443ada77a1b0266bc06f4d3862e9fe381459646ce1e927b"
assert sha(BRIDGE / "bridge-v3-source/parallel_analyzer.py") == expected == review["source_sha256"]
assert sha(WORK / path) == previous["complete_candidate_baseline"][path]
owned = {"zscope/orchestration/instance_semantics_context.py": "d78ed827bf8ecea033df961260e0ec481adea722fad244d9e69e1c48ca438798", "tests/test_instance_currentness_revocation_r33.py": "91d5b133e9c41b5fe9f296d060da80463f4612af967621489d6b6eeff7cfeca0"}
assert all(sha(WORK / name) == digest for name, digest in owned.items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / name) == digest for name, digest in root_inputs.items())
target = OUT / "context-v3-readonly-override.json"
assert not target.exists()
shutil.copyfile(BRIDGE / "bridge-v3-source/parallel_analyzer.py", WORK / path)
assert sha(WORK / path) == expected
assert all(sha(WORK / name) == digest for name, digest in owned.items())
assert all(sha(ROOT / name) == digest for name, digest in root_inputs.items())
receipt = dict(actual_task="/root", copied_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), workspace=WORK.relative_to(ROOT).as_posix(), previous_override=OLD.relative_to(ROOT).as_posix(), previous_override_sha256=sha(OLD), original_baseline_preserved=True, readonly_source_overrides=previous["readonly_source_overrides"] | {path: expected}, previous_readonly_sha256=previous["previous_readonly_sha256"] | {path: previous["complete_candidate_baseline"][path]}, complete_candidate_baseline=previous["complete_candidate_baseline"] | {path: expected}, producer_owned_paths_unchanged=True, producer_owned_sha256=owned, readonly_to_producer=True, producer_behavior_4_pass_receipt=(BRIDGE / "bridge-v3-check/receipt.json").relative_to(ROOT).as_posix(), producer_behavior_receipt_sha256=sha(BRIDGE / "bridge-v3-check/receipt.json"), source_review=REVIEW.relative_to(ROOT).as_posix(), source_review_sha256=sha(REVIEW), independent_behavior_acceptance_pending=True, only_while_producer_idle=True, stage_intake=False, root_intake=False, P2_cost_logic_changed=False)
target.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=target.relative_to(ROOT).as_posix(), copied_at=receipt["copied_at"])))
