"""Create stronger green admission without mutating the queued V1 red launcher."""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OLD = HERE / "verify_session_cost_r33.py"
NEW = HERE / "verify_session_cost_r33_v2.py"
OUT = ROOT / "artifacts/coordinator-session-cost-r33-20261017"
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert not NEW.exists()
source = OLD.read_text(encoding="utf-8")
old = 'prep,frozen=read(BASE/"preparation.json"),read(BASE/"test-freeze.json")'
new = old + '\nassert sha(ROOT/prep["readonly_source_review"])==prep["readonly_source_review_sha256"]'
assert source.count(old)==1
source=source.replace(old,new)
old = '    change=read(BASE/"candidate.json")\n    expected=expected|change["candidate_sha256"]'
new = '''    change=read(BASE/"candidate.json")
    only_path="zscope/orchestration/scan_session.py"
    assert set(change["candidate_sha256"])=={only_path}
    assert change["before_sha256"]=={only_path:frozen["complete_inputs"][only_path]}
    assert sha(BASE/"candidate"/only_path)==change["candidate_sha256"][only_path]
    causal=read(BASE/"red-causal-audit.json")
    assert causal["strict_current_preentry_red_confirmed"]
    assert causal["red_receipt_sha256"]==sha(BASE/"red/review.json")
    assert causal["red_xml_sha256"]==sha(BASE/"red/results.xml")
    expected=expected|change["candidate_sha256"]'''
assert source.count(old)==1
source=source.replace(old,new)
old = '    references += [BASE/"candidate.json",BASE/"red/review.json",BASE/"red/results.xml"]'
new = '    references += [BASE/"candidate.json",BASE/"red/review.json",BASE/"red/results.xml",BASE/"red-causal-audit.json"]'
assert source.count(old)==1
source=source.replace(old,new)
old = 'red_ok=phase=="red" and valid and result.returncode==1 and counts["failures"]==1'
new = '''failed=[node for node in tree.iter("testcase") if node.find("failure") is not None]
strict_red_cause=bool(len(failed)==1 and failed[0].get("name")=="test_real_instance_builder_retains_current_preentry_cost_and_service[True]" and "total_tokens" in "".join(failed[0].find("failure").itertext()) and "assert 0 == 24" in "".join(failed[0].find("failure").itertext()))
red_ok=phase=="red" and valid and result.returncode==1 and counts["failures"]==1 and strict_red_cause'''
assert source.count(old)==1
source=source.replace(old,new)
NEW.write_text(source, encoding="utf-8", newline="\n")
receipt=dict(actual_task="/root", original_v1_sha256=sha(OLD), candidate_v2_sha256=sha(NEW), original_v1_unchanged=True, exact_single_product_path_required=True, readonly_review_original_sha_required=True, red_true_cost_assertion_false_control_required=True, original_red_receipt_preserved=True, product_written=False, stage_intake=False, root_intake=False)
(OUT/"launcher-v2-preparation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2)+"\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
