"""Preserve the invalid fixture red, then freeze an explicit real-client fixture."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/coordinator-session-cost-r33-20261017"
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-session-cost-r33"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def write(p, value):
    assert not p.exists()
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


old = read(BASE / "test-freeze.json")
assert all(sha(WORK / p) == digest for p, digest in old["complete_inputs"].items())
tree = ET.parse(BASE / "red/results.xml").getroot()
failed = [n for n in tree.iter("testcase") if n.find("failure") is not None]
assert len(failed) == 1 and "StopIteration" in "".join(failed[0].find("failure").itertext())
write(BASE / "red-invalid-causal-audit.json", dict(actual_task="/root", audited_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), red_receipt_sha256=sha(BASE / "red/review.json"), red_xml_sha256=sha(BASE / "red/results.xml"), original_receipt_valid_red_claim_rejected=True, valid_product_red=False, cause="Fixture llms={} caused StopIteration before cost assertion", old_receipt_preserved=True, product_failed_deliveries_increment=0))
test = old["fixed_test_path"]
text = (WORK / test).read_text(encoding="utf-8")
needle = '    config.llm.models = ["offline-session-accounting-fixture"]\n'
assert text.count(needle) == 1
fixed = text.replace(needle, needle + '    config.llms = {"default": config.llm}\n')
def assertions(source):
    return [ast.dump(n) for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Assert)]
assert assertions(text) == assertions(fixed)
(WORK / test).write_text(fixed, encoding="utf-8", newline="\n")
(BASE / "fixed-test-v2.py").write_text(fixed, encoding="utf-8", newline="\n")
write(BASE / "test-freeze-v2.json", dict(actual_task="/root", frozen_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), fixed_test_path=test, fixed_test_sha256=sha(WORK / test), complete_inputs=old["complete_inputs"] | {test:sha(WORK / test)}, original_preparation_sha256=sha(BASE / "preparation.json"), previous_freeze_sha256=sha(BASE / "test-freeze.json"), invalid_red_audit_sha256=sha(BASE / "red-invalid-causal-audit.json"), original_assertions_exact=True, explicit_real_client_config=True, provider_requests=False))
source = (HERE / "verify_session_cost_r33_v2.py").read_text(encoding="utf-8")
source = source.replace('"test-freeze.json"', '"test-freeze-v2.json"').replace('"fixed-test.py"', '"fixed-test-v2.py"')
source = source.replace('phase=sys.argv[1]', 'phase=sys.argv[1]\nphase_folder={"red":"red2","green":"green2"}[phase]')
source = source.replace('BASE/phase', 'BASE/phase_folder').replace('BASE/"red/', 'BASE/"red2/').replace('BASE/"red-causal-audit.json"', 'BASE/"red2-causal-audit.json"')
source = source.replace('references += [BASE/"candidate.json",', 'references += [BASE/"candidate"/only_path,BASE/"candidate.json",')
source = source.replace('refs={str(path):sha(path) for path in references}', 'references += [BASE/"red-invalid-causal-audit.json",BASE/"test-freeze.json",BASE/"red/review.json",BASE/"red/results.xml"]\nrefs={str(path):sha(path) for path in references}')
target = HERE / "verify_session_cost_r33_v3.py"
assert not target.exists()
target.write_text(source, encoding="utf-8", newline="\n")
write(BASE / "launcher-v3-preparation.json", dict(actual_task="/root", launcher_sha256=sha(target), previous_launcher_sha256=sha(HERE / "verify_session_cost_r33_v2.py"), original_launcher_sha256=sha(HERE / "verify_session_cost_r33.py"), fixed_test_sha256=sha(WORK / test), strict_red_cause_required=True, physical_green_candidate_in_before_after_refs=True, no_old_evidence_overwritten=True))
print(json.dumps(dict(fixed_test_sha256=sha(WORK / test), launcher_sha256=sha(target))))
