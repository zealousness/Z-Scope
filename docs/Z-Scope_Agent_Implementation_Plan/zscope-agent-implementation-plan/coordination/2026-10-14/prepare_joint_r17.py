"""Prepare the complete next collection; no intake or acceptance state change."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import re
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
target = HERE / "verify_current_root_r17.py"
assert not target.exists()
old = HERE / "verify_current_root_r16.py"
assert old.read_bytes() == (ROOT / "artifacts/coordinator-r16-astra-projection-intaken-20261015/launcher.py").read_bytes()
tree = ast.parse((HERE / "verify_delivery_r12.py").read_text(encoding="utf-8"))
contract_tests = set()
for node in ast.walk(tree):
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        continue
    test = node.test
    if not (isinstance(test.left, ast.Name) and test.left.id == "kind" and len(test.comparators) == 1 and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value == "contract"):
        continue
    for statement in node.body:
        for item in ast.walk(statement):
            if isinstance(item, ast.List):
                contract_tests.update(value.value for value in item.elts if isinstance(value, ast.Constant) and isinstance(value.value, str) and re.fullmatch(r"test_[a-z0-9_]+", value.value))
producer = ROOT / ".coordination/20261014/workspaces/contract-validation-r12"
xml = ET.parse(producer / "artifacts/contract-validation-r12/results-contract-validation-r12-final4.xml")
original = {part for case in xml.iter("testcase") for part in str(case.get("classname") or "").split(".") if part.startswith("test_") and (producer / "tests" / (part + ".py")).is_file()}
assert len(original) == 39 and original <= contract_tests
assert {"test_single_slot_pool", "test_retention_protocols"} <= contract_tests
source = old.read_text(encoding="utf-8")
anchor = 'TESTS = list(dict.fromkeys(TESTS))\nassert all((ROOT/name).is_file() for name in TESTS), "accepted current-root test missing"'
assert source.count(anchor) == 1
added = '''# Preserve the original39 producer regressions and all independent neighbors.
if "CONTRACT-VALIDATION-R12" in integrated:
    TESTS += ["tests/" + name + ".py" for name in CONTRACT_R17_TESTS]
    TESTS += [str((HERE / "followups-r12" / name).relative_to(ROOT)) for name in ("test_contract_omitted_usr_boundary.py", "test_contract_context_receipt_boundary.py")]
if "COORD-BOUND-EVENTS-R17" in integrated:
    TESTS += ["tests/test_job_bound_completion.py"]
if "SCAN-CHECKPOINT-R17" in integrated:
    assert {"SCAN-SESSION-R12", "CONTRACT-VALIDATION-R12", "COORD-BOUND-EVENTS-R17"} <= integrated
    TESTS += ["tests/test_scan_checkpoint_resume.py", str((HERE / "followups-r12/test_scan_checkpoint_authority_boundary.py").relative_to(ROOT)), str((HERE / "followups-r12/test_scan_checkpoint_dependency_boundary.py").relative_to(ROOT))]
'''
source = source.replace(anchor, "CONTRACT_R17_TESTS = " + repr(sorted(contract_tests)) + "\n" + added + anchor)
source = source.replace('BACKEND_ONLY = "--backend-only" in sys.argv[2:]', 'BACKEND_ONLY = "--backend-only" in sys.argv[2:]\nassert not BACKEND_ONLY, "R17 requires the entire collection including Astra browser tests"')
black_anchor = '    if "black" in command:\n'
assert source.count(black_anchor) == 1
source = source.replace(black_anchor, black_anchor + '''        for row in ledger["tasks"]:
            if row["id"] in {"CONTRACT-VALIDATION-R12", "SCAN-SESSION-R12", "SCAN-CHECKPOINT-R17"} and row["id"] in integrated:
                command += [name for name in row.get("write_paths", []) if name.endswith(".py") and "*" not in name]
        if "CONTRACT-VALIDATION-R12" in integrated:
            command += ["tests/test_contract_build_scope.py", "tests/test_native_wrapper_inference.py", "tests/test_single_slot_pool.py", "tests/test_retention_protocols.py"]
        if "SCAN-SESSION-R12" in integrated:
            command += ["tests/test_scan_session_resume_svf.py"]
        if "COORD-BOUND-EVENTS-R17" in integrated:
            command += ["zscope/orchestration/jobs/store.py", "tests/test_job_bound_completion.py"]
''')
source = source.replace('"environment_evidence": "artifacts/coordinator-runtime-r14-20261015.json"', '"environment_evidence": "artifacts/coordinator-runtime-r17-20261015.json"')
target.write_text(source, encoding="utf-8", newline="\n")
proof = {"prepared_at": dt.datetime.now(dt.timezone.utc).isoformat(), "prior_launcher_sha256": hashlib.sha256(old.read_bytes()).hexdigest(), "new_launcher_sha256": hashlib.sha256(target.read_bytes()).hexdigest(), "original_producer_test_files": sorted(original), "required_contract_test_files": sorted(contract_tests), "retains_prior_root_collection": True, "commands": 6, "default_pytest_fd": True, "full_astra_browser_required": True, "execution_pending_intake": True, "root_changed": False, "acceptance": False}
(HERE / "joint-r17-plan.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"launcher": str(target), "original_contract_files": len(original), "required_contract_files": len(contract_tests), "root_changed": False}))
