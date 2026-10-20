"""Apply the narrowly validated fixture migration only after the joint exits."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
failed_out = ROOT / "artifacts/coordinator-r17-batch-intaken-20261015"
source = json.loads((failed_out / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and source["before"] == source["after"]
assert len(source["commands"]) == 1 and source["commands"][0]["returncode"] == 1
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in source["after"].items())
suites = ET.parse(failed_out / "results.xml").getroot().findall("testsuite")
assert suites and all(s.get("errors") == "0" and s.get("skipped") == "0" for s in suites)
failures = [(t.get("classname"), t.get("name")) for s in suites for t in s.findall("testcase") if t.find("failure") is not None]
expected = {("tests.test_scan_demand_equivalence", "test_same_current_input_plans_match_serialized_reference"), ("tests.test_scan_demand_equivalence", "test_stale_serialized_plan_cannot_replace_current_planning")}
assert len(failures) == 2 and set(failures) == expected, failures
proof = json.loads((ROOT / "artifacts/coordinator-demand-fixture-r19-migration-20261015/review.json").read_text(encoding="utf-8"))
assert proof["coordinator_validation_passed"] and proof["source_unchanged"]
assert proof["junit"]["tests"] == "94" and all(proof["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
assert len(proof["commands"]) == 3 and all(r["returncode"] == 0 for r in proof["commands"])
name = proof["owned_path"]
assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == proof["before_sha256"]
branch = ROOT / ".coordination/20261014/workspaces/coordinator-demand-r19"
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha for p, sha in proof["after_all_inputs"].items())
out = ROOT / "artifacts/intake-demand-fixture-r19-20261015"
out.mkdir(exist_ok=False)
(out / "original-fixture.json").write_bytes((ROOT / name).read_bytes())
(ROOT / name).write_bytes((branch / name).read_bytes())
assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == proof["after_sha256"]
at = dt.datetime.now(dt.timezone.utc).isoformat()
receipt = {"at": at, "path": name, "before_sha256": proof["before_sha256"], "after_sha256": proof["after_sha256"], "changes": "24 existing SymbolIdentity strings gain usr empty string; no assertion/product/obligation change", "validation": "artifacts/coordinator-demand-fixture-r19-migration-20261015/review.json", "failed_joint": "artifacts/coordinator-r17-batch-intaken-20261015/source-evidence.json", "failed_tests": failures, "current_joint_passed": False}
(out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "CURRENT-JOINT-R17")
row.update(status="fixture_migration_intaken_current_joint_retry_pending", failed_attempt="artifacts/coordinator-r17-batch-intaken-20261015/source-evidence.json", fixture_migration="artifacts/intake-demand-fixture-r19-20261015/receipt.json", whole_package_complete=False)
ledger["current_accepted_stage"].update(is_current_root=False, current_root_status="R17 joint failed two stale synthetic fixture identities; validated explicit unknown-USR migration applied, full current-root retry pending")
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
