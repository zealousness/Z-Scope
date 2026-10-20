"""Intake the independently validated test-path migration without weakening its obligations."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
failed = ROOT / "artifacts/coordinator-r18-ui-doc-intaken-20261015"
source = json.loads((failed / "source-evidence.json").read_text(encoding="utf-8"))
assert source["direct_source_unchanged"] and len(source["commands"]) == 1 and source["commands"][0]["returncode"] == 1
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source["after"].items())
suites = ET.parse(failed / "results.xml").getroot().findall("testsuite")
assert suites and all(s.get("errors") == "0" and s.get("skipped") == "0" for s in suites)
failures = [(t.get("classname"), t.get("name")) for s in suites for t in s.findall("testcase") if t.find("failure") is not None]
assert failures == [("tests.test_instance_coverage_ui", "test_instance_coverage_native_owner_http")], failures
proof = json.loads((ROOT / "artifacts/coordinator-ui-queue-receipt-r19-migration-20261015/review.json").read_text(encoding="utf-8"))
assert proof["coordinator_validation_passed"] and proof["source_unchanged"]
assert len(proof["commands"]) == 4 and all(r["returncode"] == 0 for r in proof["commands"])
assert proof["junit"]["tests"] == "107" and all(proof["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
branch = ROOT / ".coordination/20261014/workspaces/coordinator-ui-queue-r19"
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in proof["after_all_inputs"].items())
name = proof["path"]
assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == proof["before_sha256"]
out = ROOT / "artifacts/intake-ui-queue-receipt-r19-20261015"
out.mkdir(exist_ok=False)
(out / "original-test.py").write_bytes((ROOT / name).read_bytes())
(ROOT / name).write_bytes((branch / name).read_bytes())
assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == proof["after_sha256"]
receipt = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "path": name, "before_sha256": proof["before_sha256"], "after_sha256": proof["after_sha256"], "validation": "artifacts/coordinator-ui-queue-receipt-r19-migration-20261015/review.json", "failed_joint": "artifacts/coordinator-r18-ui-doc-intaken-20261015/source-evidence.json", "scope": "Only the native UI test queue locator now reads the actual scoped scheduler SQL event and verifies job/run/input/path plus the original two completed instances; no product or assertion removal.", "current_joint_passed": False}
(out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "CURRENT-JOINT-R18")
row.update(status="queue_receipt_test_migration_intaken_full_retry_pending", failed_attempt=receipt["failed_joint"], last_attempt_result={"passed": 2078, "failed": 1, "errors": 0, "skipped": 0}, test_migration="artifacts/intake-ui-queue-receipt-r19-20261015/receipt.json", whole_package_complete=False)
ledger["updated_at"] = receipt["at"]
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
