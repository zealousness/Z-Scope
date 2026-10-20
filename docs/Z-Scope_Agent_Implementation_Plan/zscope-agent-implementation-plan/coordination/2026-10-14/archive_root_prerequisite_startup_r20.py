"""Retain the non-test prerequisite failure before an actual Root run."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = ROOT / "artifacts/coordinator-r20-job-cli-intaken-20261015"
target = ROOT / "artifacts/coordinator-r20-job-cli-prerequisite-startup-20261015"
assert source.resolve().parent == target.resolve().parent == (ROOT / "artifacts").resolve()
assert source.is_dir() and not target.exists()
assert not (source / "results.xml").exists() and not (source / "source-evidence.json").exists()
source.rename(target)
receipt = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "classification": "coordinator dependency-startup assertion, no test conclusion", "intake_happened": False, "tests_executed": 0, "reason": "Intake correctly rejected a separately modified protected test_slot.py; coordinator mistakenly attempted dependent Root launcher after intake command exit1, which refused integrated prerequisite", "root_product_written_by_failed_intake": False, "product_delivery_failure": False, "correction": "Review and bind exact test_slot before/after plus guard probe/full646 acceptance; keep all other1040 old inputs exact; only launch after confirmed successful intake"}
(target / "startup-receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"archived": str(target), "tests_executed": 0}), flush=True)
