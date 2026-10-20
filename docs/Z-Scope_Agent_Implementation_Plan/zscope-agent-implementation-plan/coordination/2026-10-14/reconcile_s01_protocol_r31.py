"""Reconcile an ambiguous prompt failure before any retry; no product execution."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

assert sys.platform == "linux" and len(sys.argv) == 2 and sys.argv[1] in {"first", "second"}
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-s01-replacement-r31-20261017"
prep = json.loads((OUT / "preparation.json").read_text(encoding="utf-8"))
work = ROOT / prep["new_workspace"]
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
old = ROOT / prep["old_workspace"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


checks = {}
for label, base, inputs in (("new", work, prep["new_source_inputs"]), ("old", old, prep["old_workspace_inputs"]), ("root", ROOT, prep["root_inputs"]), ("stage", stage, prep["stage_inputs"])):
    mismatches = [path for path, digest in inputs.items() if not (base / path).is_file() or sha(base / path) != digest]
    checks[label] = dict(inputs=len(inputs), mismatches=mismatches, unchanged=not mismatches)
new_actual = {path.relative_to(work).as_posix() for path in work.rglob("*") if path.is_file()}
extra = sorted(new_actual - prep["new_source_inputs"].keys())
missing = sorted(prep["new_source_inputs"].keys() - new_actual)
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof = dict(recorded_at=at, actual_task="/root", checks=checks, new_extra_files=extra, new_missing_files=missing, all_source_inputs_unchanged=all(check["unchanged"] for check in checks.values()), no_new_files=not extra and not missing, tests_executed=0, quality_executed=0, product_delivery=False, counted_development_failure=False, failed_delivery_count=3, retry_authorized_by_this_receipt_alone=False)
path = OUT / f"protocol-{sys.argv[1]}-workspace-reconciliation.json"
assert not path.exists()
path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(proof))
