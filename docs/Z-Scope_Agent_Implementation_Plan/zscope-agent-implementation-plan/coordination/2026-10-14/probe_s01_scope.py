"""Exercise interim entry-instance consumer boundaries using explicit synthetic facts."""

from pathlib import Path
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = ROOT / ".coordination/20261014/workspaces/s01-instances"
sys.path.insert(0, str(source))
from zscope.orchestration.entry_instances import _query_context_instances

path = source / "zscope/orchestration/entry_instances.py"
before = hashlib.sha256(path.read_bytes()).hexdigest()
directory = HERE / "review-repro" / (sys.argv[1] if len(sys.argv) > 1 else "s01-scope-boundary")
directory.mkdir(parents=True)

def foreign_context(name, file, **kwargs):
    return {"complete": True, "function_identity": {"usr": "usr-main", "key": "bc-b:usr-main", "build_context_id": "bc-b"}, "functions": [{"owner": {"file": "unit.c"}}]}

def other_definition(name, file, **kwargs):
    if file:
        return {"complete": False, "reason": "function_identity_not_found"}
    return {"complete": True, "function_identity": {"usr": "usr-other", "key": "bc-a:usr-other", "build_context_id": "bc-a"}, "functions": [{"owner": {"file": "other.c"}}]}

results = {}
for name, getter in (("foreign_build_identity", foreign_context), ("explicit_entry_file_absent_but_other_file_present", other_definition)):
    instances, gap, detail, queries = _query_context_instances(getter, "main", "unit.c", {"build_context_id": "bc-a"})
    results[name] = {"accepted_instances": instances, "gap": gap, "detail": detail, "queries": queries}
after = hashlib.sha256(path.read_bytes()).hexdigest()
proof = {"synthetic_only": True, "interim_worker_source": True, "source_sha256_before": before,
         "source_sha256_after": after, "stable": before == after, "results": results}
(directory / "review.json").write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
print(json.dumps(proof))
