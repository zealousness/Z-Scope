"""Read-only ownership/source audit; does not run tests, tools or processes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import uuid

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
NAME = "coordinator-instance-integration-r24"
STAGE = ROOT / ".coordination/20261014/workspaces" / NAME

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

baseline = read(HERE / "followups-r12" / (NAME + "-baseline.json"))
expected = {row["path"]: row["sha256"] for row in baseline["files"]}
allowed = set(baseline["task"]["write_paths"])
for suffix in ("01", "02", "03", "04"):
    allowed.update(read(HERE / "followups-r12" / (NAME + "-ownership-extension-" + suffix + ".json"))["write_paths"])
root_drift = [path for path, digest in expected.items() if not (ROOT / path).is_file() or sha(ROOT / path) != digest]
changed = {
    path: sha(STAGE / path) if (STAGE / path).is_file() else None
    for path, digest in expected.items()
    if not (STAGE / path).is_file() or sha(STAGE / path) != digest
}
new = {}
for directory in ("zscope", "tests", "docs/modules"):
    for path in (STAGE / directory).rglob("*"):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        relative = path.relative_to(STAGE).as_posix()
        if relative not in expected:
            new[relative] = sha(path)
unexpected = sorted((set(changed) | set(new)) - allowed)
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
out = ROOT / "artifacts" / ("coordinator-instance-stage-audit-r24-" + uuid.uuid4().hex[:12])
out.mkdir(exist_ok=False)
result = {
    "observed_at": at, "actual_task": "/root", "logical_task": "COORD-INSTANCE-INTEGRATION-R24",
    "root_bound_inputs": len(expected), "root_source_drift": root_drift,
    "workspace": str(STAGE), "changed": changed, "new": new,
    "unexpected_write_paths": unexpected, "ownership_audit_passed": not root_drift and not unexpected,
    "functional_acceptance": False, "independent_acceptance": False, "integrated": False,
    "joint_verification": False, "tests_executed": 0, "services_started": 0,
    "native_process_inspection": False, "worker_candidates_copied": True,
    "worker_candidates": ["S08 isolated MIN codec; stage only; no S01"],
}
(out / "review.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "receipt": str(out / "review.json"), "passed": result["ownership_audit_passed"], "changed": list(changed), "new": list(new)}, ensure_ascii=False), flush=True)
sys.exit(0 if result["ownership_audit_passed"] else 1)
