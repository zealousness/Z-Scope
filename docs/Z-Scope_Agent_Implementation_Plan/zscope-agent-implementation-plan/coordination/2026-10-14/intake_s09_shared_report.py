"""Update exactly two reviewed owned files only if prior intake bytes remain intact."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = ROOT / ".coordination/20261014/workspaces/s09-prep"
prior = json.loads((HERE / "intake-s09-prep.json").read_text(encoding="utf-8"))
state = json.loads((HERE / "route-check/bridge-response-s09-shared-report-status.json").read_text(encoding="utf-8"))
assert state["task_id"] == "task_5d7aa39420" and state["status"] == "completed"
assert state["observed_model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
suites = ET.parse(HERE / "s09-shared-report-independent-tests.xml").getroot().findall("testsuite")
assert suites and sum(int(s.get("tests", "0")) for s in suites) == 39
assert all(int(s.get("failures", "0")) == int(s.get("errors", "0")) == int(s.get("skipped", "0")) == 0 for s in suites)
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
for item in baseline["files"]:
    assert hashlib.sha256((source / item["path"]).read_bytes()).hexdigest() == item["sha256"], item["path"]
files = []
for item in prior["files"]:
    target = ROOT / item["path"]
    old = target.read_bytes()
    assert hashlib.sha256(old).hexdigest() == item["sha256"], "root bytes changed; merge required: " + item["path"]
    new = (source / item["path"]).read_bytes()
    files.append((item, target, old, new))
backup = ROOT / ".coordination/20261014/integration-backups/s09-before-shared-report"
for item, target, old, new in files:
    preserved = backup / item["path"]
    preserved.parent.mkdir(parents=True, exist_ok=True)
    if preserved.exists():
        assert preserved.read_bytes() == old
    else:
        preserved.write_bytes(old)
for item, target, old, new in files:
    assert target.read_bytes() == old, "root changed after review"
    temporary = target.with_suffix(target.suffix + ".s09-intake.tmp")
    with temporary.open("xb") as output:
        output.write(new)
    temporary.replace(target)
record = {
    "at": dt.datetime.now(dt.timezone.utc).isoformat(), "task_id": state["task_id"],
    "prior_intake": "intake-s09-prep.json", "existing_source_changes": [],
    "tests": "s09-shared-report-independent-tests.xml:39 passed/3.19s; no formal/LLM/native",
    "large_report_limit": "Actual 16MiB read rejects because optional ijson unavailable; streaming path untested. No formal-ready claim.",
    "files": [{"path": item["path"], "before_sha256": hashlib.sha256(old).hexdigest(), "sha256": hashlib.sha256(new).hexdigest()} for item, target, old, new in files],
}
with (HERE / "intake-s09-shared-report.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(record, ensure_ascii=False))
