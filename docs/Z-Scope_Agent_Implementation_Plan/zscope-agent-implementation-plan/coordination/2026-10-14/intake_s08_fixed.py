"""Intake only stable S08-owned new files after real-process Linux validation."""

from pathlib import Path
import hashlib
import json
import datetime as dt
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = ROOT / ".coordination/20261014/workspaces/s08-owner"
state = json.loads((HERE / "route-check/bridge-response-s08-current-delivery.json").read_text(encoding="utf-8"))
assert state["task_id"] == "task_1e2a609d1d" and state["status"] == "completed"
assert state["observed_model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
suites = ET.parse(HERE / "s08-fixed-explicit-path-tests.xml").getroot().findall("testsuite")
assert sum(int(s.get("tests", "0")) for s in suites) == 69
assert all(int(s.get("failures", "0")) == int(s.get("errors", "0")) == int(s.get("skipped", "0")) == 0 for s in suites)
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
for item in baseline["files"]:
    assert hashlib.sha256((source / item["path"]).read_bytes()).hexdigest() == item["sha256"], item["path"]
names = sorted(p.relative_to(source).as_posix() for p in (source / "zscope/orchestration/jobs").glob("*.py"))
names += ["tests/test_scan_jobs.py", "tests/test_scan_job_execution.py"]
assert len(names) == 12
files = []
for name in names:
    target = ROOT / name
    assert not target.exists(), "root target exists; preserve and inspect: " + name
    raw = (source / name).read_bytes()
    files.append((name, target, raw))
for name, target, raw in files:
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as output:
        output.write(raw)
evidence = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "task_id": state["task_id"],
            "existing_source_changes": [], "tests": "s08-fixed-explicit-path-tests.xml:69 passed/33.64s; original68/1 import-binding failure retained in s08-fixed-independent-tests.xml",
            "files": [{"path": name, "sha256": hashlib.sha256(raw).hexdigest()} for name, target, raw in files],
            "scope": "real owner/store/process over controlled scanners; full JOB04/JOB06, real model/native scanning and real UI jobs not yet verified"}
with (HERE / "intake-s08-fixed.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(evidence, ensure_ascii=False))
