"""Intake only independent verified files with exact baseline preservation."""
from pathlib import Path
import hashlib
import json
import shutil
import sys
import xml.etree.ElementTree as ET
import datetime as dt

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
branches = {
    "s01-coverage": ("s01-coverage-fixed-independent.xml", "baseline-s01-coverage.json", ["zscope/orchestration/entry_instance_coverage.py", "tests/test_entry_instance_coverage.py"]),
    "s08-scheduling": ("s08-queue-fixed-independent.xml", "baseline-s08-scheduling.json", ["zscope/orchestration/jobs/work_queue.py", "tests/test_scan_job_work_queue.py"]),
    "s08-r5": ("s08-r5-fixed-independent.xml", "baseline.json", ["zscope/orchestration/jobs/service.py", "zscope/orchestration/jobs/store.py", "tests/test_scan_jobs.py", "tests/test_scan_job_execution.py"]),
}
for branch in sys.argv[1:]:
    xml, baseline_name, owned = branches[branch]
    destination_receipt = HERE / f"intake-{branch}-current.json"
    if destination_receipt.exists():
        raise RuntimeError("intake receipt already exists; inspect before another mutation")
    suites = ET.parse(HERE / xml).getroot().findall("testsuite")
    assert suites and all(int(s.get("failures", 0)) == int(s.get("errors", 0)) == int(s.get("skipped", 0)) == 0 for s in suites)
    baseline = json.loads((HERE / baseline_name).read_text(encoding="utf-8"))
    workspace = ROOT / ".coordination/20261014/workspaces" / ("s08-owner" if branch == "s08-r5" else branch)
    for item in baseline["files"]:
        if item["path"] not in owned:
            assert hashlib.sha256((workspace / item["path"]).read_bytes()).hexdigest() == item["sha256"], item["path"]
    previous = {}
    if branch == "s08-r5":
        previous = {item["path"]: item["sha256"] for item in json.loads((HERE / "intake-s08-fixed.json").read_text(encoding="utf-8"))["files"]}
    rows = []
    for name in owned:
        source, target = workspace / name, ROOT / name
        raw = source.read_bytes()
        if branch == "s08-r5":
            old = target.read_bytes()
            assert hashlib.sha256(old).hexdigest() == previous[name], "root changed: " + name
            backup = ROOT / ".coordination/20261014/integration-backups/s08-r5" / name
            backup.parent.mkdir(parents=True, exist_ok=True)
            with backup.open("xb") as stream:
                stream.write(old)
        else:
            assert not target.exists(), name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        rows.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "old_sha256": previous.get(name)})
    proof = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "branch": branch, "independent_junit": xml, "tests": [dict(s.attrib) for s in suites], "baseline_inputs_unchanged": len(baseline["files"]), "files": rows, "scope": "accepted backend slice; not whole package"}
    with destination_receipt.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(proof, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({k: v for k, v in proof.items() if k != "files"}, ensure_ascii=False))
