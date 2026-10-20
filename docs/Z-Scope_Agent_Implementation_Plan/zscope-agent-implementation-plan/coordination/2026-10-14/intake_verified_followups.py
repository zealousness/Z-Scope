"""Controlled intake of two stable reviewed followups; no overlapping writers."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
base = {item["path"]: item["sha256"] for item in baseline["files"]}

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def intake(branch, state_name, task_id, xml_name, count, old_names, new_names, accepted=None):
    state = json.loads((HERE / "route-check" / f"bridge-response-{state_name}.json").read_text(encoding="utf-8"))
    assert state["task_id"] == task_id and state["status"] == "completed"
    assert state["observed_model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
    suites = ET.parse(HERE / xml_name).getroot().findall("testsuite")
    assert suites and sum(int(s.get("tests", "0")) for s in suites) == count
    assert all(int(s.get("failures", "0")) == int(s.get("errors", "0")) == int(s.get("skipped", "0")) == 0 for s in suites)
    source = ROOT / ".coordination/20261014/workspaces" / branch
    expected = dict(base)
    expected.update(accepted or {})
    for name, sha in expected.items():
        if name not in old_names:
            assert digest((source / name).read_bytes()) == sha, "source ownership violation: " + name
    items = []
    for name in sorted(set(old_names) | set(new_names)):
        target = ROOT / name
        raw = target.read_bytes() if target.exists() else None
        if name in old_names:
            assert raw is not None and digest(raw) == base[name], "root diverged; controlled merge required: " + name
        else:
            assert raw is None, "new target exists; inspect: " + name
        items.append((name, target, raw, (source / name).read_bytes()))
    for name, target, raw, new in items:
        if raw is not None:
            backup = ROOT / ".coordination/20261014/integration-backups" / branch / name
            backup.parent.mkdir(parents=True, exist_ok=True)
            with backup.open("xb") as output:
                output.write(raw)
    for name, target, raw, new in items:
        if raw is None:
            with target.open("xb") as output:
                output.write(new)
        else:
            assert target.read_bytes() == raw
            temporary = target.with_suffix(target.suffix + ".intake.tmp")
            with temporary.open("xb") as output:
                output.write(new)
            temporary.replace(target)
    evidence = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "task_id": task_id,
                "existing_source_changes": sorted(old_names), "independent_collection": {"junit": xml_name, "tests": count},
                "files": [{"path": name, "before_sha256": digest(raw) if raw is not None else None, "sha256": digest(new)} for name, target, raw, new in items],
                "state": "partial_slice_intaken_pending_same_root_integration_full_package_unfinished"}
    with (HERE / f"intake-{branch}-followup.json").open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(evidence, ensure_ascii=False))

intake("s01-instances", "s01-scope-live", "task_071c8fd074", "s01-scope-fixed-independent-tests.xml", 66,
       {"zscope/orchestration/scan_session.py", "zscope/retrieval/code_index.py"},
       {"zscope/orchestration/entry_instances.py", "tests/test_all_variant_scan.py"})
core = json.loads((HERE / "intake-u01-core.json").read_text(encoding="utf-8"))
intake("u01-config", "u01-preparation-live", "task_6d1d8b525e", "u01-preparation-independent-tests.xml", 87,
       set(), {"zscope/config/v3_preparation.py", "tests/test_config_v3_preparation.py"},
       {item["path"]: item["sha256"] for item in core["files"]})
