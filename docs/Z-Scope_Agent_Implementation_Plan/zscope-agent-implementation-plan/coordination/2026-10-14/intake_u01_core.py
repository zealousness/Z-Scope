"""Import reviewed v3 core without overwriting any root change since the dirty baseline."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
source = ROOT / ".coordination/20261014/workspaces/u01-config"
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
owned_old = {"zscope/config/config.py", "zscope/config/v2.py"}
owned_new = {"zscope/config/v3.py", "tests/test_config_v3.py"}
state = json.loads((HERE / "current-public/8698ada089bf/u01-state.json").read_text(encoding="utf-8"))
assert state["task_id"] == "task_a4b3c14cd9" and state["status"] == "completed"
assert state["observed_model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
suites = ET.parse(HERE / "u01-schema-fixed-independent-tests.xml").getroot().findall("testsuite")
assert suites and sum(int(s.get("tests", "0")) for s in suites) == 142
assert all(int(s.get("failures", "0")) == int(s.get("errors", "0")) == int(s.get("skipped", "0")) == 0 for s in suites)
expected = {item["path"]: item["sha256"] for item in baseline["files"]}
for name, digest in expected.items():
    if name not in owned_old:
        assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
updates = []
for name in sorted(owned_old | owned_new):
    target = ROOT / name
    old = target.read_bytes() if target.exists() else None
    if name in owned_old:
        assert old is not None and hashlib.sha256(old).hexdigest() == expected[name], "root changed, controlled merge needed: " + name
    else:
        assert old is None, "new root target already exists; inspect rather than overwrite: " + name
    new = (source / name).read_bytes()
    updates.append((name, target, old, new))
backup = ROOT / ".coordination/20261014/integration-backups/u01-before-core"
for name, target, old, new in updates:
    if old is not None:
        preserved = backup / name
        preserved.parent.mkdir(parents=True, exist_ok=True)
        if preserved.exists():
            assert preserved.read_bytes() == old
        else:
            preserved.write_bytes(old)
for name, target, old, new in updates:
    if old is None:
        with target.open("xb") as output:
            output.write(new)
    else:
        assert target.read_bytes() == old
        temporary = target.with_suffix(target.suffix + ".u01-intake.tmp")
        with temporary.open("xb") as output:
            output.write(new)
        temporary.replace(target)
record = {
    "at": dt.datetime.now(dt.timezone.utc).isoformat(), "task_id": state["task_id"],
    "source_baseline": baseline["source_manifest_sha256"], "existing_source_changes": sorted(owned_old),
    "independent_tests": "u01-schema-fixed-independent-tests.xml:142 passed/34.42s; four original schema discrepancy probes now match documented contract",
    "state": "core_imported_pending_root_config_ui_quality_validation_full_u01_unfinished",
    "limits": "Single target only; focus/reproduction/max_workers/platform declared-only; stop_at resolves but S08 does not consume yet; full CLI/init/MCP/templates/prepare and UX remain pending; no actual scan/native/LLM/formal.",
    "files": [{"path": name, "before_sha256": hashlib.sha256(old).hexdigest() if old is not None else None, "sha256": hashlib.sha256(new).hexdigest()} for name, target, old, new in updates],
}
with (HERE / "intake-u01-core.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(record, ensure_ascii=False))
