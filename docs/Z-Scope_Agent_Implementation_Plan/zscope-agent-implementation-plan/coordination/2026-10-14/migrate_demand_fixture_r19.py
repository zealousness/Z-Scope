"""Migrate only explicit unknown-USR serialization; retain every oracle assertion."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
branch = ROOT / ".coordination/20261014/workspaces/coordinator-demand-r19"
failed = json.loads((ROOT / "artifacts/coordinator-demand-joint-r19-probe-20261015/review.json").read_text(encoding="utf-8"))
assert failed["source_unchanged"] and failed["junit"]["failures"] == "2"
out = ROOT / "artifacts/coordinator-demand-fixture-r19-migration-20261015"
out.mkdir(exist_ok=False)
name = "tests/fixtures/scan_demand_equivalence/stale_serialized_plan.json"
target = branch / name
original = target.read_bytes()
assert hashlib.sha256(original).hexdigest() == failed["before"][name]
(out / "original-stale_serialized_plan.json").write_bytes(original)
count = 0
def migrate(value):
    global count
    if isinstance(value, dict):
        return {k: migrate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [migrate(v) for v in value]
    if isinstance(value, str) and value.startswith("{"):
        try:
            symbol = json.loads(value)
        except json.JSONDecodeError:
            return value
        if isinstance(symbol, dict) and set(symbol) == {"build_context_id", "file_path", "name", "signature", "symbol_type"}:
            count += 1
            return json.dumps({**symbol, "usr": ""}, sort_keys=True, separators=(",", ":"))
    return value
old = json.loads(original)
new = migrate(old)
assert count > 0
assert new["counts"] == old["counts"] and new["usage"] == old["usage"]
target.write_text(json.dumps(new, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
after = {p: hashlib.sha256((branch / p).read_bytes()).hexdigest() for p in failed["before"]}
assert [p for p in after if after[p] != failed["before"][p]] == [name]
commands = [["-m", "pytest", "-q", "tests/test_scan_demand_equivalence.py", "tests/test_semantic_demand.py", "tests/test_incremental_semantic_modeling.py", "tests/test_global_modeler.py", "--junitxml=" + str(out / "results.xml")], ["-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"], ["-m", "mypy", "zscope"]]
results = []
for i, argv in enumerate(commands):
    at = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / f"command-{i}.log").open("w", encoding="utf-8") as log:
        result = subprocess.run([sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", sys.executable, *argv], stdout=log, stderr=subprocess.STDOUT)
    row = {"argv": argv, "returncode": result.returncode, "started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    results.append(row)
    print(json.dumps(row), flush=True)
    if result.returncode:
        break
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
final = {p: hashlib.sha256((branch / p).read_bytes()).hexdigest() for p in after}
passed = len(results) == 3 and all(r["returncode"] == 0 for r in results) and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped")) and after == final
receipt = {"finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "coordinator_validation_passed": passed, "source_unchanged": after == final, "owned_path": name, "before_sha256": failed["before"][name], "after_sha256": after[name], "symbol_occurrences_migrated": count, "change": "Add only explicit usr empty string to legacy SymbolIdentity JSON strings; every current-input equality, stale/tampered/coverage/obligation/build-partition assertion unchanged.", "before_all_inputs": after, "after_all_inputs": final, "commands": results, "junit": dict(suite.attrib), "root_changed": False, "scope": "Synthetic shadow oracle fixture schema migration; no native/real-project/whole-package claim."}
(out / "review.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert passed
