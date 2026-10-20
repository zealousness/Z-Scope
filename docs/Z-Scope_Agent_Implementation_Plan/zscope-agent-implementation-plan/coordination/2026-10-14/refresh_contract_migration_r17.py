"""Publish readonly migrated tests, retaining the still-failing product case."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import ROOT, HERE, audit

assert sys.platform == "linux"
label = "coordinator-contract-migration-r17-20261015"
out = ROOT / "artifacts" / label
proof = json.loads((out / "review.json").read_text(encoding="utf-8"))
assert not proof["validated"] and proof["before"] == proof["after"]
suite = ET.parse(out / "results.xml").getroot()
failed = [row.get("name") for row in suite.iter("testcase") if row.find("failure") is not None]
assert failed == ["test_wrapped_guard_keeps_slot_address_and_parameter_mapping"]
assert proof["junit"]["tests"] == "105" and proof["junit"]["failures"] == "1"
assert proof["junit"]["errors"] == proof["junit"]["skipped"] == "0"
branch = ROOT / ".coordination/20261014/workspaces/coordinator-contract-migration-r17"
producer = ROOT / ".coordination/20261014/workspaces/contract-validation-r12"
baseline = json.loads((HERE / "followups-r12/coordinator-contract-migration-r17-baseline.json").read_text(encoding="utf-8"))
owns = baseline["task"]["owns"]
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha for p, sha in proof["after"].items())
assert not audit("coordinator-contract-migration-r17")["nonowned_changes"]
commands = []
for number, args in enumerate([
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "black", "--check", *owns],
]):
    command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(branch), "--", *args]
    at = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / ("quality-" + str(number) + ".log")).open("w", encoding="utf-8") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    commands.append({"command": command, "returncode": result.returncode, "started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()})
    print(json.dumps(commands[-1]), flush=True)
    assert result.returncode == 0
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == sha for p, sha in proof["after"].items())
processes = json.loads(subprocess.check_output([sys.executable, str(HERE / "inspect_workspace_processes.py"), "contract-validation-r12"], text=True))
assert not processes["processes"], processes
path = HERE / "followups-r12/contract-validation-r12-dependencies.json"
ready = HERE / "followups-r12/contract-test-migration-ready-r17.json"
assert not path.exists() and not ready.exists()
files = []
for name in owns:
    original = next(row["sha256"] for row in baseline["files"] if row["path"] == name)
    assert hashlib.sha256((producer / name).read_bytes()).hexdigest() == original
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == original
    sha = proof["after"][name]
    assert hashlib.sha256((out / "source-before" / name).read_bytes()).hexdigest() == sha
    shutil.copyfile(out / "source-before" / name, producer / name)
    files.append({"path": name, "previous_sha256": original, "sha256": sha, "readonly": True, "authority": (out / "review.json").relative_to(ROOT).as_posix(), "authority_scope": "Coordinator-prepared migration: 104 passed / 1 genuine product regression remains. No acceptance or root intake."})
at = dt.datetime.now(dt.timezone.utc).isoformat()
data = {"refreshed_at": at, "files": files, "source_tests": proof["junit"], "quality": commands, "quality_passed": True, "coordinator_authored": True, "migration_full_passed": False, "independent_acceptance": False, "root_changed": False, "integrated": False, "whole_package_complete": False, "remaining_failure": failed[0], "instruction": "Four readonly test dependencies are ready for the producer's final full regression. One test intentionally still exposes the real compiler product gap: deterministic_contract_snapshot(ctx, registry) with complete synthetic native wrapper/callee identities returns None; do not alter or wrap this test to hide the missing identity propagation. Inspect contract_compiler known-callee loops, especially unbound find_for_call at1034/1087/1238. Fix product; all105 and original full regression plus all independent probes must pass. Do not wait for a falsely green migration receipt."}
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
ready.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
(out / "quality-and-refresh.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"readonly_tests_refreshed": owns, "at": at, "remaining_product_failure": failed[0], "root_changed": False}))
