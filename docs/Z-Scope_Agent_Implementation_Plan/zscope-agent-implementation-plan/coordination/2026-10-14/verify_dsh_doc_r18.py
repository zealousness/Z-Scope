"""Independent DSH doc checks with the existing real native tool enabled."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from audit_followup_r12 import audit, HERE, ROOT

assert sys.platform == "linux"
workspace = ROOT / ".coordination/20261014/workspaces/doc-identity-r18"
ownership = audit("doc-identity-r18")
assert not ownership["nonowned_changes"]
expected = {"docs/modules/configuration-state.md", "docs/modules/retrieval-backends.md"}
assert {r["path"] for r in ownership["changes"]} == expected
baseline = json.loads((HERE / "followups-r12/doc-identity-r18-baseline.json").read_text(encoding="utf-8"))
names = {r["path"] for r in baseline["files"]}
def hashes():
    return {p: hashlib.sha256((workspace / p).read_bytes()).hexdigest() for p in sorted(names)}
before = hashes()
out = ROOT / "artifacts/coordinator-dsh-doc-r18-acceptance-20261015"
out.mkdir(exist_ok=False)
for p in expected:
    data = (workspace / p).read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf") and b"\r" not in data and data.endswith(b"\n")
    data.decode("utf-8", errors="strict")
    target = out / "source-before" / p
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
env = dict(os.environ, Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
native = Path(env["Z_SCOPE_TEST_CLANG_INDEXER"])
native_before = hashlib.sha256(native.read_bytes()).hexdigest()
assert native_before == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
tests = ["test_agent_docs", "test_reference_configs", "test_user_config_workbook_readme", "test_config_v3", "test_config_v3_preparation", "test_cli_config_v2", "test_concurrency_config", "test_config_migration", "test_config_v2", "test_project_preparation", "test_contract_usr_scope", "test_contract_build_scope"]
commands = [["-m", "pytest", "-q", *["tests/" + p + ".py" for p in tests], "--junitxml=" + str(out / "results.xml")], ["-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"], ["-m", "mypy", "zscope"]]
results = []
for i, argv in enumerate(commands):
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with (out / f"command-{i}.log").open("w", encoding="utf-8") as log:
        result = subprocess.run([sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, *argv], env=env, stdout=log, stderr=subprocess.STDOUT)
    row = {"argv": argv, "returncode": result.returncode, "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    results.append(row)
    print(json.dumps(row), flush=True)
    if result.returncode:
        break
suite = ET.parse(out / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
native_after = hashlib.sha256(native.read_bytes()).hexdigest()
final_audit = audit("doc-identity-r18")
passed = len(results) == 3 and all(r["returncode"] == 0 for r in results) and before == after and native_before == native_after and not final_audit["nonowned_changes"] and all(suite.get(k) == "0" for k in ("failures", "errors", "skipped"))
proof = {"task_id": "task_b579d5cd4e", "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "commands": results, "junit": dict(suite.attrib), "before_all_inputs": before, "after_all_inputs": after, "source_unchanged": before == after, "delivered_hashes": {p: after[p] for p in sorted(expected)}, "source_snapshot": str(out / "source-before"), "native_before": native_before, "native_after": native_after, "ownership": ownership, "after_ownership": final_audit, "independent_acceptance_passed": passed, "integrated": False, "whole_package_complete": False, "producer_native_skip_note": "Producer extra run skipped two native cases because env was unset; existing native tool was already built. This independent run enables that exact tool and forbids skips.", "scope": "Two fixed module documents only; native USR fixtures reexecuted as validation neighbors. No actual project/model/formal/portable acceptance."}
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert passed
