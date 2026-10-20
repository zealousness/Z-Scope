"""Independent Linux acceptance of the stable U01 repair, including original probes."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from audit_followup_r6 import audit

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/u01-entrypoints-r6"
OUT = ROOT / "artifacts/coordinator-u01-review1-r6-20261014"
OUT.mkdir(exist_ok=False)
ownership = audit(BRANCH.name)
assert ownership["safe_to_review"] and ownership["delivery_exists"]
delivery = (BRANCH / "DELIVERY.md").read_text(encoding="utf-8")
files = {row["path"]: row["after"] for row in ownership["changes"]}
assert len(files) == 8
assert all(value and value in delivery and name in delivery for name, value in files.items())


def hashes():
    return {name: hashlib.sha256((BRANCH / name).read_bytes()).hexdigest() for name in files}


tests = [
    "tests/test_config_v3_entrypoints.py", "tests/test_cli_config_v2.py",
    "tests/test_reference_configs.py", "tests/test_project_preparation.py",
    "tests/test_config_v3.py", "tests/test_config_v3_preparation.py", "tests/test_config_v2.py",
    "tests/test_config_migration.py", "tests/test_agent_docs.py", "tests/test_portable_release.py",
    str(HERE / "followups-r6/test_init_yaml_paths.py"),
    str(HERE / "followups-r6/test_editor_concurrent_candidates.py"),
]
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(BRANCH),
           "--", sys.executable, "-m", "pytest", "-q", *tests,
           f"--junitxml={OUT / 'results.xml'}"]
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (OUT / "command.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(OUT / "results.xml").getroot().find("testsuite")
assert suite is not None
proof = {
    "task": "U01-ENTRYPOINTS", "task_id": "task_8e1ce5c8cc",
    "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "command": command, "returncode": result.returncode, "junit": suite.attrib,
    "ownership": ownership, "delivered_hashes": files, "after_hashes": hashes(),
    "source_unchanged": hashes() == files,
    "scope": "CLI/init/templates and parser-only editor; shared service, v3 portable-template assertion migration and browser multi-target integration remain coordinator work.",
    "integrated": False, "whole_package_complete": False,
}
passed = result.returncode == 0 and suite.get("tests") == "201" and all(
    suite.get(key) == "0" for key in ("failures", "errors", "skipped")) and proof["source_unchanged"]
proof["independent_acceptance_passed"] = passed
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"accepted": passed, "junit": suite.attrib, "receipt": str(OUT / "review.json")}))
sys.exit(0 if passed else 1)
