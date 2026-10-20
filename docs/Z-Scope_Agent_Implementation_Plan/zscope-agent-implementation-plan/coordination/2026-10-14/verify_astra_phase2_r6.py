"""Independent stable-byte real HTTP/browser acceptance after U01 integration."""
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
BRANCH = ROOT / ".coordination/20261014/workspaces/astra-config-r6"
PHASE = int(sys.argv[1]) if len(sys.argv) > 1 else 2
assert PHASE in (2, 3)
OUT = ROOT / ("artifacts/coordinator-astra-r6-phase2-retry1-20261014" if PHASE == 2 else
              "artifacts/coordinator-astra-r6-phase3-20261014")
OUT.mkdir(exist_ok=False)
ownership = audit(BRANCH.name)
assert ownership["safe_to_review"], ownership
delivery = json.loads((BRANCH / f"artifacts/phase{PHASE}-delivery-receipt.json").read_text())
files = delivery["files"]
dependencies = delivery.get("readonly_dependencies", delivery.get("unchanged_dependencies"))
assert dependencies

def hashes():
    return {name: hashlib.sha256((BRANCH / name).read_bytes()).hexdigest() for name in files}

def dependency_hashes():
    return {row["path"]: hashlib.sha256((BRANCH / row["path"]).read_bytes()).hexdigest() for row in dependencies}

assert hashes() == files
before_dependencies = dependency_hashes()
assert before_dependencies == {row["path"]: row["sha256"] for row in dependencies}
env = os.environ.copy()
env.update(
    ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright",
    ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
    ZSCOPE_UI_CONFIG_EVIDENCE=str(OUT / "config"), ZSCOPE_UI_EVIDENCE=str(OUT / "u02"),
    ZSCOPE_UI_JOB_EVIDENCE=str(OUT / "owner"), ZSCOPE_UI_MULTI_TARGET_EDITING="1",
)
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(BRANCH), "--",
           sys.executable, "-m", "pytest", "-q", "tests/test_agent_workbench_ui.py",
           "tests/test_config_editor_http.py", f"--junitxml={OUT / 'results.xml'}"]
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (OUT / "command.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(OUT / "results.xml").getroot().find("testsuite")
assert suite is not None
after = hashes()
proof = {
    "task": "ASTRA-V3-EDITOR", "agent_task_name": "/root/astra_v3_editor_r6",
    "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "command": command, "returncode": result.returncode, "junit": suite.attrib,
    "ownership": ownership, "delivered_hashes": files, "after_hashes": after,
    "source_unchanged": after == files and dependency_hashes() == before_dependencies,
    "dependencies": before_dependencies,
    "scope": "Real all-target HTTP/browser editing, exact GET and prepare execution refusal; 409 labelled contract fixture. Scanner/report effects controlled.",
    "integrated": False, "whole_package_complete": False,
}
passed = result.returncode == 0 and suite.get("tests") == "10" and all(
    suite.get(key) == "0" for key in ("failures", "errors", "skipped")) and proof["source_unchanged"]
proof["independent_acceptance_passed"] = passed
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"accepted": passed, "junit": suite.attrib, "receipt": str(OUT / "review.json")}))
sys.exit(0 if passed else 1)
