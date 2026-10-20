"""Independent Linux browser acceptance of Astra's stable first-stage delivery."""

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
OUT = ROOT / "artifacts/coordinator-astra-r6-phase1-20261014"
OUT.mkdir(exist_ok=False)
ownership = audit(BRANCH.name)
assert ownership["safe_to_review"] and ownership["delivery_exists"], ownership
delivery = json.loads((BRANCH / "artifacts/delivery-receipt.json").read_text())
files = delivery["files"]


def hashes():
    return {name: hashlib.sha256((BRANCH / name).read_bytes()).hexdigest() for name in files}


assert hashes() == files
env = os.environ.copy()
env.update(
    ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright",
    ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
    ZSCOPE_UI_CONFIG_EVIDENCE=str(OUT / "config"),
    ZSCOPE_UI_EVIDENCE=str(OUT / "u02"),
    ZSCOPE_UI_JOB_EVIDENCE=str(OUT / "owner"),
    ZSCOPE_UI_MULTI_TARGET_EDITING="0",
)
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(BRANCH),
           "--", sys.executable, "-m", "pytest", "-q", "tests/test_agent_workbench_ui.py",
           f"--junitxml={OUT / 'results.xml'}"]
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (OUT / "command.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
suite = ET.parse(OUT / "results.xml").getroot().find("testsuite")
assert suite is not None
proof = {
    "task": "ASTRA-V3-EDITOR", "agent_task_name": "/root/astra_v3_editor_r6",
    "started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "command": command, "returncode": result.returncode, "junit": suite.attrib,
    "ownership": ownership, "delivered_hashes": files, "after_hashes": hashes(),
    "source_unchanged": hashes() == files,
    "scope": "First-stage UI and real single-target HTTP; real multi-target 400 is pending integration; 409 is a labelled fixture; scanner/report data controlled.",
    "integrated": False, "whole_package_complete": False,
}
passed = result.returncode == 0 and suite.get("tests") == "4" and all(
    suite.get(key) == "0" for key in ("failures", "errors", "skipped")) and proof["source_unchanged"]
proof["independent_acceptance_passed"] = passed
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"accepted": passed, "junit": suite.attrib, "receipt": str(OUT / "review.json")}))
sys.exit(0 if passed else 1)
