"""Recheck only the migrated unit tests and compileall after the import fix."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

base = Path(__file__).resolve().parent
root = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
first = json.loads((base / "ordinary-validation.json").read_text())
work = Path(tempfile.mkdtemp(prefix="zscope-resource-final-unit-"))
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
snapshot = lambda: {p: digest(root / p) for p in first["inputs_before"]["files"]}
before = snapshot()
changes = [p for p, value in first["inputs_after"]["files"].items() if before[p] != value]
assert changes == ["tests/test_dynamic_reproduction.py"], changes
env = {"PATH": "/home/zeal/venv313/bin:/usr/lib/llvm-18/bin:/usr/bin:/bin",
       "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1",
       "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "LANG": "C.UTF-8", "TMPDIR": str(work)}
checks = []
for label, args in (
    ("unit-final", ["-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short",
                    "--basetemp=" + str(work / "tmp"), "--junitxml=" + str(base / "unit-final.xml"),
                    "tests/test_dynamic_reproduction.py"]),
    ("compileall-final", ["-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"]),
):
    out, err = base / (label + ".stdout.log"), base / (label + ".stderr.log")
    command = [sys.executable, *args]
    started = time.monotonic()
    active_env = dict(env)
    if label.startswith("compileall"):
        active_env["PYTHONPYCACHEPREFIX"] = str(work / "compile-cache")
    with out.open("xb") as so, err.open("xb") as se:
        result = subprocess.run(command, cwd=root, env=active_env, stdout=so, stderr=se,
                                timeout=300, check=False, start_new_session=True)
    check = {"label": label, "command": command, "cwd": str(root), "exit_code": result.returncode,
             "elapsed_seconds": round(time.monotonic() - started, 3), "stdout": str(out),
             "stderr": str(err), "stdout_sha256": digest(out), "stderr_sha256": digest(err),
             "counts": None, "stopped": None}
    if label == "unit-final":
        xml = base / "unit-final.xml"
        cases = list(ET.parse(xml).getroot().iter("testcase"))
        counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
        for case in cases:
            state = ("errors" if case.find("error") is not None else
                     "failed" if case.find("failure") is not None else
                     "skipped" if case.find("skipped") is not None else "passed")
            counts[state] += 1
        check.update(counts={**counts, "tests": len(cases)}, junit=str(xml), junit_sha256=digest(xml))
    checks.append(check)
    print(json.dumps({"label": label, "exit_code": result.returncode, "counts": check["counts"]}), flush=True)
after = snapshot()
record = {"checks": checks, "inputs_before": before, "inputs_after": after,
          "changed_inputs": [p for p in before if before[p] != after[p]],
          "planned_test_only_delta_from_first_round": changes,
          "product_sha256": digest(root / "zscope/core/validation/dynamic_reproduction.py")}
(base / "integrated-final-validation.json").write_text(json.dumps(record, indent=2) + "\n")
assert not record["changed_inputs"]
assert all(check["exit_code"] == 0 for check in checks)
