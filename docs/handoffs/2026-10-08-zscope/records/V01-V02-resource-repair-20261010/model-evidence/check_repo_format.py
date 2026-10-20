"""Apply repository Black settings to changed ranges, then check affected code."""
import ast
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

base = Path(__file__).resolve().parent
root = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
destination = root / "docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010"
source = root / "zscope/core/validation/dynamic_reproduction.py"
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
before = source.read_bytes()
with (base / "dynamic_reproduction.pre_repo_format.py").open("xb") as stream:
    stream.write(before)
command = ["/home/zeal/.cache/zscope-p1-black-venv/bin/black", "--line-ranges", "2257-2307",
           "--line-ranges", "2608-2810", "--line-ranges", "2873-2893", str(source)]
format_result = subprocess.run(command, cwd=root, capture_output=True, check=False)
assert format_result.returncode == 0
assert ast.dump(ast.parse(before)) == ast.dump(ast.parse(source.read_bytes()))
first = json.loads((base / "ordinary-validation.json").read_text())
snapshot = lambda: {p: digest(root / p) for p in first["inputs_before"]["files"]}
inputs = snapshot()
work = Path(tempfile.mkdtemp(prefix="zscope-resource-repo-format-"))
env = {"PATH": "/home/zeal/venv313/bin:/usr/lib/llvm-18/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
       "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1",
       "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "TMPDIR": str(work)}
checks = []
for label, args in (
    ("format-affected-tests", ["-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short",
                               "--basetemp=" + str(work / "tmp"), "--junitxml=" + str(destination / "format-affected-tests.xml"),
                               "tests/test_dynamic_reproduction.py", str(base.parent / "test_v01_v02_independent_drift.py")]),
    ("format-compileall", ["-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"]),
):
    out, err = destination / (label + ".stdout.log"), destination / (label + ".stderr.log")
    active_env = dict(env)
    if label.endswith("compileall"):
        active_env["PYTHONPYCACHEPREFIX"] = str(work / "compile-cache")
    started = time.monotonic()
    cmd = [sys.executable, *args]
    with out.open("xb") as so, err.open("xb") as se:
        result = subprocess.run(cmd, cwd=root, env=active_env, stdout=so, stderr=se,
                                timeout=300, check=False)
    checks.append({"label": label, "command": cmd, "exit_code": result.returncode,
                   "elapsed_seconds": round(time.monotonic() - started, 3),
                   "stdout": out.name, "stderr": err.name})
    assert result.returncode == 0
    print(json.dumps(checks[-1]), flush=True)
after = snapshot()
assert after == inputs
cases = list(ET.parse(destination / "format-affected-tests.xml").getroot().iter("testcase"))
assert len(cases) == 143 and all(not list(c) for c in cases)
record = {"before_sha256": hashlib.sha256(before).hexdigest(), "source_sha256": digest(source),
          "formatting_ast_equivalent": True, "formatter_command": command,
          "repository_black_line_length": 100, "checks": checks, "tests_passed": len(cases),
          "inputs_before": inputs, "inputs_after": after, "changed_inputs": [],
          "compatibility_mypy_not_repeated": "Line wrapping only; AST identical to their tested source."}
(destination / "repo-format-validation.json").write_text(json.dumps(record, indent=2) + "\n")
(base / "repo-format-validation.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps({"source_sha256": digest(source), "tests_passed": len(cases), "changed_inputs": []}))
