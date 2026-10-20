"""Reproducible independent acceptance commands; does not edit product files."""

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
RECORDS = Path(__file__).resolve().parent
WORK = Path(tempfile.mkdtemp(prefix="zscope-v01-v02-reacceptance-20261009-"))
os.chdir(ROOT)


def hashes():
    paths = []
    for directory in ("zscope", "tests", "scripts", "native", "requirements", "docs/modules"):
        paths.extend(p for p in (ROOT / directory).rglob("*") if p.is_file()
                     and "__pycache__" not in p.parts and p.suffix != ".pyc")
    paths.extend(ROOT / p for p in ("pyproject.toml", "AGENTS.md"))
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


before = hashes()
original = json.loads((RECORDS / "V01-V02-final-workspace.json").read_text())
declared = original["frozen_inputs"]["files"]
result = {
    "date": "2026-10-09", "timezone": "Asia/Taipei", "work": str(WORK),
    "python": sys.executable, "version": sys.version, "platform": platform.platform(),
    "cwd": str(ROOT), "PATH": os.environ.get("PATH"),
    "tools": {t: shutil.which(t) for t in ("clang", "gcc", "unshare", "podman", "wpa", "saber")},
    "baseline_files": before,
    "author_record_file_count": len(declared),
    "author_record_changed_files": [p for p, h in declared.items() if before.get(p) != h],
    "checks": [],
}


def save():
    (RECORDS / "V01-V02-reacceptance-validation.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def run(label, argv, timeout=900):
    log = WORK / f"{label}.log"
    start = time.monotonic()
    with log.open("wb") as output:
        proc = subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
    check = {"label": label, "command": argv, "exit_code": proc.returncode,
             "duration_seconds": round(time.monotonic() - start, 3), "log": str(log)}
    check["output"] = log.read_text(encoding="utf-8", errors="replace")
    xml_path = WORK / f"{label}.xml"
    if xml_path.exists():
        cases = list(ET.parse(xml_path).getroot().iter("testcase"))
        counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
        for case in cases:
            state = ("errors" if case.find("error") is not None else "failed"
                     if case.find("failure") is not None else "skipped"
                     if case.find("skipped") is not None else "passed")
            counts[state] += 1
        check["counts"] = counts
        check["junit"] = str(xml_path)
    result["checks"].append(check)
    save()
    print(json.dumps({k: v for k, v in check.items() if k not in {"output", "command"}}), flush=True)


def pytest_run(label, paths, extra=()):
    run(label, [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                "--tb=short", f"--basetemp={WORK / (label + '-tmp')}",
                f"--junitxml={WORK / (label + '.xml')}", *paths, *extra])


save()
pytest_run("supplied-unit", ["tests/test_dynamic_reproduction.py"])
pytest_run("independent-negative", [str(RECORDS / "V01-V02-acceptance-regressions.py")])
pytest_run("new-boundaries", [str(RECORDS / "V01-V02-reacceptance-regressions.py")])
previous = json.loads((RECORDS / "K01-P02-G2-validation.json").read_text())
regressions = [p for p in previous["command"] if p.startswith("tests/") and p.endswith(".py")]
for path in sorted((ROOT / "tests").glob("test_*.py")):
    if path.name.startswith("test_dynamic_reproduction"):
        continue
    content = path.read_text(encoding="utf-8")
    if "deterministic_decision_proof" in content or "apply_deterministic_prevalidation" in content:
        relative = path.relative_to(ROOT).as_posix()
        if relative not in regressions:
            regressions.append(relative)
pytest_run("compatibility", regressions, [
    "-k", "not test_real_mutation_replay and not test_real_direct_bitcode_dependency_cache_and_svf and not test_native_code_to_real_terminal_tool_workbook_and_pool_consumers"
])
run("compileall", [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"])
run("mypy", [sys.executable, "-m", "mypy", "zscope", "--cache-dir", str(WORK / "mypy-cache")])
run("diff-check", ["git", "-c", "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol", "diff", "--check"])
after = hashes()
result["changed_inputs"] = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
result["status"] = "completed"
save()
print(json.dumps({"record": str(RECORDS / "V01-V02-reacceptance-validation.json"),
                  "changed_inputs": result["changed_inputs"]}), flush=True)
