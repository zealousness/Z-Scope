"""Check the updated handoff and freeze its evidence manifest."""
import hashlib
import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

root = Path("/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope")
base = Path(__file__).resolve().parent
destination = root / "docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010"
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
report = "docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010.md"
documents = ["docs/modules/analysis-pipeline.md", "docs/handoffs/2026-10-08-zscope/TASKS.yaml",
             "docs/handoffs/2026-10-08-zscope/PROGRESS.md", report]
for relative in documents:
    raw = (root / relative).read_bytes()
    raw.decode("utf-8", errors="strict")
    assert not raw.startswith(b"\xef\xbb\xbf") and raw.endswith(b"\n")
    assert b"\r\n" not in raw, relative
work = Path(tempfile.mkdtemp(prefix="zscope-resource-docs-"))
suffix = "-final"
xml_path = destination / ("agent-docs" + suffix + ".xml")
env = {"PATH": "/home/zeal/venv313/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
       "PYTHONPATH": str(root), "PYTHONDONTWRITEBYTECODE": "1",
       "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "TMPDIR": str(work)}
commands = [
    ("agent-docs", [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                    "--basetemp=" + str(work / "tmp"), "--junitxml=" + str(xml_path),
                    "tests/test_agent_docs.py"]),
    ("linux-diff-check", ["git", "-c", "core.whitespace=cr-at-eol", "diff", "--check"]),
    ("black-product-ranges", ["/home/zeal/.cache/zscope-p1-black-venv/bin/black", "--check",
                              "--line-ranges", "2257-2307", "--line-ranges", "2608-2802",
                              "--line-ranges", "2870-2900", "zscope/core/validation/dynamic_reproduction.py"]),
    ("black-new-tests", ["/home/zeal/.cache/zscope-p1-black-venv/bin/black", "--check",
                        "--line-ranges", "2401-2900", "tests/test_dynamic_reproduction.py"]),
]
checks = []
for label, command in commands:
    label += suffix
    out, err = destination / (label + ".stdout.log"), destination / (label + ".stderr.log")
    with out.open("xb") as so, err.open("xb") as se:
        result = subprocess.run(command, cwd=root, env=env, stdout=so, stderr=se,
                                timeout=120, check=False)
    checks.append({"label": label, "command": command, "exit_code": result.returncode,
                   "stdout": out.name, "stderr": err.name})
counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
for case in ET.parse(xml_path).getroot().iter("testcase"):
    state = ("errors" if case.find("error") is not None else
             "failed" if case.find("failure") is not None else
             "skipped" if case.find("skipped") is not None else "passed")
    counts[state] += 1
record = {"checks": checks, "docs_counts": counts, "utf8_no_bom_lf": True}
(destination / "documentation-final-validation.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record), flush=True)
assert all(check["exit_code"] == 0 for check in checks)
baseline = json.loads((base.parent / "V01-V02-TSAN-minimal-20261010-xc9j8htj.json").read_text())["inputs_after"]
expected = set(documents[:-1]) | {"zscope/core/validation/dynamic_reproduction.py",
                                  "tests/test_dynamic_reproduction.py"}
actual = [p for p, value in baseline.items() if digest(root / p) != value]
assert set(actual) == expected, actual
source = root / "zscope/core/validation/dynamic_reproduction.py"
assert digest(source) == json.loads((base / "repo-format-validation.json").read_text())["source_sha256"]
shutil.copyfile(Path(__file__), destination / "model-evidence/final_documentation_checks.py")
artifact_files = sorted(p for p in destination.rglob("*") if p.is_file())
manifest = {
    "at": datetime.now(timezone.utc).isoformat(), "source_sha256": digest(source),
    "source_and_test": {p: digest(root / p) for p in sorted(expected) + [report]},
    "existing_input_count": len(baseline), "declared_changes": actual, "unexpected_changes": [],
    "ordinary_counts": json.loads((destination / "summary.json").read_text())["ordinary_checks"],
    "docs_counts": counts, "compileall_exit": 0, "mypy_exit": 0,
    "current_revision_real_ASAN": "not_run", "real_TSAN": "blocked/not_run",
    "V01": "in_progress", "V02": "blocked",
    "artifacts": {str(p.relative_to(destination)): {"sha256": digest(p), "bytes": p.stat().st_size}
                  for p in artifact_files},
}
(destination / "final-evidence-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"manifest": str(destination / "final-evidence-manifest.json"),
                  "declared_changes": actual, "unexpected_changes": []}))
