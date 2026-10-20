"""Finish independent acceptance without changing implementation or old evidence."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
RECORDS = Path(__file__).resolve().parent
os.chdir(ROOT)
WORK = Path(tempfile.mkdtemp(prefix="zscope-reacceptance-final-"))
result = {"date": "2026-10-09", "work": str(WORK), "checks": []}


def run(label, argv):
    ran = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    check = {"label": label, "command": argv, "exit_code": ran.returncode,
             "stdout": ran.stdout, "stderr": ran.stderr}
    xml = WORK / (label + ".xml")
    if xml.exists():
        counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
        for case in ET.parse(xml).getroot().iter("testcase"):
            state = ("errors" if case.find("error") is not None else "failed"
                     if case.find("failure") is not None else "skipped"
                     if case.find("skipped") is not None else "passed")
            counts[state] += 1
        check["counts"] = counts
    result["checks"].append(check)


def pytest(label, file, extra=()):
    run(label, [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--tb=short",
                f"--basetemp={WORK / label}", f"--junitxml={WORK / (label + '.xml')}", file, *extra])


pytest("scan-seam", str(RECORDS / "V01-V02-reacceptance-integration.py"), ("-k", "missing_optional"))
pytest("docs", "tests/test_agent_docs.py")
run("diff-check", ["git", "-c", "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol", "diff", "--check"])
for label, argv in [("head", ["git", "rev-parse", "HEAD"]),
                    ("branch", ["git", "branch", "--show-current"])]:
    run(label, argv)

baseline = json.loads((RECORDS / "V01-V02-reacceptance-validation.json").read_text())
result["source_changes"] = [name for name, digest in baseline["baseline_files"].items()
    if not (ROOT / name).exists() or hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest]
result["baseline_combined"] = hashlib.sha256(json.dumps(baseline["baseline_files"],
    sort_keys=True, separators=(",", ":")).encode()).hexdigest()
result["encoding"] = {}
for name in ["records/V01-V02-reacceptance-review.md", "TASKS.yaml", "PROGRESS.md"]:
    path = RECORDS.parent / name
    raw = path.read_bytes()
    raw.decode("utf-8", errors="strict")
    result["encoding"][name] = {"utf8_bom": raw.startswith(b"\xef\xbb\xbf"),
                               "crlf": b"\r\n" in raw, "final_lf": raw.endswith(b"\n")}
old = json.loads((RECORDS / "V01-V02-acceptance-final-check.json").read_text())
result["previous_review_scripts_preserved"] = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
    for name, digest in old["review_scripts_sha256"].items()}
result["artifacts"] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(RECORDS.glob("V01-V02-reacceptance*")) if path.is_file()
    and path.name != "V01-V02-reacceptance-final-check.json"}
for relative in ["benchmarks/experiments/balanced_confirmed_tp/dashboard/server.pid",
                 "benchmarks/experiments/balanced_confirmed_tp/m5tpr_replay_results.jsonl"]:
    result["artifacts"][relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
(RECORDS / "V01-V02-reacceptance-final-check.json").write_text(
    json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"checks": [{k:v for k,v in c.items() if k not in {"stdout", "stderr", "command"}}
                             for c in result["checks"]], "source_changes": result["source_changes"],
                  "encoding": result["encoding"],
                  "previous_review_scripts_preserved": result["previous_review_scripts_preserved"]}, indent=2))
