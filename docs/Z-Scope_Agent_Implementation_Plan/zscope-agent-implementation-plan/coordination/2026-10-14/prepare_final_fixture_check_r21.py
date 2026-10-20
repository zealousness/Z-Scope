"""Prepare focused verification after adding only provenance assertions."""
from pathlib import Path
HERE = Path(__file__).resolve().parent
source = (HERE / "verify_root_fixtures_r21.py").read_text(encoding="utf-8")
source = source.replace('coordinator-root-fixtures-r21-acceptance-20261015', 'coordinator-root-fixtures-r21-final-acceptance-20261015')
needle = 'commands = [[sys.executable, "-m", "pytest", "-q", *tests,'
assert source.count(needle) == 1
source = source.replace(needle, '''initial = json.loads((ROOT / "artifacts/coordinator-root-fixtures-r21-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert initial["passed"] and len(initial["commands"]) == 3
assert before["tests/test_mcp_jobs.py"] == initial["after"]["tests/test_mcp_jobs.py"]
assert all(before[p] == sha for p, sha in initial["after"].items() if p != "tests/test_job_remaining.py")
tests = tests[:3]  # unchanged native collection already passed; full Root retains it.
commands = [[sys.executable, "-m", "pytest", "-q", *tests,''')
target = HERE / "verify_root_fixtures_final_r21.py"
assert not target.exists()
compile(source, str(target), "exec")
target.write_text(source, encoding="utf-8", newline="\n")
print(str(target), flush=True)
