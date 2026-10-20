"""Preserve a zero-test inventory failure and fix the launcher exclusion scope."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORK = ROOT / ".coordination/20261014/workspaces/coordinator-contract-tests-r33"
OUT = ROOT / "artifacts/coordinator-contract-tests-r33-20261017"
LAUNCHER = HERE / "verify_legacy_contract_tests_r33.py"
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
prep = json.loads((OUT / "preparation.json").read_text(encoding="utf-8"))
expected = prep["complete_baseline"] | prep["candidate_sha256"]
old_inventory = {path.relative_to(WORK).as_posix(): sha(path) for path in WORK.rglob("*") if path.is_file() and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache", "artifacts"} for part in path.relative_to(WORK).parts) and path.suffix != ".pyc"}
missing = set(expected) - set(old_inventory)
assert missing == {"tests/fixtures/wiki_project/artifacts/scan-report.md"}
assert all(sha(WORK / path) == digest for path, digest in expected.items())
assert not (OUT / "preflight.json").exists() and not (OUT / "results.xml").exists()
shutil.copyfile(LAUNCHER, OUT / "launcher-initial.py")
receipt = dict(actual_task="/root", observed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), exception="AssertionError", missing_actual_input=list(missing), original_launcher_sha256=sha(LAUNCHER), cause="Excluded every nested directory named artifacts instead of only generated workspace artifacts; fixture material must stay protected", actual_test_count=0, product_written=False, stage_written=False, root_written=False)
(OUT / "initial-launcher-failure.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
source = LAUNCHER.read_text(encoding="utf-8")
old = 'and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache", "artifacts"} for part in path.relative_to(WORK).parts)'
new = 'and path.relative_to(WORK).parts[0] != "artifacts" and not any(part in {"__pycache__", ".pytest_cache", ".mypy_cache"} for part in path.relative_to(WORK).parts)'
assert source.count(old) == 1
LAUNCHER.write_text(source.replace(old, new), encoding="utf-8", newline="\n")
print(json.dumps(dict(corrected_launcher_sha256=sha(LAUNCHER), original_failure_preserved=True)))
