"""Read-only candidate diagnostic for the original pending-hook positive fixture."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34"
WORK = JOB / "candidate-src-v2"
OUT = ROOT / "artifacts/coordinator-legacy-hook-fixture-r35-20261017"
FREEZE = JOB / "python-candidate-v2/source-freeze.json"
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
if sys.platform != "linux" or sys.flags.optimize or sys.executable != "/home/zeal/venv313/bin/python" or Path.cwd().resolve() != WORK:
    raise RuntimeError("Fixed unoptimized Linux Python and candidate cwd required")
if any(os.environ.get(name) for name in ("PYTHONOPTIMIZE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
    raise RuntimeError("External optimization and test plugins/options forbidden")
assert len(sys.argv) == 2 and sha(Path(__file__)) == sys.argv[1]
assert sha(FREEZE) == "a144dda18e558a6213a5956c2b1e99e80c4075c147f0cb1392dbe5b0b352fa14"
assert sha(HERE / "verify_store_independent_r35.py") == "932c5c2b296b8f9e4f376adba3090d54cc9f89de7199e4a98160e9fd74955540"
assert sha(HERE / "root_runtime_preflight_r23.py") == "37bdbfe76401407280598d39f89424211bb418ff8469b1dc0b2bfe89ce10b4e3"
assert sha(HERE / "test_slot.py") == "7fd4e683bb9e7523a3247eb5efd21ff5a130ebc83375933f32290f4007f9c158"
sys.path.insert(0, str(HERE))
from root_runtime_preflight_r23 import inspect_root_runtime
from verify_store_independent_r35 import host, snapshot, rows
runtime = inspect_root_runtime(require_slot=True)
frozen = read(FREEZE)["full_candidate_sha256"]
before = snapshot(WORK)
assert before == frozen and len(before) == 1083
floor_path = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
assert sha(floor_path) == "b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f"
floor = read(floor_path)
root_before = {name: sha(ROOT / name) for name in floor["root_inputs"]}
assert root_before == floor["root_inputs"] and len(root_before) == 1065
config = {p.relative_to(WORK).as_posix(): sha(p) for basename in ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml") for p in WORK.rglob(basename) if p.is_file()}
assert config == {"pyproject.toml": before["pyproject.toml"]}
host_before = host()
refs = {str(path): sha(path) for path in (Path(__file__), FREEZE, floor_path, HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py", HERE / "verify_store_independent_r35.py")}
OUT.mkdir(exist_ok=False)
argv = [sys.executable, "-m", "pytest", "-q", f"--rootdir={WORK}", f"--confcutdir={WORK}", "tests/test_scan_jobs.py::test_hook_persist_pending_bounds_items_and_records_event", f"--junitxml={OUT / 'results.xml'}"]
started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
(OUT / "preflight.json").write_text(json.dumps(dict(actual_task="/root", started_at=started, candidate_source=before, root_inputs=root_before, configurations=config, reference_sha256=refs, host=host_before, runtime=runtime, argv=argv, probe_only=True), ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
with (OUT / "command-0.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(argv, cwd=WORK, stdout=stream, stderr=subprocess.STDOUT)
after = snapshot(WORK)
tree = ET.parse(OUT / "results.xml").getroot()
counter = Counter((n.get("classname", ""), n.get("name", "")) for n in tree.iter("testcase"))
expected = Counter({("tests.test_scan_jobs", "test_hook_persist_pending_bounds_items_and_records_event"): 1})
junit = dict(tests=sum(counter.values()), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
gates = dict(candidate1083_unchanged=before == after, root1065_unchanged=root_before == {name: sha(ROOT / name) for name in root_before}, configs_unchanged=config == {p.relative_to(WORK).as_posix(): sha(p) for basename in ("conftest.py", "pytest.ini", ".pytest.ini", "mypy.ini", ".mypy.ini", "tox.ini", "setup.cfg", "pyproject.toml") for p in WORK.rglob(basename) if p.is_file()}, references_unchanged=all(sha(name) == digest for name, digest in refs.items()), host_unchanged=host_before == host(), counter_exact=counter == expected, zero_errors_and_skips=junit["errors"] == junit["skipped"] == 0)
record = dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=dict(argv=argv, returncode=result.returncode), junit=junit, case_counter=rows(counter), gates=gates, diagnostic_evidence_valid=all(gates.values()), failure_messages=[node.get("message", "") for node in tree.iter("failure")], candidate_source_sha256=before, reference_sha256=refs, product_or_test_edits=False, stage_intake=False, root_intake=False, independent_acceptance=False)
(OUT / "review.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(actual_task="/root", returncode=result.returncode, junit=junit, gates=gates, diagnostic_evidence_valid=record["diagnostic_evidence_valid"])))
raise SystemExit(0 if record["diagnostic_evidence_valid"] else 1)
