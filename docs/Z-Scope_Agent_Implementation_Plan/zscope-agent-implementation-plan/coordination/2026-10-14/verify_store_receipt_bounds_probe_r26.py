"""Reproduce legal codec identity truncation at the actual Store/Queue seam."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") or os.environ.get("PYTEST_ADDOPTS") or os.environ.get("PYTEST_PLUGINS"):
    raise RuntimeError("Non-optimized Linux checks with default pytest environment required")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert Path.cwd().resolve() == STAGE.resolve()
runtime = inspect_root_runtime(require_slot=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot():
    return {path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}

root_inputs = json.loads((ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
before = snapshot()
OUT = ROOT / "artifacts/coordinator-store-receipt-bounds-probe-r26-20261016"
OUT.mkdir(exist_ok=False)
launcher = Path(__file__).read_bytes()
(OUT / "launcher.py").write_bytes(launcher)
command = [sys.executable, "-m", "pytest", "-q", f"--rootdir={STAGE}", f"--confcutdir={STAGE}", "tests/test_job_bound_instance_results.py::test_legal_long_usr_cannot_publish_a_truncated_sql_receipt", f"--junitxml={OUT / 'results.xml'}"]
with (OUT / "command-0.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=STAGE, stdout=stream, stderr=subprocess.STDOUT)
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
stable = before == snapshot()
root_stable = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
proof = dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=command, returncode=result.returncode, junit=counts, source_before=before, sources_unchanged=stable, root_unchanged=root_stable, launcher_unchanged=launcher == Path(__file__).read_bytes(), runtime_preflight=runtime, source_review_finding="Legal >4000-character receipt data is truncated by the generic event writer but the Store returns a full in-memory trusted receipt", codec_failure=False, independent_acceptance=False, integrated=False, root_joint_verification=False)
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), returncode=result.returncode, junit=counts, sources_unchanged=stable, root_unchanged=root_stable)), flush=True)
sys.exit(result.returncode if stable and root_stable and proof["launcher_unchanged"] else 1)
