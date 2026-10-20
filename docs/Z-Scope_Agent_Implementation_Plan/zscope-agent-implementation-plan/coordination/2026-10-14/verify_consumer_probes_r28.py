"""Fixed public-entry consumer probes; no producer or Root mutation."""
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
    raise RuntimeError("Non-optimized Linux/default pytest environment required")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
assert Path.cwd().resolve() == BRANCH.resolve()
runtime = inspect_root_runtime(require_slot=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot():
    return {path.relative_to(BRANCH).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests") for path in (BRANCH / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}

root_inputs = json.loads((ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
before = snapshot()
producer = BRANCH / "artifacts/instance-consumers-r25/review.json"
assert sha(producer) == "5101d36e10090514e2b4dabb41536e8e555f4075701a0c9a0853fbf9ec544352"
probe = ROOT / "artifacts/astra-consumer-boundary-probes-r28-20261017/test_consumer_boundaries.py"
references = {str(path): sha(path) for path in (Path(__file__), producer, probe)}
OUT = ROOT / "artifacts/coordinator-consumer-boundary-probes-r28-20261017"
OUT.mkdir(exist_ok=False)
launcher = Path(__file__).read_bytes()
(OUT / "launcher.py").write_bytes(launcher)
command = [sys.executable, "-m", "pytest", "-q", f"--rootdir={BRANCH}", f"--confcutdir={BRANCH}", str(probe), f"--junitxml={OUT / 'results.xml'}"]
env = os.environ.copy()
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
with (OUT / "command-0.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=BRANCH, env=env, stdout=stream, stderr=subprocess.STDOUT)
suites = ET.parse(OUT / "results.xml").getroot().findall("testsuite")
counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
stable = before == snapshot()
root_stable = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
refs_stable = all(sha(Path(path)) == digest for path, digest in references.items()) and launcher == Path(__file__).read_bytes()
proof = dict(actual_task="/root", logical_task="ASTRA-INSTANCE-CONSUMERS-R25", actual_producer_task="/root/astra_design_contract_r23", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=command, returncode=result.returncode, junit=counts, source_before=before, sources_unchanged=stable, root_unchanged=root_stable, references_sha256=references, references_unchanged=refs_stable, runtime_preflight=runtime, scope="Actual public Clang entry with controlled semantics; unknown project template ownership and case-sensitive capability boundary. No real project/factory/native effect claim.", independent_acceptance=False, integrated=False, root_joint_verification=False)
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), junit=counts, returncode=result.returncode, sources_unchanged=stable, root_unchanged=root_stable, references_unchanged=refs_stable)), flush=True)
sys.exit(result.returncode if stable and root_stable and refs_stable else 1)
