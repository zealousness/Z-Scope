"""Full isolated type diagnostics; missing unaccepted dependencies stay errors."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import uuid
from root_runtime_preflight_r23 import inspect_root_runtime

if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("Use non-optimized Linux Python")
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
assert not (STAGE / "zscope/semantics/instance_semantics.py").exists()
OUT = ROOT / "artifacts" / ("coordinator-type-diagnostics-r26-" + uuid.uuid4().hex[:12])
OUT.mkdir(exist_ok=False)
launcher = Path(__file__).read_bytes()
(OUT / "launcher.py").write_bytes(launcher)
started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
command = [sys.executable, "-m", "mypy", "zscope"]
with (OUT / "mypy.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=STAGE, stdout=stream, stderr=subprocess.STDOUT)
stable = before == snapshot()
root_stable = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
proof = dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=command, returncode=result.returncode, source_before=before, source_unchanged=stable, root_unchanged=root_stable, launcher_unchanged=launcher == Path(__file__).read_bytes(), runtime_preflight=runtime, missing_dependency="S01 module deliberately not admitted after two P1 third-delivery findings", tests_executed=0, quality_acceptance=False, independent_acceptance=False, integrated=False, root_joint_verification=False, scope="Diagnostic full mypy command with unchanged flags and no missing-import override, placeholder module or suppressed error; full Stage quality acceptance requires real dependencies and all checks passing.")
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), returncode=result.returncode, source_unchanged=stable, root_unchanged=root_stable)), flush=True)
sys.exit(result.returncode if stable and root_stable and proof["launcher_unchanged"] else 1)
