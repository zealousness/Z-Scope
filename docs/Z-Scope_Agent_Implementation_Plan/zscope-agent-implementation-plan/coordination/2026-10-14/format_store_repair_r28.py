"""Format only the two coordinator-owned Store repair files."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from root_runtime_preflight_r23 import inspect_root_runtime

if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE"):
    raise RuntimeError("Non-optimized Linux Python required")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
if Path.cwd().resolve() != STAGE.resolve():
    raise RuntimeError("Outer slot selected the wrong workspace")
runtime = inspect_root_runtime(require_slot=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot():
    return {path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}

root_sources = json.loads((ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
paths = ["zscope/orchestration/jobs/store.py", "tests/test_job_bound_instance_results.py"]
before = snapshot()
before_ast = {path: ast.dump(ast.parse((STAGE / path).read_text(encoding="utf-8")), include_attributes=False) for path in paths}
launcher = Path(__file__).read_bytes()
OUT = ROOT / "artifacts/coordinator-store-format-r28-20261017"
OUT.mkdir(exist_ok=False)
(OUT / "launcher.py").write_bytes(launcher)
command = [sys.executable, "-m", "black", *paths]
started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
with (OUT / "black.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=STAGE, stdout=stream, stderr=subprocess.STDOUT)
after = snapshot()
ast_equal = {path: before_ast[path] == ast.dump(ast.parse((STAGE / path).read_text(encoding="utf-8")), include_attributes=False) for path in paths}
unowned_stable = {path: digest for path, digest in before.items() if path not in paths} == {path: digest for path, digest in after.items() if path not in paths}
root_stable = all(sha(ROOT / path) == digest for path, digest in root_sources.items())
proof = dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=command, returncode=result.returncode, source_before={path: before[path] for path in paths}, source_after={path: after[path] for path in paths}, ast_unchanged=ast_equal, other_stage_sources_unchanged=unowned_stable, root_unchanged=root_stable, launcher_unchanged=launcher == Path(__file__).read_bytes(), runtime_preflight=runtime, tests_executed=0, functional_acceptance=False, integrated=False, root_joint_verification=False)
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
passed = result.returncode == 0 and all(ast_equal.values()) and unowned_stable and root_stable and proof["launcher_unchanged"]
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), returncode=result.returncode, ast_unchanged=all(ast_equal.values()), other_sources_unchanged=unowned_stable, root_unchanged=root_stable)))
sys.exit(0 if passed else 1)
