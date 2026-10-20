"""Format only owned changed Python files, retaining source and AST evidence."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import subprocess
import sys
import uuid
from root_runtime_preflight_r23 import inspect_root_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert Path.cwd().resolve() == STAGE.resolve() and not sys.flags.optimize

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

runtime = inspect_root_runtime(require_slot=True)
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
baseline = read(HERE / "followups-r12/coordinator-instance-integration-r24-baseline.json")
expected = {entry["path"]: entry["sha256"] for entry in baseline["files"]}
allowed = set(baseline["task"]["write_paths"])
for suffix in ("01", "02", "03", "04"):
    allowed.update(read(HERE / "followups-r12" / ("coordinator-instance-integration-r24-ownership-extension-" + suffix + ".json"))["write_paths"])
assert all(sha(STAGE / path) == digest for path, digest in expected.items() if path not in allowed)
paths = sorted(path for path in allowed if path.endswith(".py") and (STAGE / path).is_file() and (path not in expected or sha(STAGE / path) != expected[path]))
assert paths
before = {path: sha(STAGE / path) for path in paths}
before_ast = {path: ast.dump(ast.parse((STAGE / path).read_text(encoding="utf-8")), include_attributes=False) for path in paths}
out = ROOT / "artifacts" / ("coordinator-format-r26-" + uuid.uuid4().hex[:12])
out.mkdir(exist_ok=False)
started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
command = [sys.executable, "-m", "black", *paths]
with (out / "black.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=STAGE, stdout=stream, stderr=subprocess.STDOUT)
after = {path: sha(STAGE / path) for path in paths}
ast_equal = {path: before_ast[path] == ast.dump(ast.parse((STAGE / path).read_text(encoding="utf-8")), include_attributes=False) for path in paths}
readonly_equal = all(sha(STAGE / path) == digest for path, digest in expected.items() if path not in allowed)
root_equal = all(sha(ROOT / path) == digest for path, digest in root_sources.items())
proof = dict(actual_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=command, returncode=result.returncode, source_before=before, source_after=after, ast_unchanged=ast_equal, readonly_inputs_unchanged=readonly_equal, root_unchanged=root_equal, runtime_preflight=runtime, tests_executed=0, worker_candidates_copied=True, admitted_worker_scope="S08 MIN codec only, stage-only; S01 absent", independent_acceptance=False, integrated=False, joint_verification=False, quality_scope="Formatting only, syntax follows separately; no functional/mypy acceptance")
(out / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(out / "review.json").relative_to(ROOT).as_posix(), returncode=result.returncode, changed_python_files=len(paths), ast_unchanged=all(ast_equal.values()), root_unchanged=root_equal)), flush=True)
assert result.returncode == 0 and all(ast_equal.values()) and readonly_equal and root_equal
sys.exit(subprocess.run([sys.executable, str(HERE / "verify_coordinator_syntax_r24.py")], cwd=STAGE).returncode)
