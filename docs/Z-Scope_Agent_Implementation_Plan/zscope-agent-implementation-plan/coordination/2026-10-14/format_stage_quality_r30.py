"""Format only the seven changed Stage Python files and freeze the repair."""
from pathlib import Path
import ast
import datetime as dt
import hashlib
import json
import subprocess
import sys
from root_runtime_preflight_r23 import inspect_root_runtime

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert Path.cwd().resolve() == STAGE.resolve()
runtime = inspect_root_runtime(require_slot=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def snapshot():
    return {path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}


preparation = read(ROOT / "artifacts/stage-quality-repair-r30-20261017/preparation.json")
paths = [path for path in preparation["source_before"] if path.endswith(".py")] + [preparation["new_test"]]
assert len(paths) == 7
allowed = set(preparation["source_before"]) | {preparation["new_test"]}
assert len(allowed) == 9
intake = read(ROOT / "artifacts/consumer-stage-intake-r30-20261017/receipt.json")
before = snapshot()
assert all(before.get(path) == digest for path, digest in intake["stage_source_after"].items() if path in before and path not in allowed)
assert not set(before) - set(intake["stage_source_after"]) - allowed
before_ast = {path: ast.dump(ast.parse((STAGE / path).read_text(encoding="utf-8")), include_attributes=False) for path in paths}
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
OUT = ROOT / "artifacts/coordinator-stage-format-r30-20261017"
OUT.mkdir(exist_ok=False)
command = [sys.executable, "-m", "black", *paths]
started = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
with (OUT / "black.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=STAGE, stdout=stream, stderr=subprocess.STDOUT)
after = snapshot()
ast_ok = all(before_ast[path] == ast.dump(ast.parse((STAGE / path).read_text(encoding="utf-8")), include_attributes=False) for path in paths)
other_ok = {path: digest for path, digest in before.items() if path not in paths} == {path: digest for path, digest in after.items() if path not in paths}
root_ok = all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
assert result.returncode == 0 and ast_ok and other_ok and root_ok
proof = dict(actual_task="/root", started_at=started, finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), command=command, returncode=result.returncode, formatted_paths=paths, ast_unchanged=True, other_stage_sources_unchanged=True, root_unchanged=True, runtime_preflight=runtime, tests_executed=0, independent_acceptance=False, root_intake=False)
(OUT / "review.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
repair = dict(frozen_at=proof["finished_at"], actual_task="/root", modified_paths=sorted(allowed), source_after={path: after[path] for path in allowed}, full_stage_source_after=after, source_before_repair=preparation["source_before"], other_stage_inputs_unchanged=True, accepted_consumer14_unchanged=all(sha(STAGE / path) == digest for path, digest in intake["copied_source_sha256"].items()), root_pinned_inputs_unchanged=1065, s01_module_still_absent=not (STAGE / "zscope/semantics/instance_semantics.py").exists(), context_native_param_added_but_not_executed=True, tests_or_assertions_weakened=False, fixed_source_ready_for_checks=True, full_stage_quality_passed=False, original_probe_invalid_import_retained="artifacts/coordinator-stage-quality-probe-before-r30-20261017/review.json", actual_before_failure_probe="artifacts/coordinator-stage-quality-probe-corrected-before-r30-20261017/review.json", initial_readonly_review="artifacts/stage-independent-quality-review-r30-20261017/initial-analysis.json", root_intake=False, whole_packages_complete=False)
(ROOT / "artifacts/stage-quality-repair-r30-20261017/repair-source.json").write_text(json.dumps(repair, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(dict(receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), formatted_files=7, frozen_at=repair["frozen_at"], ast_unchanged=True, root_unchanged=True)))
