"""Read-only syntax and input-reference audit, not test execution."""
from pathlib import Path
import ast
import hashlib
import json
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-s01-replacement-r31-20261017"
paths = [HERE / "prepare_s01_replacement_r31.py", HERE / "check_s01_replacement_r31.py"]
for path in paths:
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
prior = json.loads((ROOT / "artifacts/coordinator-s01-module-dependency-r26-20261016/review.json").read_text(encoding="utf-8"))
files = prior["commands"][0]["command"][6:-1]
assert len(files) == 12 and files[0] == "tests/test_instance_semantics.py"
review = dict(actual_task="/root", syntax_checked=2, original_test_paths=files, tests_executed=0, quality_executed=0, initial_inline_python_shell_launch_failed_before_execution=True, initial_error="Argument expected for the -c option", counted_development_failure=False, script_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths})
(OUT / "pre-dispatch-audit.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(syntax_checked=2, prior_test_paths=len(files), tests_executed=0, quality_executed=0)))
