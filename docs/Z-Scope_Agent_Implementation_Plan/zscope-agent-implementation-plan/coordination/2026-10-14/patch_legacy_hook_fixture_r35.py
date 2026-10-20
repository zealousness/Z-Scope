"""Bind the valid pending-hook fixture to its already captured input revision."""
import ast
import copy
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / ".coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34"
WORK = JOB / "candidate-src-v2"
NAME = "tests/test_scan_jobs.py"
OUT = ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/hook-fixture-readonly-override-r35"
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Unoptimized Linux Python required")
freeze_path = JOB / "python-candidate-v2/source-freeze.json"
assert sha(freeze_path) == "a144dda18e558a6213a5956c2b1e99e80c4075c147f0cb1392dbe5b0b352fa14"
probe = ROOT / "artifacts/coordinator-legacy-hook-fixture-r35-20261017/review.json"
assert sha(probe) == "e983cabe8a67c8e1651aa9cf9db37fcc863e3dd13f958b5963ba5367fb7f1a55"
evidence = read(probe)
assert evidence["diagnostic_evidence_valid"] and evidence["junit"] == dict(tests=1, failures=1, errors=0, skipped=0)
target = WORK / NAME
assert sha(target) == read(freeze_path)["full_candidate_sha256"][NAME]
original = target.read_bytes()
newline = b"\r\n" if b"\r\n" in original else b"\n"
old = b'        owner_token="tok",' + newline + b"        run_dir=run_dir," + newline + b"    )"
new = b'        owner_token="tok",' + newline + b"        run_dir=run_dir," + newline + b'        input_revision=job["input_revision"],' + newline + b"    )"
assert original.count(old) == 1
updated = original.replace(old, new)
expected = copy.deepcopy(ast.parse(original.decode("utf-8")))
functions = [node for node in expected.body if isinstance(node, ast.FunctionDef) and node.name == "_hook_for"]
assert len(functions) == 1 and isinstance(functions[0].body[-1], ast.Return)
call = functions[0].body[-1].value
assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "JobWindowHook"
call.keywords.append(ast.keyword(arg="input_revision", value=ast.Subscript(value=ast.Name(id="job", ctx=ast.Load()), slice=ast.Constant(value="input_revision"), ctx=ast.Load())))
assert ast.dump(ast.parse(updated.decode("utf-8")), include_attributes=False) == ast.dump(expected, include_attributes=False)
floor = read(ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json")
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert all(sha(stage / p) == v for p, v in floor["complete_inputs_after"].items())
assert all(sha(ROOT / p) == v for p, v in floor["root_inputs"].items())
if OUT.exists():
    raise RuntimeError("Preserve previous dependency override")
OUT.mkdir()
(OUT / "original-test-scan-jobs.py").write_bytes(original)
target.write_bytes(updated)
record = dict(actual_task="/root", applied_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    path=NAME, candidate_root=str(WORK), before_sha256=hashlib.sha256(original).hexdigest(), after_sha256=sha(target),
    exact_AST_change="Only add input_revision=job['input_revision'] to the valid _hook_for constructor; every original assertion and other AST node remains identical.",
    native_53_test_unchanged=sha(WORK / "tests/test_job_runtime_footprint_r34.py") == "ac34d7a64e0998e052780fc1f23283875781fc784d2c1141b52e3b827cc09b57",
    diagnostic_receipt_sha256=sha(probe), expected_existing_test_counter_changed=False,
    worker_dependency_path_readonly=True, stage1082_root1065_unchanged=True,
    source_review_and_actual_green_pending=True, independent_acceptance=False, stage_intake=False, root_intake=False)
(OUT / "receipt.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(record))
