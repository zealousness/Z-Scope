"""Execute the unchanged real bitcode/SVF readiness case on the frozen Stage."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from root_runtime_preflight_r23 import inspect_root_runtime

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-real-llvm-case-r34-20261017"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize or Path.cwd().resolve() != STAGE or any(os.environ.get(k) for k in ("PYTHONOPTIMIZE", "PYTEST_ADDOPTS", "PYTEST_PLUGINS")):
    raise RuntimeError("Fixed Linux Stage, unoptimized Python and original test environment required")
intake_path = ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json"
environment_path = ROOT / "artifacts/coordinator-joint-llvm-preflight-r34-20261017/receipt.json"
intake, environment = read(intake_path), read(environment_path)
assert environment["environment_preflight_passed"]
source, root_inputs = intake["complete_inputs_after"], intake["root_inputs"]
assert len(source) == 1082 and len(root_inputs) == 1065
assert all(sha(STAGE / p) == v for p, v in source.items()) and all(sha(ROOT / p) == v for p, v in root_inputs.items())
tool_inputs = {p: value["sha256"] for p, value in ((v["path"], v) for v in environment["actual_runner_environment_ldd"].values())}
for value in environment["actual_runner_environment_ldd"].values():
    tool_inputs.update(value["libraries_sha256"])
assert all(sha(Path(p)) == v for p, v in tool_inputs.items())
refs = {str(p): sha(p) for p in (Path(__file__), intake_path, environment_path, HERE / "test_slot.py", HERE / "root_runtime_preflight_r23.py")}
OUT.mkdir(exist_ok=False)
runtime = inspect_root_runtime(require_slot=True)
env = os.environ.copy()
env["Z_SCOPE_TEST_LLVM"] = "1"
case = "tests/test_indexing_pipeline.py::test_real_direct_bitcode_dependency_cache_and_svf"
command = [sys.executable, "-m", "pytest", "-q", f"--rootdir={STAGE}", f"--confcutdir={STAGE}", case, f"--junitxml={OUT / 'results.xml'}"]
(OUT / "preflight.json").write_text(json.dumps(dict(actual_task="/root", started_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), stage_inputs=source, root_inputs=root_inputs, tool_inputs_sha256=tool_inputs, references_sha256=refs, runtime=runtime, selected_actual_case=case, opt_in_LLVM_enabled=True, no_whole_file_or_joint_acceptance=True), indent=2) + "\n", encoding="utf-8", newline="\n")
with (OUT / "command-0.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run(command, cwd=STAGE, env=env, stdout=stream, stderr=subprocess.STDOUT)
tree = ET.parse(OUT / "results.xml").getroot()
counts = dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))
gates = dict(stage1082_unchanged=all(sha(STAGE / p) == v for p, v in source.items()), root1065_unchanged=all(sha(ROOT / p) == v for p, v in root_inputs.items()), actual_svf_tool_library_inputs_unchanged=all(sha(Path(p)) == v for p, v in tool_inputs.items()), references_unchanged=all(sha(Path(p)) == v for p, v in refs.items()))
passed = result.returncode == 0 and counts == dict(tests=1, failures=0, errors=0, skipped=0) and all(gates.values())
receipt = dict(actual_task="/root", finished_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), argv=command, returncode=result.returncode, junit=counts, gates=gates, bounded_real_llvm_svf_readiness_case_passed=passed, full_test_file_passed=False, stage_joint_passed=False, root_joint_passed=False, formal_benchmark_passed=False)
(OUT / "review.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt))
raise SystemExit(0 if passed else 1)
