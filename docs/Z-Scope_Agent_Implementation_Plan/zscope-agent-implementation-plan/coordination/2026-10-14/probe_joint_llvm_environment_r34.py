"""Read the real LLVM/SVF environment; do not run or claim benchmark/test acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
if sys.platform != "linux" or sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") or Path.cwd().resolve() != ROOT:
    raise RuntimeError("Environment probe requires the fixed Linux root and unoptimized Python")
OUT = ROOT / "artifacts/coordinator-joint-llvm-preflight-r34-20261017"
OUT.mkdir(exist_ok=False)
sys.path.insert(0, str(ROOT))
from zscope.retrieval.llvm_toolchain import svf_environment, validate_svf_llvm

sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
names = ("cmake", "gcc", "clang", "clangd", "gclang", "get-bc", "llvm-link", "llvm-nm", "wpa", "saber")
paths = {name: shutil.which(name) for name in names}
env = svf_environment("")
results = {}
for name in ("wpa", "saber"):
    if paths[name]:
        linked = subprocess.run(["ldd", paths[name]], env=env, capture_output=True, text=True, timeout=15)
        libraries = {Path(v) for v in re.findall(r"/[^\s()]+", linked.stdout) if Path(v).is_file()}
        results[name] = dict(path=paths[name], physical=str(Path(paths[name]).resolve(strict=True)), sha256=sha(Path(paths[name])), ldd_returncode=linked.returncode, ldd_stdout=linked.stdout, ldd_stderr=linked.stderr, libraries_sha256={str(p): sha(p) for p in sorted(libraries)}, no_missing_shared_libraries=linked.returncode == 0 and "not found" not in linked.stdout + linked.stderr)
compatibility = dict(passed=False)
try:
    if not all(paths.values()):
        raise RuntimeError("Missing tools: " + ",".join(k for k, v in paths.items() if not v))
    validate_svf_llvm("", paths["llvm-link"])
    compatibility = dict(passed=True)
except Exception as exc:
    compatibility = dict(passed=False, error_type=type(exc).__name__, error=str(exc))
passed = bool(all(paths.values()) and compatibility["passed"] and len(results) == 2 and all(v["no_missing_shared_libraries"] for v in results.values()))
receipt = dict(actual_task="/root", checked_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), tools_on_actual_login_PATH=paths, actual_runner_environment_ldd=results, llvm_svf_version_compatibility=compatibility, environment_preflight_passed=passed, opt_in_test_environment_to_enable_after_preflight={"Z_SCOPE_TEST_LLVM": "1"}, test_execution_count=0, benchmark_execution_count=0, formal_acceptance=False, source_sha256={str(p.relative_to(ROOT)): sha(p) for p in (Path(__file__), ROOT / "zscope/retrieval/llvm_toolchain.py")})
(OUT / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=receipt["checked_at"], preflight_passed=passed, missing_tools=[k for k, v in paths.items() if not v], llvm_svf_version_compatibility=compatibility, ldd_no_missing={k: v["no_missing_shared_libraries"] for k, v in results.items()}, tests_executed=0)))
raise SystemExit(0 if passed else 1)
