"""Read-only Linux environment receipt; never print credential values."""
from pathlib import Path
import datetime as dt
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
tools = {name: shutil.which(name) for name in ("cmake", "gcc", "clang", "clangd", "gclang", "get-bc", "llvm-link", "llvm-nm", "wpa", "saber")}
libraries = {}
for name in ("wpa", "saber"):
    if tools[name]:
        result = subprocess.run(["ldd", tools[name]], capture_output=True, text=True)
        libraries[name] = {"returncode": result.returncode, "missing": [line.strip() for line in result.stdout.splitlines() if "not found" in line]}
distribution = importlib.metadata.distribution("zscope")
direct = distribution.read_text("direct_url.json")
receipt = {
    "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "cwd": str(Path.cwd()),
    "python": sys.executable, "python_version": platform.python_version(), "pytest_version": importlib.metadata.version("pytest"),
    "distribution_direct_url": json.loads(direct) if direct else None,
    "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
    "tool_paths": tools, "ldd": libraries, "native_path": str(native),
    "native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
    "llm_environment_present": {name: bool(os.environ.get(name)) for name in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY")},
    "ijson_installed": importlib.util.find_spec("ijson") is not None,
    "scope": "Read-only development runtime inventory, not formal benchmark/toolchain or real-project scan acceptance.",
}
target = ROOT / ("artifacts/coordinator-r7-runtime-login-20261014.json" if "--login" in sys.argv else
                 "artifacts/coordinator-r7-runtime-20261014.json")
assert not target.exists()
target.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"receipt": str(target), "python":receipt["python_version"], "tools_available":sum(bool(value) for value in tools.values()),
                  "missing_libraries":libraries, "llm_environment_present":receipt["llm_environment_present"], "ijson":receipt["ijson_installed"]}))
