"""Probe required compiler paths without exposing the rest of the environment."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
label = sys.argv[1]
assert label in {"direct", "login"}
out = ROOT / "artifacts/coordinator-root-tool-environment-r21-20261015"
out.mkdir(exist_ok=True)
tools = {name: shutil.which(name) for name in ("clang", "gcc", "cmake", "clangd", "node")}
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
receipt = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "launch_mode": label, "python": sys.executable, "tools": tools, "native_sha256": hashlib.sha256(native.read_bytes()).hexdigest(), "native_present": native.is_file(), "preflight_passed": all(tools.values()), "environment_changed": False, "scope": "Existing direct-vs-login execution context only, no provider/credentials/profile editing, no formal toolchain acceptance"}
if tools["clang"]:
    result = subprocess.run([tools["clang"], "--version"], capture_output=True, text=True)
    receipt["clang_version_returncode"] = result.returncode
    receipt["clang_version_first_line"] = result.stdout.splitlines()[0]
(out / (label + ".json")).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt), flush=True)
