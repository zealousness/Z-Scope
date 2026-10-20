"""Required development toolchain preflight for the full Root collection."""
from pathlib import Path
import hashlib
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile


def inspect_root_runtime():
    assert sys.platform == "linux", "Root quality checks require Linux"
    names = ("clang", "clang++", "gcc", "cmake", "clangd", "node")
    tools = {name: shutil.which(name) for name in names}
    missing = [name for name, path in tools.items() if path is None]
    if missing:
        raise RuntimeError("Required Linux tools not found: " + ", ".join(missing) + "; start in the configured WSL login environment")
    native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
    native_sha = hashlib.sha256(native.read_bytes()).hexdigest()
    assert native_sha == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
    versions = {}
    for name in ("clang", "clang++", "clangd"):
        result = subprocess.run([tools[name], "--version"], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stdout.strip(), name
        versions[name] = result.stdout.splitlines()[0]
    dependencies = subprocess.run(["ldd", str(native)], capture_output=True, text=True, timeout=10)
    assert dependencies.returncode == 0 and "not found" not in dependencies.stdout + dependencies.stderr
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = line.split(" - ", 1)
        mount = left.split()[4]
        if mount == "/" or "/tmp" == mount or "/tmp".startswith(mount + "/"):
            mounts.append((len(mount), mount, right.split()[0]))
    temporary_mount = max(mounts)
    assert temporary_mount[2] == "ext4", temporary_mount
    with tempfile.TemporaryFile(dir="/tmp") as temporary:
        temporary.write(b"Root fd-capture prerequisite")
        temporary.flush()
        temporary.truncate(0)
        assert os.fstat(temporary.fileno()).st_size == 0
    return {"platform": sys.platform, "python": sys.executable, "uid": os.getuid(), "tools": tools, "versions": versions, "native_sha256": native_sha, "native_ldd_has_no_missing_dependencies": True, "temporary_mount": temporary_mount[1:], "ext4_unlinked_fd_truncate": True, "passed": True, "environment_modified": False, "formal_or_portable_acceptance": False}


if __name__ == "__main__":
    target = Path(sys.argv[1])
    assert not target.exists()
    try:
        proof = inspect_root_runtime()
    except (AssertionError, RuntimeError) as exc:
        proof = {"passed": False, "error": str(exc), "tools": {n: shutil.which(n) for n in ("clang", "clang++", "gcc", "cmake", "clangd", "node")}, "environment_modified": False}
    proof["captured_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(proof), flush=True)
    sys.exit(0 if proof["passed"] else 2)
