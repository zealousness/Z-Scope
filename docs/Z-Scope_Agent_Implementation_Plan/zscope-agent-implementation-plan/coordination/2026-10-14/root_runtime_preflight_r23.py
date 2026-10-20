"""Linux tool and filesystem prerequisites without diagnostic process inspection."""
from pathlib import Path
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

def inspect_test_slot():
    marker = os.environ.get("ZSCOPE_COORDINATOR_TEST_SLOT", "")
    pieces = marker.split(":")
    assert len(pieces) == 2 and pieces[0].isdigit() and int(pieces[0]) > 0 and pieces[1] in {"0", "1"}, "Run through exactly one outer test_slot.py"
    lock_path = Path("/tmp/zscope-coordination-20261014-test-slots") / (pieces[1] + ".lock")
    with lock_path.open("r") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            held = True
        else:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            raise AssertionError("Declared outer test slot is not actually held")
    return {"token": marker, "slot": int(pieces[1]), "lock_path": str(lock_path), "exclusive_lock_already_held": held, "process_inspection": False}

def inspect_root_runtime(*, require_slot=False):
    assert sys.platform == "linux"
    names = ("clang", "clang++", "gcc", "cmake", "clangd", "node", "findmnt")
    tools = {name: shutil.which(name) for name in names}
    assert all(tools.values()), "Required Linux login PATH tools are missing"
    native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
    native_sha = hashlib.sha256(native.read_bytes()).hexdigest()
    assert native_sha == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
    versions = {}
    for name in ("clang", "clang++", "clangd"):
        result = subprocess.run([tools[name], "--version"], capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stdout.strip()
        versions[name] = result.stdout.splitlines()[0]
    dependencies = subprocess.run(["ldd", str(native)], capture_output=True, text=True, timeout=10)
    assert dependencies.returncode == 0 and "not found" not in dependencies.stdout + dependencies.stderr
    mount = subprocess.run([tools["findmnt"], "--json", "--output", "TARGET,FSTYPE", "--target", "/tmp"], capture_output=True, text=True, timeout=10)
    assert mount.returncode == 0
    filesystem = json.loads(mount.stdout)["filesystems"][0]
    assert filesystem["fstype"] == "ext4"
    with tempfile.TemporaryFile(dir="/tmp") as temporary:
        temporary.write(b"default fd capture filesystem prerequisite")
        temporary.flush()
        temporary.truncate(0)
        assert os.fstat(temporary.fileno()).st_size == 0
    slot = inspect_test_slot() if require_slot else None
    return {"platform": sys.platform, "python": sys.executable, "uid": os.getuid(), "tools": tools, "versions": versions, "native_sha256": native_sha, "native_ldd_has_no_missing_dependencies": True, "temporary_mount": [filesystem["target"], filesystem["fstype"]], "ext4_unlinked_fd_truncate": True, "passed": True, "environment_modified": False, "wsl_process_inspection": False, "formal_or_portable_acceptance": False, "coordinator_test_slot": slot}
