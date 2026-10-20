"""Restore only the inactive, previously registered bundled DSH route."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import ctypes

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
state = ROOT / ".coordination/20261014/bridge-dsh-native"
saved = json.loads((state / "state.json").read_text(encoding="utf-8"))
assert all(r["status"] in {"completed", "failed", "cancelled"} for r in saved["tasks"])
def alive(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if handle:
        code = ctypes.c_ulong()
        try:
            assert kernel.GetExitCodeProcess(handle, ctypes.byref(code))
            return code.value == 259  # STILL_ACTIVE; retained exited objects are not owners.
        finally:
            kernel.CloseHandle(handle)
    return False
pids = json.loads((state / "pids.json").read_text(encoding="utf-8"))
assert pids and all(not alive(r["owner_pid"]) and not alive(r["pid"]) for r in pids.values())
assert hashlib.sha256(Path(r"C:\Users\10273\AppData\Local\Programs\DeepSeek Harness\resources\runtime\cli\bin\dsh.cmd").read_bytes()).hexdigest() == "c6c38be7f9f66a7bfb96d5ac9490618f9713df5ffb552cb7e66b831affb20ab9"
assert hashlib.sha256(Path(r"C:\Users\10273\.dsh\profiles\acp\cordis.patch.yml").read_bytes()).hexdigest() == "23259e019f6a7293ebb429654d7cc223414d3651d5be542968a81fc6265fc38b"
route = HERE / "dsh-native"
assert (route / "bridge-queue").is_dir()
pending = [p.name for p in (route / "bridge-queue").glob("*.request.json") if not p.with_suffix(".consumed").exists()]
assert not pending, pending
out = route / "r18-owner-stdout.jsonl"
err = route / "r18-owner-stderr.log"
receipt = route / "r18-owner-restoration.json"
assert not out.exists() and not err.exists() and not receipt.exists()
process = subprocess.Popen([
    r"C:\Users\10273\AppData\Roaming\uv\tools\agent-bridge\Scripts\python.exe",
    str(HERE / "bridge_mcp_client.py"), "--dsh-native",
], cwd=ROOT, env=dict(os.environ), stdin=subprocess.DEVNULL,
   stdout=out.open("w", encoding="utf-8"), stderr=err.open("w", encoding="utf-8"),
   creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS)
proof = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "pid": process.pid,
         "restored_home": str(state), "all_old_tasks_terminal": True, "prior_owner_and_worker_absent": True,
         "normal_bridge_80748_restarted": False, "external_configuration_changed": False,
         "credentials_copied": False, "route_changed": False,
         "scope": "Existing dedicated DSH route only; no competing owner or task. Public list_agents must permit dispatch before any work."}
receipt.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
identity = "r18-public-agents"
target = route / "bridge-queue" / ("080-" + identity + ".request.json")
assert not target.exists()
target.write_text(json.dumps({"id": identity, "tool": "list_agents", "arguments": {}}) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(proof))
