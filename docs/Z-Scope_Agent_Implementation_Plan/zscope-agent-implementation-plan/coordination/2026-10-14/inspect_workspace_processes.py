"""Read-only Linux process inventory, without printing arguments or environment."""
from pathlib import Path
import json
import os
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
name = sys.argv[1]
assert name in {"mcp-findings-r12", "scan-session-r12", "scan-checkpoint-r17", "checkpoint-zcode-r18", "contract-validation-r12", "astra-queue-ux-r12", "astra-job-projection-r15", "astra-instance-ui-r18", "doc-identity-r18", "coordinator-lightweight-r18", "validation-context-r18", "config-stop-at-r18", "native-hot-cache-r19", "job-cli-window-r20", "astra-first-cause-r20"}
workspace = str(ROOT / ".coordination/20261014/workspaces" / name)
rows = []
def origin(pid):
    for _ in range(12):
        try:
            process=Path("/proc")/str(pid)
            args=(process/"cmdline").read_bytes().decode("utf-8",errors="replace")
            if any(name in args for name in ("verify_delivery_r12.py","probe_frozen_r12.py","verify_shared_r13.py")):
                return "coordinator_verification"
            data=dict(line.split(":",1) for line in (process/"status").read_text().splitlines() if ":" in line)
            pid=int(data["PPid"])
            if pid<=1:
                break
        except (OSError,ValueError,KeyError):
            break
    return "producer_or_unclassified"
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit() or int(entry.name) == os.getpid():
        continue
    try:
        args = [value.decode("utf-8",errors="replace") for value in (entry / "cmdline").read_bytes().split(b"\0") if value]
        cwd = str((entry / "cwd").readlink())
        if cwd != workspace and not any(workspace in arg for arg in args):
            continue
        # Parent shells may contain this inspection command; omit them.
        if any("inspect_workspace_processes.py" in arg for arg in args):
            continue
        data = dict(line.split(":",1) for line in (entry / "status").read_text().splitlines() if ":" in line)
        kind = next((value for value in ("pytest","mypy","compileall","test_slot.py","zscope.orchestration.jobs") if any(value in arg for arg in args)), "other")
        wait_channel=(entry/"wchan").read_text().strip()
        rows.append({"pid":int(entry.name),"parent_pid":int(data["PPid"]),"executable":Path(args[0]).name if args else "", "kind":kind,"origin":origin(int(entry.name)),"state":data["State"].strip(),"wait_channel":wait_channel,"queued_slot":any(Path(arg).name=="test_slot.py" for arg in args) and wait_channel=="hrtimer_nanosleep"})
    except (OSError, ValueError, KeyError):
        continue
print(json.dumps({"workspace":name,"processes":rows},ensure_ascii=False))
