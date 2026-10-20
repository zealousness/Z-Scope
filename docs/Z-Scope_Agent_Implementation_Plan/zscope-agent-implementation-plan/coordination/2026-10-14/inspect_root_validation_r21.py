"""Observe the current Root retry process tree without exposing argv or env."""
from pathlib import Path
import datetime as dt
import json
import os
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
label = "coordinator-r21-verified-environment-20261015"
processes = {}
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit() or int(entry.name) == os.getpid():
        continue
    try:
        raw = (entry / "cmdline").read_bytes().decode("utf-8", errors="replace")
        if "inspect_root_validation_r21.py" in raw:
            continue
        status = dict(line.split(":", 1) for line in (entry / "status").read_text().splitlines() if ":" in line)
        processes[int(entry.name)] = {"parent": int(status["PPid"]), "raw": raw, "state": status["State"].strip(), "exe": (entry / "comm").read_text().strip(), "wchan": (entry / "wchan").read_text().strip()}
    except (OSError, ValueError, KeyError):
        continue
selected = {pid for pid, row in processes.items() if label in row["raw"] and ("verify_current_root_r21.py" in row["raw"] or "verify_joint_retry_with_clock_r21.py" in row["raw"])}
while True:
    children = {pid for pid, row in processes.items() if row["parent"] in selected}
    if children <= selected:
        break
    selected |= children
safe = [{"pid": pid, "parent": processes[pid]["parent"], "executable": processes[pid]["exe"], "state": processes[pid]["state"], "wait_channel": processes[pid]["wchan"]} for pid in sorted(selected)]
at = dt.datetime.now(dt.timezone.utc).isoformat()
out = ROOT / "artifacts" / label
receipt = {"at": at, "label": label, "processes": safe, "scope": "Current coordinator verification descendants only; no command arguments/environment or unrelated worker state exposed"}
if out.is_dir():
    target = out / ("process-observation-" + at.replace(":", "").replace("+", "_") + ".json")
    target.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(receipt), flush=True)
