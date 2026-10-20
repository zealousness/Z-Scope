"""Run the unchanged full launcher while observing clocks, never adjusting them."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
import threading
import time

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
label = sys.argv[1]
assert label.startswith("coordinator-r19-")
out = ROOT / "artifacts" / label
assert not out.exists()
launcher = HERE / "verify_current_root_r19.py"
before = hashlib.sha256(launcher.read_bytes()).hexdigest()
stop = threading.Event()
samples = []
def sample():
    previous = None
    while not stop.is_set():
        wall, mono = time.time(), time.monotonic()
        offset = wall - mono
        if previous is None or abs(offset - previous) > .05:
            samples.append({"wall_epoch": wall, "monotonic": mono, "wall_minus_monotonic_delta": None if previous is None else offset - previous})
        previous = offset
        stop.wait(.05)
thread = threading.Thread(target=sample, daemon=True)
thread.start()
try:
    result = subprocess.run([sys.executable, str(launcher), label])
finally:
    stop.set()
    thread.join(timeout=2)
    if out.exists():
        (out / "clock-observations.json").write_text(json.dumps({"finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "clock_adjusted": False, "test_or_timeout_modified": False, "launcher_before": before, "launcher_after": hashlib.sha256(launcher.read_bytes()).hexdigest(), "samples": samples}, indent=2) + "\n", encoding="utf-8", newline="\n")
assert before == hashlib.sha256(launcher.read_bytes()).hexdigest()
sys.exit(result.returncode)
