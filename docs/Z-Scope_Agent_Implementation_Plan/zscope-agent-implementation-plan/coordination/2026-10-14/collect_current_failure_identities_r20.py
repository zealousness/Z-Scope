"""Diagnostic collection identity only; never a test-passing conclusion."""
from pathlib import Path
import datetime as dt
import json
import os
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
label = "coordinator-r20-job-cli-intaken-20261015"
out = ROOT / "artifacts" / label / "collection-diagnostic"
out.mkdir(exist_ok=False)
targets = []
for path in Path("/proc").iterdir():
    if not path.name.isdigit():
        continue
    try:
        argv = [s.decode() for s in (path / "cmdline").read_bytes().split(b"\0") if s]
    except (OSError, UnicodeError):
        continue
    if argv[1:3] == ["-m", "pytest"] and any(s.endswith(label + "/results.xml") for s in argv):
        targets.append((int(path.name), argv))
assert len(targets) == 1
pid, original = targets[0]
command = [s for s in original if not s.startswith("--junitxml=")] + ["--collect-only", "-o", "cache_dir=" + str(out / "pytest-cache")]
env = os.environ.copy()
env.update(Z_SCOPE_TEST_CLANG_INDEXER="/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer", ZSCOPE_UI_MULTI_TARGET_EDITING="1", ZSCOPE_UI_PLAYWRIGHT_MODULE="/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright", ZSCOPE_UI_CHROMIUM="/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome")
started = dt.datetime.now(dt.timezone.utc).isoformat()
with (out / "collection.log").open("w", encoding="utf-8") as stream:
    result = subprocess.run([sys.executable, str(HERE / "test_slot.py"), "--workspace", str(ROOT), "--", *command], env=env, stdout=stream, stderr=subprocess.STDOUT)
text = (out / "collection.log").read_text(encoding="utf-8")
nodes = [line.strip() for line in text.splitlines() if "::" in line and line.lstrip().startswith(("tests/", "docs/"))]
receipt = {"started_at": started, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "running_pytest_pid": pid, "command": command, "returncode": result.returncode, "collection_count": len(nodes), "nodeids": nodes, "scope": "Collection identity diagnostic, no fixtures/tests executed and no passing test conclusion; separate cache directory, no capture/timeout/exclusion changes"}
(out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"returncode": result.returncode, "collected": len(nodes), "scope": receipt["scope"]}), flush=True)
