"""Format only coordinator-migrated readonly tests, then bind their final bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
workspace = ROOT / ".coordination/20261014/workspaces/config-stop-at-r18"
path = HERE / "followups-r12/config-stop-at-r18-dependencies.json"
data = json.loads(path.read_text(encoding="utf-8"))
assert not data["validated"] and data["coordinator_authored"]
command = [sys.executable, str(HERE / "test_slot.py"), "--workspace", str(workspace), "--", sys.executable, "-m", "black", *[r["path"] for r in data["files"]]]
out = ROOT / "artifacts/coordinator-stop-readonly-tests-r19-migration-20261015"
with (out / "format.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
assert result.returncode == 0
for row in data["files"]:
    row["unformatted_sha256"] = row["sha256"]
    row["sha256"] = hashlib.sha256((workspace / row["path"]).read_bytes()).hexdigest()
data["formatted_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
(out / "migration.json").write_bytes(path.read_bytes())
print(json.dumps({"returncode": 0, "coordinator_readonly_dependency_files": data["files"], "full_validation_pending": True}), flush=True)
