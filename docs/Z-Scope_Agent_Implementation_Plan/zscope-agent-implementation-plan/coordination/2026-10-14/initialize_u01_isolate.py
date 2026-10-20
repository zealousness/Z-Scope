"""Create one new owned isolate from the immutable source-content baseline."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4].resolve()
TARGET = ROOT / ".coordination/20261014/workspaces/u01-config"
SOURCE = ROOT / ".coordination/20261014/snapshot"

if TARGET.exists():
    raise SystemExit("u01 isolate exists; inspect rather than overwrite")
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
for item in baseline["files"]:
    src = (SOURCE / item["path"]).resolve()
    dst = (TARGET / item["path"]).resolve()
    if not src.is_relative_to(SOURCE.resolve()) or not dst.is_relative_to(TARGET.resolve()):
        raise SystemExit("baseline path outside owned source/target")
    if hashlib.sha256(src.read_bytes()).hexdigest() != item["sha256"]:
        raise SystemExit(f"snapshot differs from baseline: {item['path']}")
TARGET.mkdir(parents=True)
for item in baseline["files"]:
    src, dst = SOURCE / item["path"], TARGET / item["path"]
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
print(json.dumps({"path": str(TARGET), "files": len(baseline["files"]),
                  "source_manifest": baseline["source_manifest_sha256"]}))
