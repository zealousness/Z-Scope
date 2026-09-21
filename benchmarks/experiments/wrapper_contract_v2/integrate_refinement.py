"""Hash-guarded integration after the frozen trial process has exited."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil


def sha(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    artifacts = root / "benchmark-artifacts/pool-protocol-v3"
    work = artifacts / "refinement-work"
    execution = json.loads((artifacts / "benchmark-execution.json").read_text(encoding="utf-8"))
    manifest = json.loads((work / "integration-manifest.json").read_text(encoding="utf-8"))
    errors = []
    for row in manifest:
        target = (root / row["path"]).resolve()
        candidate = (work / row["path"]).resolve()
        if not target.is_relative_to(root) or not candidate.is_relative_to(work):
            raise RuntimeError("Manifest path escapes its workspace")
        if sha(target) != row["base_sha256"]:
            errors.append("root changed: " + row["path"])
        if sha(candidate) != row["new_sha256"]:
            errors.append("refinement changed: " + row["path"])
    if errors:
        raise RuntimeError("\n".join(errors))
    if args.check_only:
        print(json.dumps({"checked_files": len(manifest), "root_and_refinement_hashes_match": True, "trial_status": execution.get("status")}))
        return
    if execution.get("status") not in {"complete", "completed", "failed"}:
        raise RuntimeError("The frozen benchmark has not exited; integration is forbidden")
    for path, expected in execution["source_start_hashes"].items():
        if sha(root / path) != expected:
            raise RuntimeError("Frozen benchmark source changed before integration: " + path)
    backup = artifacts / "before-refinement"
    if backup.exists():
        raise RuntimeError("Integration backup already exists; inspect it before retrying")
    for row in manifest:
        path = row["path"]
        if (root / path).exists():
            (backup / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(root / path, backup / path)
    # All targets are reviewed and hashed before the first product write.
    for row in manifest:
        target = root / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(work / row["path"], target)
        if sha(target) != row["new_sha256"]:
            raise RuntimeError("Integrated bytes differ: " + row["path"])
    result = {"status": "integrated", "at": datetime.now(timezone.utc).isoformat(), "files": manifest, "trial_execution_status": execution["status"], "note": "The preceding trial used the frozen pre-refinement product. Root validation is still required."}
    (artifacts / "integration-result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "integrated", "files": len(manifest)}))


if __name__ == "__main__":
    main()
