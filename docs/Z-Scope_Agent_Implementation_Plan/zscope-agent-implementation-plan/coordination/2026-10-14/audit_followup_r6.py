"""Read-only ownership and root-baseline audit for the isolated R6 tasks."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]


def digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def audit(workspace_name: str) -> dict:
    receipt = HERE / "followups-r6" / f"{workspace_name}-baseline.json"
    incremental_receipt = HERE / "followups-r6" / f"{workspace_name}-review-baseline.json"
    if incremental_receipt.exists():
        receipt = incremental_receipt
    baseline = json.loads(receipt.read_text(encoding="utf-8"))
    task = baseline["task"]
    workspace = ROOT / ".coordination/20261014/workspaces" / workspace_name
    owns = list(task["owns"])
    extension_path = HERE / "followups-r6" / f"{workspace_name}-ownership-extension.json"
    if extension_path.exists():
        extension = json.loads(extension_path.read_text(encoding="utf-8"))
        assert Path(extension["workspace"].replace("\\", "/")).name == workspace_name
        owns.extend(extension["added_owned_paths"])
    files = {row["path"]: row["sha256"] for row in baseline["files"]}
    dependencies_path = HERE / "followups-r6" / f"{workspace_name}-dependencies.json"
    dependencies = []
    if dependencies_path.exists():
        dependencies = json.loads(dependencies_path.read_text(encoding="utf-8"))["files"]
        for row in dependencies:
            # Vendor license inputs were omitted by the original inventory.
            # They are coordinator-supplied immutable dependencies, even under
            # Astra's broad static/** ownership pattern.
            assert not any(fnmatch.fnmatchcase(row["path"], pattern) for pattern in owns) or (
                row["path"].startswith("zscope/web/static/vendor/")
                and row["path"].endswith(".LICENSE") and row["path"] not in files)
            assert row.get("previous_sha256") == files.get(row["path"])
            files[row["path"]] = row["sha256"]

    def owned(name: str) -> bool:
        return name not in {row["path"] for row in dependencies} and any(
            fnmatch.fnmatchcase(name, pattern) for pattern in owns)

    changes = []
    for name, before in files.items():
        after = digest(workspace / name)
        if after != before:
            changes.append({"path": name, "before": before, "after": after,
                            "owned": owned(name), "kind": "changed"})
    # Runtime evidence is permitted, but a new executable/source outside ownership is not.
    excluded = {"artifacts", "__pycache__", ".pytest_cache", ".mypy_cache", ".git"}
    deliveries = {"DELIVERY.md"}
    if workspace_name == "astra-config-r6":
        deliveries.add("DELIVERY-PHASE2.md")  # Explicitly authorized phase-two receipt.
        deliveries.add("DELIVERY-PHASE3.md")
    if workspace_name == "s08-session-r6":
        deliveries.update({"DELIVERY/DELIVERY.md", "DELIVERY/junit-guard-probes.xml",
                           "DELIVERY/junit-regression.xml", "DELIVERY/junit-session-scheduler.xml",
                           "DELIVERY/junit-r2-full.xml", "DELIVERY/junit-r2-probes.xml"})
    for directory, dirs, names in os.walk(workspace):
        dirs[:] = sorted(name for name in dirs if name not in excluded)
        for filename in sorted(names):
            path = Path(directory) / filename
            name = path.relative_to(workspace).as_posix()
            authorized_s08_receipt = workspace_name == "s08-session-r6" and name.startswith("DELIVERY/") and path.suffix in {".md", ".xml"}
            if name not in files and name not in deliveries and not authorized_s08_receipt:
                changes.append({"path": name, "before": None, "after": digest(path),
                                "owned": owned(name), "kind": "added"})
    root_drift = []
    for row in changes:
        if row["owned"]:
            current = digest(ROOT / row["path"])
            if current != row["before"]:
                root_drift.append({"path": row["path"], "baseline": row["before"],
                                   "current": current})
    return {
        "schema": "zscope.coordination.ownership-audit.v1",
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "task": task["id"], "workspace": str(workspace),
        "baseline": str(receipt), "baseline_file_count": len(files),
        "coordinator_readonly_dependencies": dependencies,
        "delivery_exists": any((workspace / name).is_file() for name in deliveries if name.endswith(".md")),
        "changes": changes,
        "nonowned_changes": [row for row in changes if not row["owned"]],
        "root_owned_drift": root_drift,
        "safe_to_review": not any(not row["owned"] for row in changes) and not root_drift,
        "note": "A live-worker snapshot is provisional and is not an acceptance receipt.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("workspace")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit(args.workspace)
    serialized = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    print(serialized, end="")
