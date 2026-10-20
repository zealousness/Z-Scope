"""Intake only independently accepted, stable, owned bytes; preserve old bytes."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil

from audit_followup_r6 import audit, ROOT


def digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("workspace")
    parser.add_argument("acceptance", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    receipt = json.loads(args.acceptance.read_text(encoding="utf-8"))
    assert receipt["independent_acceptance_passed"] is True
    assert receipt["source_unchanged"] is True
    review = audit(args.workspace)
    assert review["safe_to_review"] and review["delivery_exists"], review
    workspace = Path(review["workspace"])
    source_root = Path(receipt["source_snapshot"]) if receipt.get("source_snapshot") else workspace
    if source_root != workspace:
        assert source_root.resolve().is_relative_to((ROOT / "artifacts").resolve())
    for row in review["changes"]:
        assert row["owned"] and row["after"] is not None, row
        assert (workspace / row["path"]).resolve().is_relative_to(workspace.resolve())
        assert receipt["after_hashes"].get(row["path"]) == row["after"], row
        assert digest(source_root / row["path"]) == row["after"], row
        assert digest(ROOT / row["path"]) == row["before"], row
    args.output.mkdir(exist_ok=False)
    (args.output / "ownership-before.json").write_text(
        json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    for row in review["changes"]:
        source, target = source_root / row["path"], ROOT / row["path"]
        assert digest(source) == row["after"], row
        assert digest(target) == row["before"], row
        if target.exists():
            backup = args.output / "before" / row["path"]
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(target, backup)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        assert digest(target) == row["after"], row
    result = {
        "schema": "zscope.coordination.owned-intake.v1", "task": review["task"],
        "accepted_receipt": str(args.acceptance.resolve()),
        "intake_source": str(source_root.resolve()),
        "integrated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "files": review["changes"], "all_bytes_verified": True,
        "independent_acceptance": True, "joint_verification": "pending on these bytes",
        "whole_package_complete": False,
    }
    (args.output / "receipt.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                              encoding="utf-8", newline="\n")
    print(json.dumps({"task": review["task"], "files": len(review["changes"]),
                      "integrated_at": result["integrated_at"], "receipt": str(args.output / "receipt.json")}))
