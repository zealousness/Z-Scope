"""Import explicit new modules from a stable isolate, preserving root changes."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ALLOWED = {
    "u02-projection": ["zscope/reporting/acceptance.py", "tests/test_acceptance_projection.py"],
    "u02-disposition": ["zscope/config/acceptance_feedback.py", "tests/test_acceptance_feedback.py"],
    "s09-prep": ["scripts/agent_plan_evaluation.py", "tests/test_agent_plan_evaluation.py"],
    "s07-oracle": [
        "tests/test_scan_demand_equivalence.py",
        "tests/fixtures/scan_demand_equivalence/scenarios.json",
        "tests/fixtures/scan_demand_equivalence/stale_serialized_plan.json",
        "tests/fixtures/scan_demand_equivalence/README.md",
    ],
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("branch", choices=ALLOWED)
    args = parser.parse_args()
    workspace = ROOT / ".coordination/20261014/workspaces" / args.branch
    baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
    changed_existing = []
    for item in baseline["files"]:
        path = workspace / item["path"]
        if not path.is_file() or sha(path.read_bytes()) != item["sha256"]:
            changed_existing.append(item["path"])
    if changed_existing:
        raise RuntimeError(f"unexpected changes to inherited source: {changed_existing}")
    rows = []
    for name in ALLOWED[args.branch]:
        source, target = workspace / name, ROOT / name
        raw = source.read_bytes()
        digest = sha(raw)
        if target.exists():
            if sha(target.read_bytes()) != digest:
                raise RuntimeError(f"root file exists with different bytes: {name}")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(raw)
        if sha(source.read_bytes()) != digest:
            raise RuntimeError(f"isolate changed during intake; preserve root for review: {name}")
        rows.append({"path": name, "sha256": digest})
    receipt = {
        "at": dt.datetime.now(dt.timezone.utc).isoformat(), "branch": args.branch,
        "source_baseline": baseline["source_manifest_sha256"],
        "files": rows, "existing_source_changes": changed_existing,
        "state": "immutable_intake_snapshot_pending_independent_integration_tests_and_final_worker_receipt",
    }
    (HERE / f"intake-{args.branch}.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(receipt, ensure_ascii=False))


if __name__ == "__main__":
    main()
