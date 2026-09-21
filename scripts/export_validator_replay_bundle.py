#!/usr/bin/env python3
"""Export an answer-free, hash-verified validator replay bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.replay_bundle import write_validator_replay_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.report.is_file():
        parser.error(f"report does not exist: {args.report}")
    from zscope.reporting.json_io import read_report
    report = read_report(args.report)
    if not isinstance(report, dict):
        parser.error("report must be a JSON object")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    bundle = write_validator_replay_bundle(args.output, report)
    print(
        json.dumps(
            {
                "schema_version": bundle["schema_version"],
                "group_count": bundle["group_count"],
                "bundle_sha256": bundle["bundle_sha256"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
