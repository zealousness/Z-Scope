#!/usr/bin/env python3
"""Generate one post-score Range gap ledger; never invoke the scanner or model."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zscope.benchmarking.gap_analysis import analyze_range_gap_files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--adjudication", type=Path)
    parser.add_argument("--usage-events", type=Path)
    parser.add_argument("--replay-bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze_range_gap_files(
        report_path=args.report.resolve(),
        score_path=args.score.resolve(),
        truth_path=args.truth.resolve(),
        adjudication_path=args.adjudication.resolve() if args.adjudication else None,
        usage_events_path=args.usage_events.resolve() if args.usage_events else None,
        replay_bundle_path=args.replay_bundle.resolve() if args.replay_bundle else None,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps({"output": str(args.output), "cause_counts": result["cause_counts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
