#!/usr/bin/env python3
"""Build a truth-bearing post-score trace without modifying scan artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Sequence

from zscope.benchmarking.postscore_trace import (
    build_postscore_decision_trace,
    write_postscore_decision_trace,
)


def _load(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--snapshot-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = build_postscore_decision_trace(
        report=_load(args.report),
        truth=_load(args.truth),
        score_views=_load(args.score),
        snapshot_dir=args.snapshot_dir,
    )
    write_postscore_decision_trace(args.output, result)
    print(json.dumps(result["summary"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
