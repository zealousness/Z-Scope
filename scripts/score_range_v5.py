#!/usr/bin/env python3
"""Score one Benchmark v5 report or aggregate five formal v4 trials."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.benchmark_v5 import (
    BenchmarkV5Error,
    aggregate_benchmark_v5,
    score_benchmark_v5,
)


def _load(path: Path) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise BenchmarkV5Error(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate,
        parse_constant=lambda value: (_ for _ in ()).throw(
            BenchmarkV5Error(f"non-finite JSON number: {value}")
        ),
    )


def _write(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(value), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _score(args: argparse.Namespace) -> int:
    report = _load(args.report)
    truth = _load(args.truth)
    pairs = _load(args.pair_results) if args.pair_results else None
    if not isinstance(report, dict) or not isinstance(truth, dict):
        raise BenchmarkV5Error("report and truth must be JSON objects")
    if pairs is not None and not isinstance(pairs, dict):
        raise BenchmarkV5Error("pair results must be a JSON object")
    result = score_benchmark_v5(report, truth, pair_results=pairs, formal=args.formal)
    _write(args.output, result)
    return 0


def _aggregate(args: argparse.Namespace) -> int:
    trials = [_load(path) for path in args.trial]
    attestation = _load(args.e0_attestation)
    if not all(isinstance(value, dict) for value in trials) or not isinstance(attestation, dict):
        raise BenchmarkV5Error("trials and E0 attestation must be JSON objects")
    result = aggregate_benchmark_v5(
        trials,
        e0_attestation=attestation,
        trusted_workflow_run_id=args.workflow_run_id,
        trusted_head_sha=args.head_sha,
        baseline_actionable_precision=args.baseline_actionable_precision,
    )
    _write(args.output, result)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    score = subparsers.add_parser("score")
    score.add_argument("--report", required=True, type=Path)
    score.add_argument("--truth", required=True, type=Path)
    score.add_argument("--pair-results", type=Path)
    score.add_argument("--formal", action="store_true")
    score.add_argument("--output", required=True, type=Path)
    score.set_defaults(handler=_score)
    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--trial", action="append", required=True, type=Path)
    aggregate.add_argument("--e0-attestation", required=True, type=Path)
    aggregate.add_argument("--workflow-run-id", required=True)
    aggregate.add_argument("--head-sha", required=True)
    aggregate.add_argument("--baseline-actionable-precision", required=True, type=float)
    aggregate.add_argument("--output", required=True, type=Path)
    aggregate.set_defaults(handler=_aggregate)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except (BenchmarkV5Error, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"Benchmark v5 failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
