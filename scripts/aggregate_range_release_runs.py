#!/usr/bin/env python3
"""Aggregate formal Range release runs without changing their artifacts."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import statistics
from pathlib import Path
from typing import Any, Iterable


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _bootstrap_mean_ci(
    values: list[float], *, samples: int, seed: int
) -> dict[str, float]:
    if not values:
        return {"confidence_level": 0.95, "lower": 0.0, "upper": 0.0}
    rng = random.Random(seed)
    draws = sorted(
        statistics.fmean(rng.choice(values) for _ in values) for _ in range(samples)
    )
    lower_index = max(0, int(samples * 0.025) - 1)
    upper_index = min(samples - 1, int(samples * 0.975))
    return {
        "confidence_level": 0.95,
        "lower": round(draws[lower_index], 6),
        "upper": round(draws[upper_index], 6),
    }


def _stats(values: Iterable[float], *, samples: int, seed: int) -> dict[str, Any]:
    materialized = [float(value) for value in values]
    return {
        "count": len(materialized),
        "mean": round(statistics.fmean(materialized), 6),
        "median": round(statistics.median(materialized), 6),
        "stdev": round(statistics.stdev(materialized), 6)
        if len(materialized) > 1
        else 0.0,
        "minimum": round(min(materialized), 6),
        "maximum": round(max(materialized), 6),
        "bootstrap_mean_ci": _bootstrap_mean_ci(
            materialized, samples=samples, seed=seed
        ),
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return 1.0 if not union else len(left & right) / len(union)


def _pairwise_jaccard(sets: list[set[str]]) -> dict[str, Any]:
    values = [_jaccard(left, right) for left, right in itertools.combinations(sets, 2)]
    if not values:
        values = [1.0]
    return {
        "pair_count": max(0, len(sets) * (len(sets) - 1) // 2),
        "mean": round(statistics.fmean(values), 6),
        "minimum": round(min(values), 6),
        "maximum": round(max(values), 6),
    }


def _artifact_path(summary_path: Path, summary: dict[str, Any], name: str) -> Path:
    raw = str((summary.get("artifacts") or {}).get(name) or "")
    if not raw:
        raise ValueError(f"missing artifact {name!r}: {summary_path}")
    path = Path(raw)
    if path.exists():
        return path
    sibling = summary_path.parent / path.name
    if sibling.exists():
        return sibling
    raise FileNotFoundError(path)


def aggregate(
    summary_paths: list[Path], *, bootstrap_samples: int = 10_000, seed: int = 33
) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    default_evaluations: list[dict[str, Any]] = []
    review_evaluations: list[dict[str, Any]] = []

    for summary_path in summary_paths:
        summary = _load_json(summary_path)
        default_eval = _load_json(
            _artifact_path(summary_path, summary, "evaluation_default")
        )
        review_eval = _load_json(
            _artifact_path(summary_path, summary, "evaluation_with_needs_review")
        )
        gate = summary.get("release_gate_status") or {}
        metrics = gate.get("metrics") or {}
        runs.append(
            {
                "run_id": summary.get("run_id"),
                "summary_sha256": _sha256(summary_path),
                "benchmark_valid": summary.get("benchmark_valid") is True,
                "report_completeness": summary.get("report_completeness"),
                "model_trace_valid": summary.get("model_trace_valid") is True,
                "trace_models": summary.get("trace_models") or [],
                "release_gate_passed": gate.get("passed") is True,
                "release_gate_blockers": gate.get("blockers") or [],
                "confirmed_tp": metrics.get("confirmed_tp"),
                "confirmed_raw_fp": metrics.get("confirmed_raw_fp"),
                "confirmed_raw_precision": metrics.get("confirmed_raw_precision"),
                "with_review_tp": metrics.get("with_review_tp"),
                "with_review_raw_fp": metrics.get("with_review_raw_fp"),
                "needs_review": metrics.get("needs_review"),
                "total_tokens": metrics.get("total_tokens"),
                "wall_seconds": metrics.get("wall_seconds"),
            }
        )
        default_evaluations.append(default_eval)
        review_evaluations.append(review_eval)

    metric_names = (
        "confirmed_tp",
        "confirmed_raw_fp",
        "confirmed_raw_precision",
        "with_review_tp",
        "with_review_raw_fp",
        "needs_review",
        "total_tokens",
        "wall_seconds",
    )
    metric_stats = {
        name: _stats(
            [float(run[name]) for run in runs],
            samples=bootstrap_samples,
            seed=seed + index,
        )
        for index, name in enumerate(metric_names)
    }

    def truth_sets(evaluations: list[dict[str, Any]]) -> list[set[str]]:
        return [set(map(str, item.get("true_positive_truth_ids") or [])) for item in evaluations]

    def issue_sets(evaluations: list[dict[str, Any]]) -> list[set[str]]:
        result: list[set[str]] = []
        for item in evaluations:
            records = item.get("issue_identity_records") or []
            result.append(
                {
                    str(record.get("stable_fingerprint") or record.get("identity"))
                    for record in records
                    if isinstance(record, dict)
                    and (record.get("stable_fingerprint") or record.get("identity"))
                }
            )
        return result

    trial_count_valid = len(runs) >= 5
    all_runs_passed = all(
        run["benchmark_valid"]
        and run["report_completeness"] == "complete"
        and run["model_trace_valid"]
        and run["release_gate_passed"]
        for run in runs
    )
    return {
        "schema_version": "zscope.range.release-aggregate.v1",
        "trial_count": len(runs),
        "bootstrap_samples": bootstrap_samples,
        "runs": runs,
        "metrics": metric_stats,
        "stability": {
            "confirmed_tp_jaccard": _pairwise_jaccard(truth_sets(default_evaluations)),
            "with_review_tp_jaccard": _pairwise_jaccard(truth_sets(review_evaluations)),
            "confirmed_alert_jaccard": _pairwise_jaccard(issue_sets(default_evaluations)),
            "with_review_alert_jaccard": _pairwise_jaccard(issue_sets(review_evaluations)),
        },
        "release_readiness": {
            "passed": trial_count_valid and all_runs_passed,
            "trial_count_gte_5": trial_count_valid,
            "every_run_complete_valid_and_gated": all_runs_passed,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summaries", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bootstrap-samples", type=int, default=10_000)
    args = parser.parse_args()
    if args.bootstrap_samples <= 0:
        parser.error("--bootstrap-samples must be positive")
    result = aggregate(args.summaries, bootstrap_samples=args.bootstrap_samples)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["release_readiness"], ensure_ascii=False))
    return 0 if result["release_readiness"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
