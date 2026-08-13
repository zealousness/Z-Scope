#!/usr/bin/env python3
"""Aggregate formal Range release runs without changing their artifacts."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import random
import statistics
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.policy import DEFAULT_BENCHMARK_POLICY


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


def _bootstrap_mean_ci(values: list[float], *, samples: int, seed: int) -> dict[str, float]:
    if not values:
        return {"confidence_level": 0.95, "lower": 0.0, "upper": 0.0}
    rng = random.Random(seed)
    draws = sorted(statistics.fmean(rng.choice(values) for _ in values) for _ in range(samples))
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
        "stdev": round(statistics.stdev(materialized), 6) if len(materialized) > 1 else 0.0,
        "minimum": round(min(materialized), 6),
        "maximum": round(max(materialized), 6),
        "bootstrap_mean_ci": _bootstrap_mean_ci(materialized, samples=samples, seed=seed),
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
    summary_paths: list[Path],
    *,
    arm_a_summary_paths: list[Path] | None = None,
    bootstrap_samples: int = 10_000,
    seed: int = 33,
) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    default_evaluations: list[dict[str, Any]] = []
    review_evaluations: list[dict[str, Any]] = []

    for summary_path in summary_paths:
        summary = _load_json(summary_path)
        default_eval = _load_json(_artifact_path(summary_path, summary, "evaluation_default"))
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
                "provider_usage_coverage": metrics.get("provider_usage_coverage"),
                "explicit_attribution_coverage": metrics.get(
                    "explicit_attribution_coverage",
                    (default_eval.get("attribution") or {}).get("explicit_coverage"),
                ),
                "queue_drained": metrics.get("queue_drained"),
                "token_conservation_passed": metrics.get("token_conservation_passed"),
                "telemetry_complete": metrics.get("telemetry_complete"),
                "protocol_anomaly_count": metrics.get("protocol_anomaly_count"),
                "actionable_fdr": default_eval.get("actionable_false_discovery_rate"),
                "recall": default_eval.get("recall"),
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

    arm_a_evaluations: list[dict[str, Any]] = []
    for summary_path in arm_a_summary_paths or []:
        summary = _load_json(summary_path)
        arm_a_evaluations.append(
            _load_json(_artifact_path(summary_path, summary, "evaluation_default"))
        )
    trial_count_valid = len(runs) >= DEFAULT_BENCHMARK_POLICY.minimum_formal_trials
    all_runs_passed = all(
        run["benchmark_valid"]
        and run["report_completeness"] == "complete"
        and run["model_trace_valid"]
        and run["release_gate_passed"]
        for run in runs
    )

    def numeric(name: str) -> list[float]:
        return [
            float(run[name])
            for run in runs
            if isinstance(run.get(name), (int, float)) and not isinstance(run.get(name), bool)
        ]

    def bool_rate(name: str) -> float | None:
        if not runs or any(not isinstance(run.get(name), bool) for run in runs):
            return None
        return sum(run[name] is True for run in runs) / len(runs)

    fdr_values = numeric("actionable_fdr")
    baseline_fdr_values = [
        float(item["actionable_false_discovery_rate"])
        for item in arm_a_evaluations
        if isinstance(item.get("actionable_false_discovery_rate"), (int, float))
        and not isinstance(item.get("actionable_false_discovery_rate"), bool)
    ]
    recall_values = numeric("recall")
    token_values = numeric("total_tokens")
    tp_values = numeric("confirmed_tp")
    provider_values = numeric("provider_usage_coverage")
    attribution_values = numeric("explicit_attribution_coverage")
    anomaly_values = numeric("protocol_anomaly_count")
    tp_jaccard = _pairwise_jaccard(truth_sets(default_evaluations))["mean"]
    actuals: dict[str, float | None] = {
        "median_confirmed_tp": (
            statistics.median(tp_values) if len(tp_values) == len(runs) else None
        ),
        "median_tokens": (
            statistics.median(token_values) if len(token_values) == len(runs) else None
        ),
        "per_run_tokens": max(token_values) if len(token_values) == len(runs) else None,
        "actionable_fdr_delta_vs_arm_a_pp": (
            round(
                (statistics.median(fdr_values) - statistics.median(baseline_fdr_values)) * 100.0,
                8,
            )
            if len(fdr_values) == len(runs)
            and len(baseline_fdr_values) == len(arm_a_evaluations)
            and len(arm_a_evaluations) >= DEFAULT_BENCHMARK_POLICY.minimum_formal_trials
            else None
        ),
        "true_positive_jaccard": float(tp_jaccard),
        "recall_range_pp": (
            (max(recall_values) - min(recall_values)) * 100.0
            if len(recall_values) == len(runs)
            else None
        ),
        "provider_usage_coverage": (
            min(provider_values) if len(provider_values) == len(runs) else None
        ),
        "explicit_attribution_coverage": (
            min(attribution_values) if len(attribution_values) == len(runs) else None
        ),
        "queue_drained_rate": bool_rate("queue_drained"),
        "token_conservation_rate": bool_rate("token_conservation_passed"),
        "telemetry_complete_rate": bool_rate("telemetry_complete"),
        "protocol_anomaly_count": (
            sum(anomaly_values) if len(anomaly_values) == len(runs) else None
        ),
    }
    gates = {
        name: {
            "actual": actuals[name],
            "operator": operator,
            "threshold": threshold,
            "available": actuals[name] is not None,
            "passed": actuals[name] is not None
            and (
                float(actuals[name]) >= threshold
                if operator == ">="
                else float(actuals[name]) <= threshold
            ),
        }
        for name, (operator, threshold) in DEFAULT_BENCHMARK_POLICY.range_gates.items()
    }
    all_policy_gates_passed = all(gate["passed"] for gate in gates.values())
    return {
        "schema_version": "zscope.range.release-aggregate.v1",
        "benchmark_policy": DEFAULT_BENCHMARK_POLICY.as_dict(),
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
            "passed": trial_count_valid and all_runs_passed and all_policy_gates_passed,
            "trial_count_gte_5": trial_count_valid,
            "every_run_complete_valid_and_gated": all_runs_passed,
            "range_gates": gates,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summaries", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bootstrap-samples", type=int, default=10_000)
    parser.add_argument(
        "--arm-a-summary",
        action="append",
        default=[],
        type=Path,
        help="Frozen forced-final Arm-A summary; repeat for all five paired trials",
    )
    args = parser.parse_args()
    if args.bootstrap_samples <= 0:
        parser.error("--bootstrap-samples must be positive")
    result = aggregate(
        args.summaries,
        arm_a_summary_paths=args.arm_a_summary,
        bootstrap_samples=args.bootstrap_samples,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result["release_readiness"], ensure_ascii=False))
    return 0 if result["release_readiness"]["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
