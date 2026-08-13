from __future__ import annotations

import json
from pathlib import Path

from scripts.aggregate_range_release_runs import aggregate


def _write_run(
    root: Path,
    index: int,
    *,
    gate_passed: bool = True,
    actionable_fdr: float = 0.05,
) -> Path:
    run_dir = root / f"run-{index}"
    run_dir.mkdir()
    default_eval = {
        "recall": 0.82,
        "actionable_false_discovery_rate": actionable_fdr,
        "attribution": {"explicit_coverage": 1.0},
        "true_positive_truth_ids": ["T1", "T2"],
        "issue_identity_records": [
            {"stable_fingerprint": "F1"},
            {"stable_fingerprint": "F2"},
        ],
    }
    review_eval = {
        "true_positive_truth_ids": ["T1", "T2", "T3"],
        "issue_identity_records": [
            {"stable_fingerprint": "F1"},
            {"stable_fingerprint": "F2"},
            {"stable_fingerprint": "F3"},
        ],
    }
    (run_dir / "evaluation.json").write_text(json.dumps(default_eval), encoding="utf-8")
    (run_dir / "evaluation.with_needs_review.json").write_text(
        json.dumps(review_eval), encoding="utf-8"
    )
    summary = {
        "run_id": f"run-{index}",
        "benchmark_valid": True,
        "report_completeness": "complete",
        "model_trace_valid": True,
        "trace_models": ["glm-5.1"],
        "artifacts": {
            "evaluation_default": str(run_dir / "evaluation.json"),
            "evaluation_with_needs_review": str(run_dir / "evaluation.with_needs_review.json"),
        },
        "release_gate_status": {
            "passed": gate_passed,
            "blockers": [] if gate_passed else ["tokens_lte_6m"],
            "metrics": {
                "confirmed_tp": 112,
                "confirmed_raw_fp": 1,
                "confirmed_raw_precision": 0.9884,
                "with_review_tp": 134,
                "with_review_raw_fp": 93,
                "needs_review": 141,
                "total_tokens": 9_000_000 + index,
                "wall_seconds": 2_100 + index,
                "provider_usage_coverage": 1.0,
                "explicit_attribution_coverage": 1.0,
                "queue_drained": True,
                "token_conservation_passed": True,
                "telemetry_complete": True,
                "protocol_anomaly_count": 0,
            },
        },
    }
    path = run_dir / "run_summary.json"
    path.write_text(json.dumps(summary), encoding="utf-8")
    return path


def test_aggregate_range_release_runs_requires_five_passing_trials(tmp_path: Path) -> None:
    current_root = tmp_path / "current"
    baseline_root = tmp_path / "baseline"
    current_root.mkdir()
    baseline_root.mkdir()
    summaries = [_write_run(current_root, index) for index in range(5)]
    baseline = [_write_run(baseline_root, index, actionable_fdr=0.045) for index in range(5)]
    result = aggregate(
        summaries,
        arm_a_summary_paths=baseline,
        bootstrap_samples=100,
    )

    assert result["release_readiness"]["passed"] is True
    assert result["release_readiness"]["trial_count_gte_5"] is True
    assert result["release_readiness"]["every_run_complete_valid_and_gated"] is True
    assert all(gate["passed"] for gate in result["release_readiness"]["range_gates"].values())
    assert result["metrics"]["confirmed_tp"]["minimum"] == 112
    assert result["stability"]["confirmed_tp_jaccard"]["minimum"] == 1.0
    assert result["stability"]["with_review_alert_jaccard"]["minimum"] == 1.0


def test_aggregate_range_release_runs_blocks_failed_gate(tmp_path: Path) -> None:
    current_root = tmp_path / "current"
    baseline_root = tmp_path / "baseline"
    current_root.mkdir()
    baseline_root.mkdir()
    summaries = [_write_run(current_root, index, gate_passed=index != 4) for index in range(5)]
    baseline = [_write_run(baseline_root, index) for index in range(5)]

    result = aggregate(
        summaries,
        arm_a_summary_paths=baseline,
        bootstrap_samples=50,
    )

    assert result["release_readiness"]["passed"] is False
    assert result["release_readiness"]["every_run_complete_valid_and_gated"] is False


def test_aggregate_range_release_runs_fails_closed_without_arm_a(tmp_path: Path) -> None:
    summaries = [_write_run(tmp_path, index) for index in range(5)]

    result = aggregate(summaries, bootstrap_samples=20)

    fdr_gate = result["release_readiness"]["range_gates"]["actionable_fdr_delta_vs_arm_a_pp"]
    assert fdr_gate["available"] is False
    assert result["release_readiness"]["passed"] is False
