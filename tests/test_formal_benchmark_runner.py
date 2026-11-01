from __future__ import annotations

from zscope.benchmarking.runner import (
    C_GATES,
    _aggregate_arm_a_binding,
    _aggregate_range_gate_metrics,
    _gate_c,
    _gate_c_sealed,
    _gate_metrics,
    _performance_outliers,
)


def _summary(run: int, wall: float, scan: float) -> dict:
    return {
        "run": run,
        "metrics": {
            "scan_wall_seconds": scan,
            "wall_seconds": scan,
            "end_to_end_wall_seconds": wall,
        },
        "phase_seconds": {"health": 1.0, "scan": scan, "score": 2.0, "total": wall + 3.0},
    }


def test_performance_outliers_flag_single_gross_scan_delay() -> None:
    summaries = [
        _summary(1, 708.0, 700.0),
        _summary(2, 658.0, 650.0),
        _summary(3, 4518.0, 4510.0),
        _summary(4, 761.0, 753.0),
        _summary(5, 770.0, 762.0),
    ]

    outliers = _performance_outliers(summaries)

    assert {item["metric"] for item in outliers if item["run"] == 3} == {
        "scan_wall_seconds",
        "end_to_end_wall_seconds",
        "phase_seconds.scan",
        "phase_seconds.total",
    }
    assert all(item["run"] == 3 for item in outliers)


def test_performance_outliers_ignore_normal_variance() -> None:
    summaries = [
        _summary(1, 700.0, 690.0),
        _summary(2, 760.0, 750.0),
        _summary(3, 800.0, 790.0),
        _summary(4, 720.0, 710.0),
        _summary(5, 780.0, 770.0),
    ]

    assert _performance_outliers(summaries) == []


def _passing_run_score() -> dict:
    return {
        "tokens": 1_000_000,
        "provider_usage_coverage": 1.0,
        "explicit_attribution_coverage": 1.0,
        "telemetry_complete_rate": 1.0,
        "protocol_anomaly_count": 0,
        "queue_empty": True,
        "token_conservation_passed": True,
        "usage_accounting": {"complete": True, "source": "response_usage_spans"},
        "rule_qualification_telemetry_present": True,
        "report_views": {"default": {"attribution": {"explicit_coverage": 1.0}}},
    }


def _passing_fast_run_score() -> dict:
    return {
        **_passing_run_score(),
        "confirmed_precision": 0.9,
        "confirmed_count": 1,
        "fast_static_active": 1.0,
        "fast_static_formal_qualified": 1.0,
        "fast_static_duplicate_local_executions": 0,
        "fast_static_unresolved_terminal_count": 0,
        "fast_static_backend_degraded": 0.0,
    }


def test_cpp_gate_evaluates_balanced_twelve_million_cost_expectation() -> None:
    score = _passing_run_score()
    score["tokens"] = 12_000_001

    assert _gate_c(score) == ["tokens=12000001.0 > 12000000.0"]


def test_cpp_sealed_gate_is_separate_from_numeric_release_gate() -> None:
    score = _passing_run_score()

    assert _gate_c(score) == []
    failures = _gate_c_sealed(score)
    assert "missing numeric metric: sealed_confirmed_recall_delta_pp" in failures
    assert "missing numeric metric: shadow_precision_at_25" in failures
    assert "missing numeric metric: silent_rejection_without_proof_count" in failures


def test_cpp_gate_rejects_default_enabled_unqualified_rules() -> None:
    score = _passing_run_score()
    score["default_enabled_unqualified_rule_count"] = 1

    assert _gate_c(score) == ["default-enabled deterministic rules are not externally qualified"]


def test_fast_gate_requires_nonempty_confirmed_view_at_ninety_percent_precision() -> None:
    score = _passing_fast_run_score()

    assert _gate_c(score, scan_depth="fast") == []

    score["confirmed_count"] = 0
    score["confirmed_precision"] = 0.0
    failures = _gate_c(score, scan_depth="fast")
    assert "confirmed_precision=0.0 < 0.9" in failures
    assert "confirmed_count=0.0 < 1.0" in failures


def test_fast_gate_fails_closed_on_static_coverage_or_terminal_gaps() -> None:
    score = _passing_fast_run_score()
    score["fast_static_formal_qualified"] = 0.0
    score["fast_static_unresolved_terminal_count"] = 1
    score["fast_static_backend_degraded"] = 1.0

    failures = _gate_c(score, scan_depth="fast")

    assert "fast_static_formal_qualified=0.0 < 1.0" in failures
    assert "fast_static_unresolved_terminal_count=1.0 > 0.0" in failures
    assert "fast_static_backend_degraded=1.0 > 0.0" in failures


def test_range_aggregate_executes_all_locked_policy_gates() -> None:
    summaries = [
        {
            "queue_empty": True,
            "metrics": {
                "confirmed_tp": 112,
                "tokens": 9_000_000 + run,
                "confirmed_recall": 0.82,
                "confirmed_precision": 0.91 + run / 1000,
                "confirmed_count": 120,
                "fast_static_active": 1.0,
                "fast_static_formal_qualified": 1.0,
                "fast_static_duplicate_local_executions": 0,
                "fast_static_unresolved_terminal_count": 0,
                "fast_static_backend_degraded": 0.0,
                "actionable_fdr_delta_vs_arm_a_pp": 0.5,
                "provider_usage_coverage": 1.0,
                "explicit_attribution_coverage": 1.0,
                "token_conservation_passed": True,
                "telemetry_complete_rate": 1.0,
                "protocol_anomaly_count": 0,
                "true_positive_truth_ids": ["T1", "T2"],
            },
        }
        for run in range(5)
    ]

    actuals = _aggregate_range_gate_metrics(summaries)

    assert _gate_metrics(actuals, C_GATES) == []
    assert actuals["median_confirmed_tp"] == 112
    assert actuals["true_positive_jaccard"] == 1.0
    assert actuals["queue_drained_rate"] == 1.0
    assert actuals["telemetry_complete_rate"] == 1.0
    assert actuals["confirmed_precision"] == 0.91
    assert actuals["fast_static_formal_qualified"] == 1.0


def test_range_aggregate_fails_closed_without_arm_a_delta() -> None:
    summaries = [
        {
            "queue_empty": True,
            "metrics": {
                "confirmed_tp": 112,
                "tokens": 9_000_000,
                "confirmed_recall": 0.82,
                "provider_usage_coverage": 1.0,
                "explicit_attribution_coverage": 1.0,
                "token_conservation_passed": True,
                "telemetry_complete_rate": 1.0,
                "protocol_anomaly_count": 0,
                "true_positive_truth_ids": ["T1"],
            },
        }
        for _ in range(5)
    ]

    failures = _gate_metrics(_aggregate_range_gate_metrics(summaries), C_GATES)

    assert any("actionable_fdr_delta_vs_arm_a_pp" in failure for failure in failures)


def test_formal_arm_a_binding_requires_one_frozen_baseline_and_replay_bundle() -> None:
    binding = {
        "frozen": True,
        "arm": "A",
        "replay_bundle_sha256": "a" * 64,
        "baseline_sha256": "b" * 64,
    }
    summaries = [
        {
            "metrics": {"validator_arm_a_baseline": binding},
            "validator_replay_bundle": {"bundle_sha256": "a" * 64},
        }
        for _ in range(5)
    ]

    assert _aggregate_arm_a_binding(summaries)["passed"] is True
    summaries[0]["metrics"]["validator_arm_a_baseline"] = {
        **binding,
        "baseline_sha256": "c" * 64,
    }
    assert _aggregate_arm_a_binding(summaries)["passed"] is False

    summaries = [
        {
            "metrics": {"validator_arm_a_baseline": binding},
            "validator_replay_bundle": {"bundle_sha256": "c" * 64},
        }
        for _ in range(5)
    ]
    assert _aggregate_arm_a_binding(summaries)["passed"] is False
