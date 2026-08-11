from __future__ import annotations

from scripts.run_formal_benchmark import _gate_c, _gate_c_sealed, _performance_outliers


def _summary(run: int, wall: float, scan: float) -> dict:
    return {
        "run": run,
        "metrics": {"wall_seconds": wall},
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
        "wall_seconds",
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


def test_cpp_gate_applies_raw_fp_limit_to_with_review_view() -> None:
    score = {
        "confirmed_tp": 90,
        "precision": 98,
        "with_review_tp": 134,
        "with_review_raw_fp": 101,
        "needs_review": 120,
        "tokens": 1_000_000,
        "wall_seconds": 2_000,
        "sealed_confirmed_recall_delta_pp": 0,
        "sealed_precision_delta_pp": 0,
    }

    assert _gate_c(score) == ["with_review_raw_fp=101.0 > 100.0"]


def test_cpp_sealed_gate_is_separate_from_numeric_release_gate() -> None:
    score = {
        "confirmed_tp": 90,
        "precision": 98,
        "with_review_tp": 134,
        "with_review_raw_fp": 80,
        "needs_review": 120,
        "tokens": 1_000_000,
        "wall_seconds": 2_000,
    }

    assert _gate_c(score) == []
    assert _gate_c_sealed(score) == [
        "missing numeric metric: sealed_confirmed_recall_delta_pp",
        "missing numeric metric: sealed_precision_delta_pp",
    ]
