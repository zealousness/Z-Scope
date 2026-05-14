from pathlib import Path

import pytest

from scripts.evaluate_range_regression import evaluate_range_regression


def test_range_deterministic_candidate_coverage_when_available() -> None:
    project_root = Path(__file__).resolve().parents[1] / "test" / "range"
    benchmark_dir = project_root / "benchmark"
    required = [
        benchmark_dir / "evaluate_zscope_report.py",
        benchmark_dir / "ground_truth.json",
        benchmark_dir / "entries.json",
    ]
    if not all(path.exists() for path in required):
        pytest.skip("test/range benchmark fixtures are not available in this checkout")

    result = evaluate_range_regression(
        project_root=project_root,
        deterministic_candidates=True,
    )

    assert result["recall"] >= 0.70
    assert result["precision"] >= 0.50
