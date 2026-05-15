from pathlib import Path
import json

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

    truth = json.loads((benchmark_dir / "ground_truth.json").read_text(encoding="utf-8"))
    assert truth.get("version") == 6

    result = evaluate_range_regression(
        project_root=project_root,
        deterministic_candidates=True,
        min_precision=0.60,
        min_recall=0.75,
        min_f1=0.67,
    )

    assert result["threshold_status"] == "passed"
    assert result["recall"] >= 0.75
    assert result["precision"] >= 0.60
    assert result["f1"] >= 0.67
    assert "false_positive_rate" in result
    assert "with_needs_review" in result["report_views"]
    assert result["graph_issue_count"] > 0
