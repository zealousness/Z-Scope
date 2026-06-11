from pathlib import Path
import json

import pytest

from scripts.evaluate_range_regression import evaluate_range_regression
from zscope.benchmarking.protocol import score_report


def test_range_regex_candidate_coverage_when_available() -> None:
    project_root = Path(__file__).resolve().parents[1] / "test" / "range"
    benchmark_dir = project_root / "benchmark"
    required = [
        benchmark_dir / "ground_truth.json",
        benchmark_dir / "entries.json",
    ]
    if not all(path.exists() for path in required):
        pytest.skip("test/range benchmark fixtures are not available in this checkout")

    truth = json.loads((benchmark_dir / "ground_truth.json").read_text(encoding="utf-8"))
    assert truth.get("version") == 13

    result = evaluate_range_regression(
        project_root=project_root,
        regex_candidates=True,
        min_precision=0.50,
        min_recall=0.75,
        min_f1=0.65,
    )

    assert result["threshold_status"] == "passed"
    assert result["recall"] >= 0.75
    assert result["precision"] >= 0.50
    assert result["f1"] >= 0.65
    assert "false_positive_rate" in result
    assert "duplicate_of_matched_count" in result
    assert "with_needs_review" in result["report_views"]
    assert result["graph_issue_count"] > 0


def test_range_unified_candidate_recall_gate_when_available() -> None:
    project_root = Path(__file__).resolve().parents[1] / "test" / "range"
    benchmark_dir = project_root / "benchmark"
    required = [
        benchmark_dir / "ground_truth.json",
        benchmark_dir / "entries.json",
    ]
    if not all(path.exists() for path in required):
        pytest.skip("test/range benchmark fixtures are not available in this checkout")

    result = evaluate_range_regression(
        project_root=project_root,
        candidate_backend="unified",
        min_recall=0.66,
    )

    assert result["threshold_status"] == "passed"
    assert result["candidate_backend"] == "unified"
    assert result["recall"] >= 0.66
    assert result["false_positives_raw"] >= result["false_positives_effective"]
    assert result["duplicate_of_matched_count"] >= 0
    assert result["issue_sources"]["clang_ast_cfg"] > 0
    assert "miss_analysis" in result
    assert all("reason" in row for row in result["miss_analysis"])
    assert "miss_reason_summary" in result


def test_range_scorer_counts_discoverable_same_location_even_with_category_drift() -> None:
    truth = {
        "benchmark": "unit",
        "vulnerabilities": [
            {
                "id": "RANGE-X",
                "cwe": "CWE-193",
                "category": "off_by_one",
                "file": "src/lifecycle.c",
                "function": "_lifecycle_format_topic",
                "line": 331,
                "end_line": 333,
                "keywords": ["topic", "sizeof(topic)", "off-by-one"],
            }
        ],
    }
    report = {
        "issues": [
            {
                "function": "_lifecycle_format_topic",
                "location": "src/lifecycle.c:333",
                "category": "integer_overflow",
                "description": "The topic terminator writes topic[sizeof(topic)] one byte past the stack buffer.",
                "code_snippet": "topic[sizeof(topic)] = '\\0';",
            }
        ]
    }

    result = score_report(report, truth, line_tolerance=5)

    assert result["true_positives"] == 1
    assert result["false_negatives"] == 0


