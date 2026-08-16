from pathlib import Path
import json

import pytest

from scripts.evaluate_range_regression import evaluate_range_regression
from zscope.benchmarking.protocol import issue_matches, score_report


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
    assert truth.get("version") == 15

    result = evaluate_range_regression(
        project_root=project_root,
        regex_candidates=True,
        min_precision=0.50,
        min_recall=0.75,
        min_f1=0.60,
    )

    assert result["threshold_status"] == "passed"
    assert result["recall"] >= 0.75
    assert result["precision"] >= 0.50
    assert result["f1"] >= 0.65
    assert result["actionable_precision"] >= 0.50
    assert result["actionable_f1"] >= 0.60
    assert result["threshold_metric_fields"]["precision"] == "actionable_precision"
    assert result["threshold_metric_fields"]["f1"] == "actionable_f1"
    assert "false_positive_rate" not in result
    assert "standard_false_positive_rate" not in result
    assert "false_discovery_rate" in result
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


def test_range_v15_structured_anchor_and_resource_family_corrections() -> None:
    truth_path = (
        Path(__file__).resolve().parents[1] / "test" / "range" / "benchmark" / "ground_truth.json"
    )
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in truth["vulnerabilities"]}

    cases = {
        "REAL-029": {
            "category": "stale_fd",
            "function": "_runtime_reopen_cached_descriptor",
            "location": "src/lifecycle.c:1552",
        },
        "ISSUE42-002": {
            "category": "memory_leak",
            "cwe": "CWE-401",
            "function": "_runtime_close_thread_cache",
            "location": "src/lifecycle.c:2286",
        },
        "ISSUE42-022": {
            "category": "memory_leak",
            "cwe": "CWE-401",
            "function": "_runtime_cleanup_tls_reserve",
            "location": "src/lifecycle.c:2650",
        },
        "ISSUE42-028": {
            "category": "signal_deadlock",
            "function": "_runtime_record_signal_event",
            "location": "src/lifecycle.c:2765",
        },
    }

    assert truth["version"] == 15
    assert truth["total_vulnerabilities"] == 136
    for truth_id, issue in cases.items():
        assert issue_matches(issue, by_id[truth_id], line_tolerance=8), truth_id


def test_range_scorer_does_not_promote_same_location_with_category_drift() -> None:
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

    assert result["true_positives"] == 0
    assert result["false_negatives"] == 1
    assert result["weak_legacy_overlap_count"] == 1
    assert result["false_positives_effective"] == 1
