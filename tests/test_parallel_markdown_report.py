from pathlib import Path

from zscope.orchestration.parallel_analyzer import ParallelAnalysisResult, ParallelAnalyzer


def test_markdown_report_uses_final_combined_projection(tmp_path: Path) -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    review = {
        "id": "CAND_REVIEW",
        "function": "handle_request",
        "location": "src/request.c:12",
        "category": "reliability",
        "subcategory": "contract",
        "description": "The caller contract is not established.",
        "root_cause": "The input range is unknown.",
        "suggested_fix": "Review the documented precondition.",
        "confidence": 0.5,
        "impact_level": "medium",
        "candidate_disposition": "needs_review",
    }
    analyzer._last_combined_report = {
        "completeness": "complete",
        "summary": {
            "functions_analyzed": 1,
            "functions_failed": 0,
            "total_issues": 0,
            "deferred_entry_count": 0,
        },
        "function_results": [
            {
                "function": "handle_request",
                "entry_identity": "src/request.c::handle_request",
                "verdict": "no_issue_found",
                "duration_seconds": 0.2,
            }
        ],
        "issues": [],
        "metadata": {"audit_observations": [review]},
        "report_views": {
            "with_needs_review": {
                "issues": [review],
                "included_needs_review_count": 1,
            }
        },
    }
    stale_entry_issue = {
        "id": "STALE_ENTRY_ISSUE",
        "description": "This intermediate entry result must not be rendered.",
    }
    results = {
        "handle_request": ParallelAnalysisResult(
            function_name="handle_request",
            verdict="issues_found",
            issues=[stale_entry_issue],
        )
    }

    output = tmp_path / "batch.md"
    content = analyzer.generate_combined_markdown_report(results, output)

    assert output.read_text(encoding="utf-8") == content
    assert "This intermediate entry result must not be rendered." not in content
    assert "- **Audit Observations**: 1" in content
    assert "## Needs Review Findings" in content
    assert "The caller contract is not established." in content
    assert "*No needs_review observations.*" not in content
