import pytest

from scripts.render_trial_metrics import TrialMetricsError, _read_json, render_trial_metrics
from zscope.reporting.json_io import write_json_atomic


def test_trial_metrics_render_shared_and_legacy_reports_identically(tmp_path):
    run_dir = tmp_path / "trial" / "run-01"
    write_json_atomic(run_dir / "summary.json", {"completed": True, "run_number": 1})
    write_json_atomic(run_dir / "score.json", {})
    report = {
        "issues_by_severity": {"high": 3},
        "issues_by_severity_with_needs_review": {"high": 5},
        "function_results": [{"function": "example", "total_issues": 3}],
    }
    report_path = run_dir / "report.json"
    write_json_atomic(report_path, report)
    _, legacy = render_trial_metrics(run_dir)
    write_json_atomic(report_path, report, shared=True)
    original = report_path.read_bytes()

    assert _read_json(report_path) == report
    _, shared = render_trial_metrics(run_dir)

    assert shared == legacy
    assert report_path.read_bytes() == original


def test_trial_metrics_reject_corrupted_shared_report(tmp_path):
    path = tmp_path / "report.json"
    write_json_atomic(
        path, {"storage_schema": "zscope.shared-json.v1", "root": ["ref", "missing"], "objects": {}}
    )

    with pytest.raises(TrialMetricsError):
        _read_json(path)
