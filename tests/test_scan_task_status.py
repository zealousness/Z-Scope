from pathlib import Path

from scripts.check_scan_task_status import detect_scan_status


def test_detect_scan_status_reports_complete_for_batch_log() -> None:
    result = detect_scan_status(
        """
Task ID: release-42
Batch Analysis Complete.
Functions analyzed: 3
Interrupted entries: none.
""",
        task_id="release-42",
    )

    assert result["status"] == "complete"
    assert result["done"] is True


def test_detect_scan_status_keeps_other_task_running() -> None:
    result = detect_scan_status(
        """
Task ID: other-task
Batch Analysis Complete.
""",
        task_id="release-42",
    )

    assert result["status"] == "not_found"
    assert result["done"] is False


def test_detect_scan_status_reports_failure_before_completion() -> None:
    result = detect_scan_status("Analysis failed: backend crashed\n")

    assert result["status"] == "failed"
    assert result["done"] is True
