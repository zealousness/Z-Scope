from pathlib import Path

from scripts.check_scan_task_status import detect_scan_status, main


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


def test_cli_prints_status_and_returns_zero_for_running_log(tmp_path: Path, capsys) -> None:
    log = tmp_path / "scan.log"
    log.write_text("Task ID: release-42\nstill scanning\n", encoding="utf-8")

    exit_code = main(["--log", str(log), "--task-id", "release-42"])

    assert exit_code == 0
    assert capsys.readouterr().out == "running\n"


def test_cli_json_returns_zero_for_missing_log(tmp_path: Path, capsys) -> None:
    exit_code = main(["--log", str(tmp_path / "missing.log"), "--json"])

    assert exit_code == 0
    assert '"status": "missing_log"' in capsys.readouterr().out
