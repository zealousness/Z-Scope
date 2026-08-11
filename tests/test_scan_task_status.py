from pathlib import Path

from scripts.check_scan_task_status import check_log_dir, detect_scan_status, main


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


def test_completion_marker_wins_over_earlier_failure_text() -> None:
    result = detect_scan_status(
        """
Task ID: release-42
Analysis failed: one candidate probe failed but scan kept going
more progress
Batch Analysis Complete.
Interrupted entries: none.
""",
        task_id="release-42",
    )

    assert result["status"] == "complete"
    assert result["reason"] == "completion marker found"


def test_failure_marker_outside_tail_keeps_task_running() -> None:
    log = "\n".join(
        ["Task ID: release-42", "Analysis failed: transient probe failure"]
        + [f"progress line {index}" for index in range(220)]
    )

    result = detect_scan_status(log, task_id="release-42")

    assert result["status"] == "running"


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


def test_check_log_dir_finds_matching_task_log(tmp_path: Path) -> None:
    older = tmp_path / "scan-old.log"
    newer = tmp_path / "scan-new.log"
    older.write_text("Task ID: other\nBatch Analysis Complete.\n", encoding="utf-8")
    newer.write_text("Task ID: release-42\nBatch Analysis Complete.\n", encoding="utf-8")

    result = check_log_dir(tmp_path, task_id="release-42")

    assert result["status"] == "complete"
    assert result["log"] == str(newer)


def test_cli_accepts_log_dir_and_task_id_without_log_file(tmp_path: Path, capsys) -> None:
    log = tmp_path / "scan-release-42.log"
    log.write_text("Task ID: release-42\nstill scanning\n", encoding="utf-8")

    exit_code = main(["--log-dir", str(tmp_path), "--task-id", "release-42"])

    assert exit_code == 0
    assert capsys.readouterr().out == "running\n"
