from zscope.cli.cli import _batch_interruption_lines
from zscope.orchestration.scan_session import ScanSessionResult


def test_batch_interruption_lines_report_no_interrupted_entries() -> None:
    result = ScanSessionResult(is_batch=True, exit_code=0)

    assert _batch_interruption_lines(result) == ["Interrupted entries: none."]


def test_batch_interruption_lines_prompt_resume_for_interrupted_entries() -> None:
    result = ScanSessionResult(
        is_batch=True,
        exit_code=1,
        interrupted=True,
        interrupted_entries=["api_b", "api_c"],
    )

    assert _batch_interruption_lines(result) == [
        "Interrupted entries: 2 (api_b, api_c)",
        "Use --resume to continue from the last checkpoint.",
    ]


def test_batch_interruption_lines_prompt_resume_for_unknown_interruption() -> None:
    result = ScanSessionResult(is_batch=True, exit_code=1, interrupted=True)

    assert _batch_interruption_lines(result) == [
        "Interrupted entries: unknown (scan stopped before all workers reported status).",
        "Use --resume to continue from the last checkpoint.",
    ]
