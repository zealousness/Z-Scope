from click.testing import CliRunner
from pathlib import Path
from types import SimpleNamespace

from zscope._version import __version__
from zscope.cli import cli as cli_module
from zscope.cli.cli import main
from zscope.cli.cli import _batch_interruption_lines, _review_count_lines
from zscope.orchestration.scan_session import ScanSessionResult


def test_cli_version_reports_package_version() -> None:
    assert __version__ == "1.3.2"

    result = CliRunner().invoke(main, ["--version"])

    assert result.exit_code == 0
    assert result.output == f"Z-SCOPE, version {__version__}\n"


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


def test_review_count_lines_distinguish_visible_findings_from_obligations() -> None:
    result = ScanSessionResult(
        is_batch=True,
        exit_code=1,
        needs_review_count=30,
        unresolved_obligations_count=951,
    )

    assert _review_count_lines(result) == [
        "needs_review findings: 30",
        "Unresolved candidate obligations: 951",
    ]


def test_cli_passes_task_id_to_scan_session(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("project: {}\n", encoding="utf-8")
    captured = {}

    fake_config = SimpleNamespace(
        project=SimpleNamespace(project_root=tmp_path, source_root=tmp_path)
    )

    class FakeConfigLoader:
        @staticmethod
        def load(path, **_overrides):
            captured["config_path"] = path
            return fake_config

    class FakeScanSessionRunner:
        def __init__(self, config, **kwargs):
            captured["task_id"] = kwargs.get("task_id")

        def run(self):
            return ScanSessionResult(
                is_batch=True,
                exit_code=0,
                reports=[tmp_path / "zscope_batch_report_release_42.json"],
                functions_analyzed=1,
                task_id="release-42",
                task_slug="release-42",
            )

    monkeypatch.setattr(cli_module, "ConfigLoader", FakeConfigLoader)
    monkeypatch.setattr(cli_module, "ScanSessionRunner", FakeScanSessionRunner)

    result = CliRunner().invoke(main, ["-c", str(config_path), "--task-id", "release-42"])

    assert result.exit_code == 0
    assert captured["task_id"] == "release-42"
    assert "Task ID: release-42" in result.output
    assert "zscope_batch_report_release_42.json" in result.output
