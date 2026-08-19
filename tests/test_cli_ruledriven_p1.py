from pathlib import Path
from types import SimpleNamespace

import pytest

from click.testing import CliRunner

from zscope.cli.cli import main


def _config(tmp_path: Path, language: str):
    return SimpleNamespace(
        project=SimpleNamespace(
            language=language,
            project_root=tmp_path,
            source_root=tmp_path,
            compile_commands_path=None,
            include_paths=[],
            exclude_paths=[],
        ),
        analysis=SimpleNamespace(workflow_name="default"),
        indexing=SimpleNamespace(),
        concurrency=SimpleNamespace(svf_workers=None, index_workers=1),
    )


def test_c_cpp_ruledriven_is_rejected_before_index_or_model_work(
    tmp_path: Path, monkeypatch
) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("config_version: 2\n", encoding="utf-8")
    monkeypatch.setattr(
        "zscope.cli.cli.ConfigLoader.load",
        lambda *args, **kwargs: _config(tmp_path, "c_cpp"),
    )
    monkeypatch.setattr(
        "zscope.cli.cli.CodeIndex",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("index must not run")),
    )

    result = CliRunner().invoke(main, ["--config", str(config_path), "--mode", "ruledriven"])

    assert result.exit_code != 0
    assert "use --mode default" in result.output
    assert "Candidate Ledger" in result.output


def test_java_ruledriven_remains_available(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("config_version: 2\n", encoding="utf-8")
    monkeypatch.setattr(
        "zscope.cli.cli.ConfigLoader.load",
        lambda *args, **kwargs: _config(tmp_path, "java"),
    )

    class FakeCodeIndex:
        def close(self):
            return None

    monkeypatch.setattr("zscope.cli.cli.CodeIndex", lambda *args, **kwargs: FakeCodeIndex())

    class FakeRuleDrivenAnalyzer:
        def __init__(self, config, *, code_index):
            self.config = config
            self.code_index = code_index

        def run(self):
            return {"issues": []}

        def close(self):
            return None

    monkeypatch.setattr(
        "zscope.rules.analyzer.RuleDrivenAnalyzer",
        FakeRuleDrivenAnalyzer,
    )

    result = CliRunner().invoke(main, ["--config", str(config_path), "--mode", "ruledriven"])

    assert result.exit_code == 0, result.output
    assert "Rule-driven analysis complete" in result.output


@pytest.mark.parametrize(
    ("flags", "expected_resume", "expected_maintain"),
    [
        ([], False, False),
        (["--resume"], True, False),
        (["--maintain"], False, True),
    ],
)
def test_default_resume_and_maintain_cli_dispatch_without_model_or_network(
    tmp_path: Path,
    monkeypatch,
    flags: list[str],
    expected_resume: bool,
    expected_maintain: bool,
) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("config_version: 2\n", encoding="utf-8")
    monkeypatch.setattr(
        "zscope.cli.cli.ConfigLoader.load",
        lambda *args, **kwargs: _config(tmp_path, "c_cpp"),
    )
    captured = {}

    class FakeScanSessionRunner:
        def __init__(self, config, **kwargs):
            captured.update(kwargs)

        def run(self):
            return SimpleNamespace(
                is_batch=False,
                exit_code=0,
                reports=[],
                issues_count=0,
                needs_review_count=0,
                unresolved_obligations_count=0,
                verdict="clean",
                task_id="",
                project_root=tmp_path,
            )

    monkeypatch.setattr("zscope.cli.cli.ScanSessionRunner", FakeScanSessionRunner)
    monkeypatch.setattr(
        "zscope.cli.cli.CodeIndex",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("CLI dispatch smoke must not construct an index")
        ),
    )

    result = CliRunner().invoke(main, ["--config", str(config_path), *flags])

    assert result.exit_code == 0, result.output
    assert captured["resume"] is expected_resume
    assert captured["maintain"] is expected_maintain


def test_alert_verify_empty_sarif_exits_before_model_use(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "zscope.yaml"
    config_path.write_text("config_version: 2\n", encoding="utf-8")
    sarif_path = tmp_path / "empty.sarif"
    sarif_path.write_text('{"version":"2.1.0","runs":[]}\n', encoding="utf-8")
    monkeypatch.setattr(
        "zscope.cli.cli.ConfigLoader.load",
        lambda *args, **kwargs: _config(tmp_path, "c_cpp"),
    )

    class FakeCodeIndex:
        def close(self):
            return None

    class ModelTrap:
        def __init__(self, *args, **kwargs):
            raise AssertionError("empty alert smoke must not construct a model client")

    monkeypatch.setattr("zscope.cli.cli.CodeIndex", lambda *args, **kwargs: FakeCodeIndex())
    monkeypatch.setattr("zscope.framework.llm_client.LLMClient", ModelTrap)

    result = CliRunner().invoke(
        main,
        ["--config", str(config_path), "--mode", "alert-verify", "--sarif", str(sarif_path)],
    )

    assert result.exit_code == 0, result.output
    assert "No alerts to verify" in result.output
