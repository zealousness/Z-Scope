from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from zscope.cli.config_cli import main, migrate_legacy_document


def _legacy(root: Path) -> dict:
    return {
        "llm": {
            "provider": "openai",
            "base_url": "http://localhost/v1",
            "model": "unit-model",
            "api_key": "unit-key",
            "temperature": 0.1,
        },
        "project": {
            "root": str(root),
            "source_root": ".",
            "language": "cpp",
            "compile_commands": "build/compile_commands.json",
            "entry_discovery": {
                "enabled": True,
                "root": "src",
                "header_files": ["include/**/*.h"],
                "max_candidates": 30,
            },
            "agents": [
                {"name": "semantic_modeler", "llm_ref": "default"},
                {
                    "name": "vulnerability_analyzer",
                    "llm_ref": "default",
                    "task": "focus on ownership",
                    "skills": ["memory-safety"],
                },
            ],
        },
        "indexing": {
            "backend": "unified",
            "max_clangd_threads": 6,
            "svf_scope": "entry",
        },
        "analysis": {
            "parallel_workers": 3,
            "entry_workers": 5,
            "index_workers": 8,
            "svf_workers": 2,
            "validator_workers": 2,
            "llm_max_inflight": 7,
        },
    }


def test_known_legacy_fields_have_deterministic_v2_mapping(tmp_path: Path) -> None:
    migrated, warnings = migrate_legacy_document(_legacy(tmp_path))

    assert migrated["config_version"] == 2
    assert migrated["llms"]["default"]["base_urls"] == ["http://localhost/v1"]
    assert migrated["llms"]["default"]["models"] == ["unit-model"]
    assert migrated["project"]["language"] == "c_cpp"
    assert migrated["project"]["compile_commands_path"] == "build/compile_commands.json"
    assert migrated["project"]["entry_discovery"] == {
        "enabled": True,
        "search_root": "src",
        "interface_files": ["include/**/*.h"],
        "max_entries": 30,
    }
    assert migrated["scan"]["task"] == "focus on ownership"
    assert migrated["concurrency"] == {
        "entry_workers": 5,
        "validator_workers": 2,
        "investigator_workers": 1,
        "evidence_completion_workers": 2,
        "index_workers": 8,
        "llm_max_inflight": 7,
        "svf_workers": 2,
    }
    assert any("provider" in warning for warning in warnings)
    assert any("review concurrency" in warning for warning in warnings)


def test_migrate_command_preserves_source_and_refuses_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "old.yaml"
    destination = tmp_path / "new.yaml"
    original = yaml.safe_dump(_legacy(tmp_path), sort_keys=False)
    source.write_text(original, encoding="utf-8")
    runner = CliRunner()

    first = runner.invoke(
        main,
        ["migrate", "--input", str(source), "--output", str(destination)],
    )
    assert first.exit_code == 0, first.output
    assert source.read_text(encoding="utf-8") == original
    assert yaml.safe_load(destination.read_text(encoding="utf-8"))["config_version"] == 2

    second = runner.invoke(
        main,
        ["migrate", "--input", str(source), "--output", str(destination)],
    )
    assert second.exit_code != 0
    assert "refusing to overwrite" in second.output


def test_unknown_legacy_field_fails_without_creating_output(tmp_path: Path) -> None:
    source = tmp_path / "old.yaml"
    destination = tmp_path / "new.yaml"
    legacy = _legacy(tmp_path)
    legacy["project"]["mystery"] = True
    source.write_text(yaml.safe_dump(legacy, sort_keys=False), encoding="utf-8")

    result = CliRunner().invoke(
        main,
        ["migrate", "--input", str(source), "--output", str(destination)],
    )

    assert result.exit_code != 0
    assert "unknown legacy key(s) at project: mystery" in result.output
    assert not destination.exists()


def test_force_replaces_destination_and_reports_dropped_fields(tmp_path: Path) -> None:
    source = tmp_path / "old.yaml"
    destination = tmp_path / "new.yaml"
    source.write_text(yaml.safe_dump(_legacy(tmp_path), sort_keys=False), encoding="utf-8")
    destination.write_text("stale\n", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "migrate",
            "--input",
            str(source),
            "--output",
            str(destination),
            "--force",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "dropped ineffective field llm.provider" in result.output
    assert destination.read_text(encoding="utf-8").startswith("config_version: 2\n")


def test_force_still_refuses_to_overwrite_migration_source(tmp_path: Path) -> None:
    source = tmp_path / "old.yaml"
    original = yaml.safe_dump(_legacy(tmp_path), sort_keys=False)
    source.write_text(original, encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "migrate",
            "--input",
            str(source),
            "--output",
            str(source),
            "--force",
        ],
    )

    assert result.exit_code != 0
    assert "migration never overwrites source" in result.output
    assert source.read_text(encoding="utf-8") == original
