from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from zscope.cli.config_cli import main, migrate_document
from zscope.config.config import ConfigLoader


def _legacy(root: Path, language: str = "c_cpp") -> dict:
    return {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["${MIGRATION_URL}"],
                "models": ["unit"],
                "api_key": "${MIGRATION_KEY}",
            }
        },
        "project": {
            "language": language,
            **(
                {"compile_commands_path": "build/compile_commands.json"}
                if language == "c_cpp"
                else {}
            ),
        },
        "scan": {"task": "focus on ownership", "llm_profiles": {"analysis": "default"}},
        "indexing": {"backend": "unified" if language == "c_cpp" else "java_unified"},
        "concurrency": {"entry_workers": 3, "llm_max_inflight": 7},
        "rules": {"disabled_ids": ["example-rule"]},
    }


@pytest.mark.parametrize("language", ["c_cpp", "java"])
@pytest.mark.parametrize("depth", [None, "fast", "balanced", "deep"])
def test_migration_preserves_depth_and_advanced_settings(tmp_path, language, depth, monkeypatch):
    raw = _legacy(tmp_path, language)
    if depth is not None:
        raw["scan"]["depth"] = depth
    source = tmp_path / "old.yaml"
    source.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = source.read_bytes()
    destination = tmp_path / "zscope.yaml"
    result = CliRunner().invoke(
        main, ["migrate", "--input", str(source), "--output", str(destination)]
    )
    assert source.read_bytes() == before
    if language == "java" and depth in {"balanced", "deep"}:
        assert result.exit_code != 0
        assert "use 'fast'" in result.output
        assert not destination.exists()
        return
    assert result.exit_code == 0, result.output
    migrated = yaml.safe_load(destination.read_text())
    assert migrated["config_version"] == 3
    assert migrated["scan"]["preset"] == (depth or "fast")
    assert "depth" not in migrated["scan"]
    assert "compile_commands_path" not in migrated["project"]
    for key in ("llms", "concurrency", "rules"):
        assert migrated[key] == raw[key]
    monkeypatch.setenv("MIGRATION_URL", "http://localhost/v1")
    monkeypatch.setenv("MIGRATION_KEY", "dummy")
    config = ConfigLoader.load(str(destination), read_only=True)
    assert config.scan.depth == (depth or "fast")
    assert config.scan.task == "focus on ownership"
    assert config.project.entry_discovery.enabled is False
    assert config.concurrency.entry_workers == 3
    if language == "c_cpp":
        assert config.indexing.svf_heap_limit_mb == 32768
        assert config.project.compile_commands_path == tmp_path / "build/compile_commands.json"


@pytest.mark.parametrize(
    "preset,expected",
    [(None, "deep"), ("quick", "fast"), ("overnight", "deep"), ("balanced", "balanced")],
)
def test_historical_v3_default_is_materialized(tmp_path, preset, expected):
    raw, _ = migrate_document(_legacy(tmp_path))
    raw["scan"].pop("preset")
    if preset:
        raw["scan"]["preset"] = preset
    converted, _ = migrate_document(raw)
    assert converted["scan"]["preset"] == expected


def test_force_does_not_overwrite_source_or_invalid_destination(tmp_path):
    source, destination = tmp_path / "old.yaml", tmp_path / "new.yaml"
    raw = _legacy(tmp_path)
    raw["project"]["mystery"] = True
    source.write_text(yaml.safe_dump(raw), encoding="utf-8")
    before = source.read_bytes()
    destination.write_text("keep existing\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        main, ["migrate", "--input", str(source), "--output", str(destination), "--force"]
    )
    assert result.exit_code != 0
    assert "project.mystery" in result.output
    assert destination.read_text() == "keep existing\n"
    assert source.read_bytes() == before
    result = runner.invoke(
        main, ["migrate", "--input", str(source), "--output", str(source), "--force"]
    )
    assert "migration never overwrites source" in result.output
    assert source.read_bytes() == before


def test_existing_output_requires_force(tmp_path):
    source, destination = tmp_path / "old.yaml", tmp_path / "new.yaml"
    source.write_text(yaml.safe_dump(_legacy(tmp_path)), encoding="utf-8")
    destination.write_text("keep\n", encoding="utf-8")
    args = ["migrate", "--input", str(source), "--output", str(destination)]
    assert "refusing to overwrite" in CliRunner().invoke(main, args).output
    result = CliRunner().invoke(main, args + ["--force"])
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(destination.read_text())["config_version"] == 3


@pytest.mark.parametrize("version", [None, 1, 4, "2", True])
def test_unsupported_migration_versions_are_explicit(tmp_path, version):
    raw = _legacy(tmp_path)
    raw["config_version"] = version
    with pytest.raises(ValueError, match="zscope-init"):
        migrate_document(raw)


def test_conversion_does_not_mutate_input(tmp_path):
    raw = _legacy(tmp_path)
    original = deepcopy(raw)
    migrate_document(raw)
    assert raw == original


def test_missing_compile_database_preserves_old_lookup_location(tmp_path):
    raw = _legacy(tmp_path)
    raw["project"].pop("compile_commands_path")
    converted, warnings = migrate_document(raw)
    assert converted["project"]["targets"] == [
        {"id": "main", "compile_commands": "compile_commands.json"}
    ]
    assert any("verify it before scanning" in warning for warning in warnings)
