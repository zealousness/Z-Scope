"""The loaded YAML directory is the only public project-root authority."""

from dataclasses import fields
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from test_config_v2 import _config
from test_config_v3 import _document
from zscope.cli.config_cli import main as config_cli
from zscope.cli.init import main as init_cli, render_project_config
from zscope.config.config import ConfigLoader, ProjectConfig
from zscope.config.v3 import parse_user_config_v3, public_json_schema
from zscope.config.editor import (
    save_document_data,
    save_document_text,
    validate_document_file,
    validate_document_text,
)
from zscope.config.v3_preparation import prepare_saved_config


def test_editor_expands_available_strings_for_validation_but_preserves_saved_references(
    tmp_path, monkeypatch
):
    for name in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ZSCOPE_EDITOR_TIMEZONE", "UTC")
    monkeypatch.setenv("ZSCOPE_EDITOR_STOP", "23:59")
    document = yaml.safe_load(render_project_config(tmp_path, language="c_cpp"))
    document["execution"] = {
        "timezone": "${ZSCOPE_EDITOR_TIMEZONE}",
        "stop_at": "${ZSCOPE_EDITOR_STOP}",
    }
    path = tmp_path / "zscope.yaml"
    save_document_data(path, document, expand_environment=False)
    assert yaml.safe_load(path.read_text())["execution"] == document["execution"]
    saved = path.read_bytes()
    monkeypatch.setenv("ZSCOPE_EDITOR_TIMEZONE", "Unknown/Invalid")
    with pytest.raises(ValueError, match="timezone"):
        save_document_data(path, document, expand_environment=False)
    assert path.read_bytes() == saved


def test_unresolved_numeric_environment_is_an_explicit_structural_validation_error(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ZSCOPE_EDITOR_WORKERS", raising=False)
    document = yaml.safe_load(render_project_config(tmp_path, language="c_cpp"))
    document["execution"] = {"max_workers": "${ZSCOPE_EDITOR_WORKERS}"}
    with pytest.raises(
        ValueError,
        match="cannot structurally validate execution.max_workers.*ZSCOPE_EDITOR_WORKERS",
    ):
        save_document_data(tmp_path / "zscope.yaml", document, expand_environment=False)
    assert not (tmp_path / "zscope.yaml").exists()
    monkeypatch.setenv("ZSCOPE_EDITOR_WORKERS", "8")
    with pytest.raises(ValueError, match="execution.max_workers must be a positive integer"):
        save_document_data(tmp_path / "zscope.yaml", document, expand_environment=False)


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize("key", ["root", "source_root"])
def test_even_equivalent_old_roots_require_migration(tmp_path, version, key):
    document = _config(tmp_path) if version == 2 else _document()
    document["project"][key] = "."
    path = tmp_path / "zscope.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ValueError, match=f"project.{key} removed.*migrate"):
        ConfigLoader.load(str(path), read_only=True)


def test_schema_and_internal_config_have_no_second_root():
    assert "root" not in public_json_schema()["properties"]["project"]["properties"]
    assert "source_root" not in {field.name for field in fields(ProjectConfig)}


def test_editor_can_save_unconfigured_v3_but_execution_still_requires_environment(
    tmp_path, monkeypatch
):
    for name in ("Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL", "Z_SCOPE_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    text = render_project_config(tmp_path, language="c_cpp", preset="balanced")
    path = tmp_path / "zscope.yaml"
    validate_document_text(text, config_dir=tmp_path, expand_environment=False)
    save_document_text(path, text, expand_environment=False)
    validate_document_file(path, expand_environment=False)
    raw = yaml.safe_load(path.read_text())
    assert raw["llms"]["default"]["api_key"] == "${Z_SCOPE_API_KEY}"
    raw["scan"]["preset"] = "fast"
    save_document_data(path, raw, expand_environment=False)
    assert yaml.safe_load(path.read_text())["scan"]["preset"] == "fast"
    for strict_call in (
        lambda: validate_document_file(path),
        lambda: validate_document_text(text, config_dir=tmp_path),
        lambda: ConfigLoader.load(str(path), read_only=True),
        lambda: prepare_saved_config(str(path)),
    ):
        with pytest.raises(ValueError, match="environment variable"):
            strict_call()
    saved = path.read_bytes()
    raw["project"]["root"] = "."
    with pytest.raises(ValueError, match="project.root removed"):
        save_document_data(path, raw, expand_environment=False)
    assert path.read_bytes() == saved


@pytest.mark.parametrize(
    "overrides", [{"target_id": " "}, {"compile_commands": ""}, {"preset": ""}, {"preset": "quick"}]
)
def test_shared_renderer_rejects_invalid_inputs(tmp_path, overrides):
    with pytest.raises(ValueError):
        render_project_config(tmp_path, language="c_cpp", **overrides)


@pytest.mark.parametrize("preset", ["fast", "balanced", "deep"])
def test_preset_is_the_actual_execution_depth(tmp_path, preset):
    document = _document(scan={"preset": preset})
    path = tmp_path / "zscope.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    model = parse_user_config_v3(str(path))
    assert model.scan.preset == model.scan.mapped_depth == preset


@pytest.mark.parametrize("old,new", [("quick", "fast"), ("overnight", "deep")])
def test_explicit_v3_migration_moves_config_to_original_root_and_preserves_depth(
    tmp_path, monkeypatch, old, new
):
    project = tmp_path / "工程 # root"
    project.mkdir()
    source = tmp_path / "old.yaml"
    document = _document(scan={"preset": old})
    document["project"]["root"] = project.name
    source.write_text(yaml.safe_dump(document), encoding="utf-8")
    before = source.read_bytes()
    target = project / "zscope.yaml"
    result = CliRunner().invoke(
        config_cli, ["migrate", "--input", str(source), "--output", str(target)]
    )
    assert result.exit_code == 0, result.output
    assert source.read_bytes() == before
    monkeypatch.chdir(tmp_path.parent)
    model = parse_user_config_v3(str(target))
    assert model.project.root == project.resolve()
    assert model.scan.mapped_depth == new
    assert "root" not in yaml.safe_load(target.read_text())["project"]


def test_migration_refuses_wrong_destination_ambiguous_v2_cwd_and_split_roots(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    source = tmp_path / "old.yaml"
    raw = _config(project)
    raw["project"]["root"] = "project"
    source.write_text(yaml.safe_dump(raw), encoding="utf-8")
    target = project / "zscope.yaml"
    args = ["migrate", "--input", str(source), "--output", str(target)]
    result = CliRunner().invoke(config_cli, args)
    assert "--legacy-working-directory" in result.output
    assert not target.exists()
    result = CliRunner().invoke(config_cli, args + ["--legacy-working-directory", str(tmp_path)])
    assert result.exit_code == 0, result.output
    target.unlink()
    raw["project"]["root"] = str(project)
    raw["project"]["source_root"] = "src"
    source.write_text(yaml.safe_dump(raw), encoding="utf-8")
    result = CliRunner().invoke(config_cli, args)
    assert "cannot migrate automatically" in result.output
    assert not target.exists()
    raw["project"].pop("source_root")
    source.write_text(yaml.safe_dump(raw), encoding="utf-8")
    result = CliRunner().invoke(
        config_cli, ["migrate", "--input", str(source), "--output", str(tmp_path / "wrong.yaml")]
    )
    assert "original project directory" in result.output
    assert not (tmp_path / "wrong.yaml").exists()


def test_init_default_destination_and_shared_renderer(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        init_cli,
        [
            "--project-root",
            str(project),
            "--language",
            "c_cpp",
            "--preset",
            "balanced",
            "--no-interactive",
        ],
    )
    assert result.exit_code == 0, result.output
    target = project / "zscope.yaml"
    assert target.is_file()
    assert not (tmp_path / "zscope.yaml").exists()
    assert yaml.safe_load(target.read_text()) == yaml.safe_load(
        render_project_config(project, language="c_cpp", preset="balanced")
    )


def test_init_uses_existing_realworld_benchmark_compile_database(tmp_path):
    build = tmp_path / "build-rwb"
    build.mkdir()
    (build / "compile_commands.json").write_text("[]\n", encoding="utf-8")

    document = yaml.safe_load(render_project_config(tmp_path, language="c_cpp"))

    assert document["project"]["targets"][0]["compile_commands"] == (
        "build-rwb/compile_commands.json"
    )
