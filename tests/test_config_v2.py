from __future__ import annotations

import json
from pathlib import Path

import pytest

from zscope.config.config import ConfigLoader
from zscope.orchestration.skill_selection import select_vulnerability_skills


def _config(root: Path, *, language: str = "c_cpp") -> dict:
    data = {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {
            "root": str(root),
            "source_root": ".",
            "language": language,
            "entry_discovery": {
                "enabled": True,
                "search_root": ".",
                "interface_files": ["include/**/*.h"],
                "max_entries": 20,
                "max_functions": 100,
            },
        },
        "scan": {"task": ""},
        "indexing": {"backend": "regex"},
        "concurrency": {
            "entry_workers": 2,
            "validator_workers": 2,
            "investigator_workers": 1,
            "evidence_completion_workers": 2,
            "index_workers": 2,
            "svf_workers": 1,
            "llm_max_inflight": 2,
        },
    }
    if language == "java":
        data["project"]["entry_discovery"]["interface_files"] = ["src/**/*.java"]
        data["indexing"] = {"backend": "java_source", "java": {"structure_frontend": "builtin"}}
        del data["concurrency"]["svf_workers"]
    return data


def _write(root: Path, data: dict, name: str = "zscope.yaml") -> Path:
    path = root / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_empty_task_activates_every_available_skill(tmp_path: Path) -> None:
    config = ConfigLoader.load(str(_write(tmp_path, _config(tmp_path))))
    analyzer = next(
        agent for agent in config.project.agents if agent.name == "vulnerability_analyzer"
    )

    assert analyzer.task == ""
    selection = select_vulnerability_skills(analyzer.task, ["memory", "concurrency"])
    assert selection.skills == ["memory", "concurrency"]
    assert selection.restricted is False


def test_unknown_key_reports_full_path_and_suggestion(tmp_path: Path) -> None:
    data = _config(tmp_path)
    discovery = data["project"]["entry_discovery"]
    discovery["interfce_files"] = discovery.pop("interface_files")

    with pytest.raises(
        ValueError,
        match=r"project\.entry_discovery\.interfce_files.*interface_files",
    ):
        ConfigLoader.load(str(_write(tmp_path, data)))


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text("config_version: 2\nconfig_version: 2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate YAML key 'config_version'"):
        ConfigLoader.load(str(path))


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("project", "language"), "cpp", "project.language"),
        (("indexing", "backend"), "auto", "indexing.backend"),
        (("concurrency", "index_workers"), True, "concurrency.index_workers"),
        (("project", "entry_discovery", "interface_files"), ["^api/.*$"], "must be a glob"),
    ],
)
def test_types_enums_and_language_aliases_are_strict(
    tmp_path: Path, path: tuple[str, ...], value, message: str
) -> None:
    data = _config(tmp_path)
    cursor = data
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value

    with pytest.raises(ValueError, match=message):
        ConfigLoader.load(str(_write(tmp_path, data)))


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("llms.default", "provider"),
        ("llms.default", "temperature"),
        ("llms.default", "model"),
        ("project", "task"),
        ("project", "compile_commands"),
        ("project.entry_discovery", "header_files"),
    ],
)
def test_removed_v1_fields_are_rejected(tmp_path: Path, section: str, field: str) -> None:
    data = _config(tmp_path)
    cursor = data
    for key in section.split("."):
        cursor = cursor[key]
    cursor[field] = "removed"

    with pytest.raises(ValueError, match=field):
        ConfigLoader.load(str(_write(tmp_path, data)))


def test_unset_environment_variable_in_required_llm_field_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _config(tmp_path)
    data["llms"]["default"]["api_key"] = "${Z_SCOPE_MISSING_TEST_KEY}"
    monkeypatch.delenv("Z_SCOPE_MISSING_TEST_KEY", raising=False)

    with pytest.raises(ValueError, match="llms.default.api_key.*Z_SCOPE_MISSING_TEST_KEY"):
        ConfigLoader.load(str(_write(tmp_path, data)))


def test_default_config_location_is_only_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    _write(tmp_path, _config(tmp_path))
    monkeypatch.chdir(nested)

    with pytest.raises(FileNotFoundError, match="nested.*zscope.yaml"):
        ConfigLoader.load()


def test_runtime_paths_are_anchored_to_project_root(tmp_path: Path) -> None:
    config = ConfigLoader.load(str(_write(tmp_path, _config(tmp_path))))

    assert (
        Path(config.indexing.knowledge_db_path)
        == (tmp_path / ".zscope_knowledge" / "code_knowledge.db").resolve()
    )
    assert Path(config.analysis.snapshot_dir) == (tmp_path / ".zscope_snapshots").resolve()
    assert (
        config.project.user_config_file
        == (tmp_path / ".zscope_snapshots" / "user_config.xlsx").resolve()
    )


def test_search_root_is_relative_to_project_root_and_cannot_escape(tmp_path: Path) -> None:
    module = tmp_path / "modules" / "api"
    module.mkdir(parents=True)
    data = _config(tmp_path)
    data["project"]["source_root"] = "src"
    (tmp_path / "src").mkdir()
    data["project"]["entry_discovery"]["search_root"] = "modules/api"
    config = ConfigLoader.load(str(_write(tmp_path, data)))
    assert config.project.entry_discovery.search_root == module.resolve()

    data["project"]["entry_discovery"]["search_root"] = "../outside"
    (tmp_path.parent / "outside").mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="inside project.root"):
        ConfigLoader.load(str(_write(tmp_path, data)))


def test_cross_language_fields_are_rejected(tmp_path: Path) -> None:
    java = _config(tmp_path, language="java")
    java["project"]["compile_commands_path"] = "build/compile_commands.json"
    with pytest.raises(ValueError, match="not valid for Java"):
        ConfigLoader.load(str(_write(tmp_path, java)))

    java = _config(tmp_path, language="java")
    java["indexing"]["svf"] = {"scope": "auto"}
    with pytest.raises(ValueError, match="indexing.svf"):
        ConfigLoader.load(str(_write(tmp_path, java)))


def test_svf_pool_names_paths_and_references_are_strict(tmp_path: Path) -> None:
    data = _config(tmp_path)
    data["indexing"] = {
        "backend": "unified",
        "svf": {
            "exclusive_pools": [{"name": "variant", "paths": ["src/a/**"]}],
            "shared_pools": [
                {"name": "common", "paths": ["src/common/**"], "conflicts_with": ["missing"]}
            ],
        },
    }
    with pytest.raises(ValueError, match="references unknown"):
        ConfigLoader.load(str(_write(tmp_path, data)))

    data["indexing"]["svf"]["shared_pools"][0] = {
        "name": "variant",
        "paths": ["src/common/**"],
        "conflicts_with": ["variant"],
    }
    with pytest.raises(ValueError, match="names must be unique"):
        ConfigLoader.load(str(_write(tmp_path, data)))

    data["indexing"]["svf"]["shared_pools"][0] = {
        "name": "common",
        "paths": [],
        "conflicts_with": ["variant"],
    }
    with pytest.raises(ValueError, match="paths.*must not be empty"):
        ConfigLoader.load(str(_write(tmp_path, data)))


def test_runtime_override_requires_developer_mode_and_records_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = _write(tmp_path, _config(tmp_path))
    override = tmp_path / "runtime.override.yaml"
    override.write_text(
        "runtime_spec_version: 1\nanalysis:\n  max_function_lines: 777\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("Z_SCOPE_RUNTIME_SPEC", str(override.resolve()))
    monkeypatch.delenv("Z_SCOPE_DEVELOPER_MODE", raising=False)
    with pytest.raises(ValueError, match="requires Z_SCOPE_DEVELOPER_MODE=1"):
        ConfigLoader.load(str(config_path))

    monkeypatch.setenv("Z_SCOPE_DEVELOPER_MODE", "1")
    config = ConfigLoader.load(str(config_path))
    assert config.analysis.max_function_lines == 777
    assert config.runtime_provenance.developer_override is True
    assert config.runtime_provenance.source_path == str(override.resolve())
    assert len(config.runtime_provenance.sha256) == 64


def test_runtime_override_is_strict_and_must_be_absolute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = _write(tmp_path, _config(tmp_path))
    monkeypatch.setenv("Z_SCOPE_DEVELOPER_MODE", "1")
    monkeypatch.setenv("Z_SCOPE_RUNTIME_SPEC", "runtime.override.yaml")
    with pytest.raises(ValueError, match="must be an absolute path"):
        ConfigLoader.load(str(config_path))

    override = tmp_path / "runtime.override.yaml"
    override.write_text("runtime_spec_version: 1\nunknown: true\n", encoding="utf-8")
    monkeypatch.setenv("Z_SCOPE_RUNTIME_SPEC", str(override.resolve()))
    with pytest.raises(ValueError, match="runtime.unknown"):
        ConfigLoader.load(str(config_path))
