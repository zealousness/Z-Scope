"""Synthetic execution-config checks; no benchmark, scorer or answer data runs."""

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from zscope.benchmarking.runner import BenchmarkError, _write_execution_config
from zscope.config.config import ConfigLoader


def _spec(tmp_path):
    source = tmp_path / "template.yaml"
    source.write_text(
        yaml.safe_dump(
            {
                "config_version": 3,
                "llms": {
                    "default": {
                        "base_urls": ["http://dummy.invalid/v1"],
                        "models": ["dummy"],
                        "api_key": "dummy",
                    }
                },
                "project": {
                    "language": "c_cpp",
                    "platform": "linux_user",
                    "semantics_file": "zscope.semantics.yaml",
                    "targets": [{"id": "main", "compile_commands": "build/compile_commands.json"}],
                },
                "scan": {"preset": "fast"},
            }
        ),
        encoding="utf-8",
    )
    return SimpleNamespace(config_path=source, language="c_cpp")


def test_execution_config_uses_its_project_directory_and_preserves_other_runs(tmp_path):
    spec = _spec(tmp_path)
    project = tmp_path / "project with spaces"
    project.mkdir()
    (project / "zscope.semantics.yaml").write_text(
        "schema_version: zscope.project-semantics.v1\n"
        "interfaces: []\n"
        "dispatchers: []\n"
        "function_pointer_bindings: []\n"
        "discovery_receipt: {}\n",
        encoding="utf-8",
    )
    user = project / "zscope.yaml"
    user.write_text("user-owned\n", encoding="utf-8")
    first = project / ".zscope-execution-first.yaml"
    second = project / ".zscope-execution-second.yaml"
    raw = _write_execution_config(spec, project, first)
    _write_execution_config(spec, project, second, scan_depth="deep")
    assert raw["config_version"] == 3
    assert ConfigLoader.load(str(first)).project.project_root == project.resolve()
    assert ConfigLoader.load(str(second)).project.project_root == project.resolve()
    assert yaml.safe_load(first.read_text())["scan"]["preset"] == "fast"
    assert yaml.safe_load(second.read_text())["scan"]["preset"] == "deep"
    assert user.read_text() == "user-owned\n"
    with pytest.raises(FileExistsError):
        _write_execution_config(spec, project, first)
    assert yaml.safe_load(first.read_text())["scan"]["preset"] == "fast"


def test_execution_config_refuses_a_different_project_directory(tmp_path):
    spec = _spec(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "outside.yaml"
    with pytest.raises(BenchmarkError, match="target project directory"):
        _write_execution_config(spec, project, output)
    assert not output.exists()


def test_java_execution_uses_the_same_public_format(tmp_path):
    spec = _spec(tmp_path)
    raw = yaml.safe_load(spec.config_path.read_text())
    raw["project"] = {"language": "java", "targets": [{"id": "app"}]}
    spec.config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    spec.language = "java"
    output = tmp_path / "execution.yaml"
    result = _write_execution_config(spec, tmp_path, output)
    assert result["project"]["entry_functions_list"] == "entries.json"
    assert ConfigLoader.load(str(output), read_only=True).scan.depth == "fast"


def test_execution_generator_rejects_v2_without_writing(tmp_path):
    spec = _spec(tmp_path)
    raw = yaml.safe_load(spec.config_path.read_text())
    raw["config_version"] = 2
    spec.config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    output = tmp_path / "execution.yaml"
    with pytest.raises(BenchmarkError, match="must use public config v3"):
        _write_execution_config(spec, tmp_path, output)
    assert not output.exists()
