from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from zscope.cli.cli import main as zscope_main
from zscope.cli.doctor import main as doctor_main
from zscope.cli.init import main as init_main
from zscope.config.config import ConfigLoader


def _regex_config(root: Path) -> dict:
    return {
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
            "language": "c_cpp",
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


def test_zscope_init_generates_detected_strict_v2_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "CMakeLists.txt").write_text("project(demo C)\n", encoding="utf-8")
    output = tmp_path / "zscope.yaml"
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        init_main,
        [
            "--project-root",
            str(tmp_path),
            "--output",
            str(output),
            "--no-interactive",
        ],
    )

    assert result.exit_code == 0, result.output
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://localhost/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "unit-model")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "unit-key")
    config = ConfigLoader.load(str(output))
    assert config.project.language == "c_cpp"
    assert config.indexing.backend == "unified"
    assert config.concurrency.svf_workers == 2
    assert config.scan.depth == "fast"
    assert "--plan-entries" in result.output


def test_zscope_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    output = tmp_path / "zscope.yaml"
    output.write_text("existing\n", encoding="utf-8")

    result = CliRunner().invoke(
        init_main,
        ["--project-root", str(tmp_path), "--output", str(output), "--no-interactive"],
    )

    assert result.exit_code != 0
    assert output.read_text(encoding="utf-8") == "existing\n"


def test_zscope_init_generates_language_isolated_java_config(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    output = tmp_path / "zscope.yaml"

    result = CliRunner().invoke(
        init_main,
        [
            "--project-root",
            str(tmp_path),
            "--output",
            str(output),
            "--no-interactive",
        ],
    )

    assert result.exit_code == 0, result.output
    raw = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert raw["project"]["language"] == "java"
    assert raw["indexing"]["backend"] == "java_unified"
    assert "compile_commands_path" not in raw["project"]
    assert "svf" not in raw["indexing"]
    assert "svf_workers" not in raw["concurrency"]
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://localhost/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "unit-model")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "unit-key")
    assert ConfigLoader.load(str(output)).project.language == "java"


def test_doctor_checks_only_the_explicit_regex_backend(tmp_path: Path) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(_regex_config(tmp_path)), encoding="utf-8")

    result = CliRunner().invoke(
        doctor_main,
        ["--config", str(path), "--json-output"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["backend"] == "regex"
    names = {item["name"] for item in payload["checks"]}
    assert "runtime-spec" in names
    assert "tool:clangd" not in names
    assert "tool:wpa" not in names


def test_cli_forwards_scan_overrides_to_mcp_server(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(_regex_config(tmp_path)), encoding="utf-8")
    captured = {}

    def fake_run_stdio_server(config_path: str, **kwargs) -> None:
        captured["config_path"] = config_path
        captured.update(kwargs)

    monkeypatch.setattr("zscope.mcp.server.run_stdio_server", fake_run_stdio_server)

    result = CliRunner().invoke(
        zscope_main,
        [
            "--config",
            str(path),
            "--mcp-stdio",
            "--scan-depth",
            "deep",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured == {
        "config_path": str(path),
        "scan_depth": "deep",
    }


def test_plan_entries_builds_index_and_writes_preview_without_llm(tmp_path: Path) -> None:
    include = tmp_path / "include"
    source = tmp_path / "src"
    include.mkdir()
    source.mkdir()
    (include / "api.h").write_text("int api_run(const char *input);\n", encoding="utf-8")
    (source / "api.c").write_text(
        '#include "api.h"\nint api_run(const char *input) { return input ? 0 : -1; }\n',
        encoding="utf-8",
    )
    data = _regex_config(tmp_path)
    data["project"]["include_paths"] = ["include", "src"]
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    result = CliRunner().invoke(
        zscope_main,
        ["--config", str(path), "--plan-entries"],
    )

    assert result.exit_code == 0, result.output
    plan_path = tmp_path / "entry_functions.discovered.json"
    assert plan_path.is_file()
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    assert any(item["function_name"] == "api_run" for item in payload["functions"])
