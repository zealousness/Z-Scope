from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from zscope.cli.rules import main as rules_main


def _write_config(root: Path) -> Path:
    config: dict[str, Any] = {
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
        "rules": {"disabled_ids": ["same_pointer_freed_twice"]},
    }
    path = root / "zscope.yaml"
    path.write_text(json.dumps(config), encoding="utf-8")
    return path


def test_rule_list_json_uses_effective_schema_and_filters_engine_and_status(
    tmp_path: Path,
) -> None:
    path = _write_config(tmp_path)
    result = CliRunner().invoke(
        rules_main,
        [
            "list",
            "--config",
            str(path),
            "--language",
            "c_cpp",
            "--engine",
            "cpp_clang_cfg",
            "--status",
            "unavailable",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "zscope.rule-catalog.v2"
    assert payload["language"] == "c_cpp"
    assert payload["backend"] == "regex"
    assert payload["summary"]["total"] > 0
    assert payload["summary"]["total"] == payload["summary"]["unavailable"]
    assert all(row["engine"] == "cpp_clang_cfg" for row in payload["rules"])
    assert all(row["effective_status"] == "unavailable" for row in payload["rules"])
    assert payload["enabled_ids"] == []


def test_rule_list_json_reports_disabled_rule_and_table_has_governance_columns(
    tmp_path: Path,
) -> None:
    path = _write_config(tmp_path)
    runner = CliRunner()

    json_result = runner.invoke(
        rules_main,
        ["list", "--config", str(path), "--status", "disabled", "--json"],
    )
    assert json_result.exit_code == 0, json_result.output
    payload = json.loads(json_result.output)
    assert {"id": "same_pointer_freed_twice", "reason": "disabled_by_config"} in payload["disabled"]
    assert "same_pointer_freed_twice" in {row["id"] for row in payload["rules"]}
    assert any(row["reason"] == "disabled_by_default" for row in payload["disabled"])

    table_result = runner.invoke(
        rules_main,
        ["list", "--config", str(path), "--status", "disabled"],
    )
    assert table_result.exit_code == 0, table_result.output
    assert "ID\tLANGUAGE\tENGINE\tCWE\tSKILL\tREV\tSOURCE\tSTATUS\tREASON" in table_result.output
    assert "same_pointer_freed_twice" in table_result.output
    assert "disabled_by_config" in table_result.output


def test_rule_show_json_resolves_descriptor_and_effective_reason(tmp_path: Path) -> None:
    path = _write_config(tmp_path)
    result = CliRunner().invoke(
        rules_main,
        ["show", "same_pointer_freed_twice", "--config", str(path), "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "zscope.rule-catalog.v2"
    assert len(payload["catalog_sha256"]) == 64
    assert len(payload["effective_sha256"]) == 64
    assert payload["config_valid"] is True
    assert payload["rule"]["id"] == "same_pointer_freed_twice"
    assert payload["rule"]["engine"] == "cpp_regex"
    assert payload["rule"]["skill"] == "temporal_memory"
    assert payload["rule"]["revision"] == 8
    assert payload["rule"]["effective_status"] == "disabled"
    assert payload["rule"]["effective_reason"] == "disabled_by_config"


def test_rule_show_rejects_unknown_id(tmp_path: Path) -> None:
    path = _write_config(tmp_path)
    result = CliRunner().invoke(
        rules_main,
        ["show", "not_registered", "--config", str(path), "--json"],
    )

    assert result.exit_code != 0
    assert "unknown rule id 'not_registered'" in result.output


def test_rule_list_rejects_invalid_engine_without_traceback(tmp_path: Path) -> None:
    path = _write_config(tmp_path)
    result = CliRunner().invoke(
        rules_main,
        ["list", "--config", str(path), "--engine", "bogus"],
    )

    assert result.exit_code != 0
    assert "engine must be one of" in result.output
    assert "Traceback" not in result.output
