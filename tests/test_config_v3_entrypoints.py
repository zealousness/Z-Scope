"""U01 entry points: CLI prepare/validate, the v3 initializer, and the shared
config editor service behind the structured Web/MCP editing contract.

All credentials, endpoints, and targets in this module are dummies; nothing
here reads a real key, a personal configuration, or runs a model/scan.  The
CLI checks run through the real command entry points with real files from
deliberately different working directories, and the editor checks exercise
the same-directory validated atomic save the coordinator wires into
``ConfigService``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from zscope.cli.config_cli import main as config_main
from zscope.cli.init import main as init_main
from zscope.config.config import ConfigLoader
from zscope.config.editor import (
    read_structured_document,
    save_document_data,
    save_document_text,
    validate_document_text,
)
from zscope.config.v3 import parse_user_config_v3
from zscope.config.v3_preparation import prepare_saved_config
from zscope.config.user_config_workbook import SHEET_HEADERS, UserConfigWorkbook
from zscope.web.services import ConfigService


def _v3_document(
    *,
    language: str = "c_cpp",
    targets: list | None = None,
    execution: dict | None = None,
) -> dict:
    document: dict = {
        "config_version": 3,
        "llms": {
            "default": {
                "base_urls": ["http://dummy-endpoint.invalid/v1"],
                "models": ["dummy-model-name"],
                "api_key": "dummy-api-key-material",
            }
        },
        "project": {
            "language": language,
            "platform": "linux_user",
            "targets": targets if targets is not None else [{"id": "main"}],
        },
        "scan": {"preset": "fast" if language == "java" else "deep"},
    }
    if language == "c_cpp" and targets is None:
        document["project"]["semantics_file"] = "zscope.semantics.yaml"
        document["project"]["targets"] = [
            {"id": "main", "compile_commands": "build/compile_commands.json"}
        ]
    if execution is not None:
        document["execution"] = execution
    return document


def _v2_document() -> dict:
    return {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://dummy-endpoint.invalid/v1"],
                "models": ["dummy-model-name"],
                "api_key": "dummy-api-key-material",
            }
        },
        "project": {"language": "c_cpp"},
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


def _write(root: Path, data: dict, name: str = "zscope.yaml") -> Path:
    if data.get("project", {}).get("semantics_file"):
        (root / str(data["project"]["semantics_file"])).write_text(
            "schema_version: zscope.project-semantics.v1\n"
            "interfaces: []\n"
            "dispatchers: []\n"
            "function_pointer_bindings: []\n"
            "discovery_receipt: {}\n",
            encoding="utf-8",
        )
    path = root / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _materialize_cpp_project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    (root / "build").mkdir(exist_ok=True)
    (root / "build" / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(root),
                    "file": "unit.c",
                    "arguments": ["dummy-compiler", "-c", "unit.c"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return root


# --- CLI prepare: one shared service, every target, any working directory ---------


def test_cli_prepare_matches_the_web_payload_and_checks_every_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _materialize_cpp_project(tmp_path / "proj")
    document = _v3_document(
        targets=[
            {"id": "alpha", "compile_commands": "build/compile_commands.json"},
            {"id": "beta", "compile_commands": "build/missing.json"},
        ]
    )
    path = _write(project, document)
    monkeypatch.chdir(tmp_path)  # deliberately outside the project directory

    web = ConfigService(path).prepare_project()
    cli = CliRunner().invoke(config_main, ["prepare", "--config", str(path), "--json"])

    assert cli.exit_code == 0, cli.output
    assert json.loads(cli.output) == web
    version3 = web["version3"]
    assert [target["id"] for target in version3["targets"]] == ["alpha", "beta"]
    by_id = {target["id"]: target for target in version3["targets"]}
    assert by_id["alpha"]["build"]["status"] == "available"
    assert by_id["beta"]["build"]["status"] == "missing"
    assert version3["start_capability"]["startable"] is False
    reason_codes = [reason["code"] for reason in version3["start_capability"]["reasons"]]
    assert "multi_target_execution_unwired" in reason_codes
    assert "dummy-api-key-material" not in cli.output
    assert "dummy-endpoint.invalid" not in cli.output


def test_cli_prepare_v3_text_output_names_every_target_and_refuses_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _materialize_cpp_project(tmp_path / "proj")
    document = _v3_document(
        targets=[
            {"id": "alpha", "compile_commands": "build/compile_commands.json"},
            {"id": "beta", "compile_commands": "build/missing.json"},
        ],
        execution={"timezone": "Asia/Taipei", "stop_at": "08:00", "max_workers": 4},
    )
    path = _write(project, document)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(config_main, ["prepare", "--config", str(path)])

    assert result.exit_code == 0, result.output
    output = result.output
    assert "目标 1/2 alpha" in output
    assert "目标 2/2 beta" in output
    assert "存在" in output and "缺失" in output
    assert "预设：deep" in output and "deep" in output
    assert "已声明未消费" in output
    assert "停止边界：Asia/Taipei 08:00 -> " in output
    assert "启动：不可用" in output
    assert "multi_target_execution_unwired" in output
    assert "仅检查本地配置和文件" in output


def test_cli_prepare_v3_single_target_requires_initial_semantic_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _materialize_cpp_project(tmp_path / "proj")
    path = _write(project, _v3_document())
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(config_main, ["prepare", "--config", str(path)])

    assert result.exit_code == 0, result.output
    assert "目标 1/1 main" in result.output
    assert "project_semantics_not_ready" in result.output


def test_cli_prepare_v3_java_has_no_compile_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "service"
    project.mkdir()
    path = _write(project, _v3_document(language="java"))
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(config_main, ["prepare", "--config", str(path), "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    target = payload["version3"]["targets"][0]
    assert target["compile_commands"] is None
    assert target["database_exists"] is None
    assert target["build"]["status"] == "not_applicable"


# --- CLI validate: actual version, validation distinct from execution -------------


def test_cli_validate_v3_multi_target_is_a_valid_document_but_not_startable(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        _v3_document(
            targets=[
                {"id": "alpha", "compile_commands": "build/one.json"},
                {"id": "beta", "compile_commands": "build/two.json"},
            ]
        ),
    )

    result = CliRunner().invoke(config_main, ["validate", "--config", str(path)])

    assert result.exit_code == 0, result.output
    assert "Valid config v3" in result.output
    assert "Valid config v2" not in result.output
    assert "targets=2" in result.output
    assert "target alpha" in result.output and "target beta" in result.output
    assert "Execution: not startable" in result.output
    assert "exactly one" in result.output
    # The document validates, but the public execution chain still refuses it.
    with pytest.raises(ValueError, match="exactly one"):
        ConfigLoader.load(str(path))


def test_cli_validate_v3_single_target_reports_execution_and_unconsumed_fields(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _v3_document())

    result = CliRunner().invoke(config_main, ["validate", "--config", str(path)])

    assert result.exit_code == 0, result.output
    assert "Valid config v3" in result.output
    assert "preset=deep" in result.output
    assert "Execution: composes into the current single-target chain" in result.output
    declared = [line for line in result.output.splitlines() if "Declared, not yet consumed" in line]
    assert declared
    for field in ("scan.focus", "scan.reproduction", "project.platform", "execution.max_workers"):
        assert field in declared[0]


def test_cli_validate_v2_keeps_the_existing_label(tmp_path: Path) -> None:
    path = _write(tmp_path, _v2_document())

    result = CliRunner().invoke(config_main, ["validate", "--config", str(path)])

    assert result.exit_code == 0, result.output
    assert "Valid config v2" in result.output


def test_cli_validate_rejects_unknown_versions(tmp_path: Path) -> None:
    document = _v3_document()
    document["config_version"] = 4
    path = _write(tmp_path, document)

    result = CliRunner().invoke(config_main, ["validate", "--config", str(path)])

    assert result.exit_code != 0
    assert "must be 2 or 3" in result.output


# --- Initializer: strict v3 documents that round-trip from any working directory --


def test_init_round_trips_from_a_different_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _materialize_cpp_project(tmp_path / "engine")
    (project / "CMakeLists.txt").write_text("project(engine C)\n", encoding="utf-8")
    output = project / "zscope.yaml"
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        init_main,
        ["--project-root", str(project), "--output", str(output), "--no-interactive"],
    )

    assert result.exit_code == 0, result.output
    raw = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert raw["config_version"] == 3
    assert "root" not in raw["project"] and "source_root" not in raw["project"]
    assert raw["project"]["semantics_file"] == "zscope.semantics.yaml"
    semantics = yaml.safe_load(
        (project / "zscope.semantics.yaml").read_text(encoding="utf-8")
    )
    assert semantics["schema_version"] == "zscope.project-semantics.v1"
    assert semantics["interfaces"] == []

    third = tmp_path / "third"
    third.mkdir()
    monkeypatch.chdir(third)
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://localhost/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "unit-model")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "unit-key")
    model = parse_user_config_v3(str(output))
    assert model.project.root == project.resolve()
    assert (
        model.project.targets[0].compile_commands
        == (project / "build" / "compile_commands.json").resolve()
    )
    config = ConfigLoader.load(str(output))
    assert (
        config.project.compile_commands_path
        == (project / "build" / "compile_commands.json").resolve()
    )
    assert config.user_config_version == 3


def test_init_refuses_when_only_the_semantics_target_already_exists(
    tmp_path: Path,
) -> None:
    project = _materialize_cpp_project(tmp_path / "engine")
    semantics = project / "zscope.semantics.yaml"
    semantics.write_text("reviewer-owned\n", encoding="utf-8")
    output = project / "zscope.yaml"

    result = CliRunner().invoke(
        init_main,
        ["--project-root", str(project), "--output", str(output), "--no-interactive"],
    )

    assert result.exit_code != 0
    assert "refusing to overwrite" in result.output
    assert not output.exists()
    assert semantics.read_text(encoding="utf-8") == "reviewer-owned\n"


def test_migrate_semantics_preserves_xlsx_and_reports_removed_context(
    tmp_path: Path,
) -> None:
    project = _materialize_cpp_project(tmp_path / "engine")
    document = _v3_document()
    document["project"].pop("semantics_file")
    config = project / "zscope.yaml"
    config.write_text(
        yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    workbook_path = project / "legacy.xlsx"
    rows = {name: [] for name in SHEET_HEADERS}
    rows["resource"] = [
        {
            "symbol_name": "project_alloc",
            "kind": "allocator",
            "symbol_type": "function",
            "pair": "project_free",
            "source": "user",
            "status": "active",
            "contract": '{"carrier":{"kind":"return"},"resource_family":"heap"}',
        },
        {
            "symbol_name": "project_free",
            "kind": "deallocator",
            "symbol_type": "function",
            "source": "user",
            "status": "active",
            "contract": '{"carrier":{"kind":"argument","argument_index":0},"resource_family":"heap"}',
        },
    ]
    rows["module_lifecycle"] = [{"symbol_name": "module_init", "kind": "init"}]
    rows["function_intents"] = [
        {"symbol_name": "parse_input", "intents": "untrusted request"}
    ]
    UserConfigWorkbook(workbook_path).write_rows(rows)
    original = workbook_path.read_bytes()

    result = CliRunner().invoke(
        config_main,
        [
            "migrate-semantics",
            "--config",
            str(config),
            "--from-xlsx",
            str(workbook_path),
            "--output",
            "zscope.semantics.yaml",
        ],
    )

    assert result.exit_code == 0, result.output
    assert workbook_path.read_bytes() == original
    migrated = yaml.safe_load(
        (project / "zscope.semantics.yaml").read_text(encoding="utf-8")
    )
    assert {row["selector"]["name"] for row in migrated["interfaces"]} == {
        "project_alloc",
        "project_free",
    }
    assert all(row["status"] == "pending" for row in migrated["interfaces"])
    assert yaml.safe_load(config.read_text(encoding="utf-8"))["project"][
        "semantics_file"
    ] == "zscope.semantics.yaml"
    report = json.loads(
        (project / "zscope.semantics.migration-report.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["source_preserved"] is True
    assert report["removed"]["module_lifecycle"][0]["symbol_name"] == "module_init"
    assert report["removed"]["function_intents"][0]["symbol_name"] == "parse_input"


def test_init_anchors_root_to_the_config_file_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "engine"
    project.mkdir()
    (project / "CMakeLists.txt").write_text("project(engine C)\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        init_main,
        [
            "--project-root",
            str(project),
            "--output",
            str(project / "conf" / "zscope.yaml"),
            "--no-interactive",
        ],
    )

    assert result.exit_code != 0
    assert "--output must be directly inside --project-root" in result.output
    assert not (project / "conf" / "zscope.yaml").exists()


def test_init_refuses_a_preset_that_the_language_has_not_opened(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>\n", encoding="utf-8")
    output = tmp_path / "zscope.yaml"

    result = CliRunner().invoke(
        init_main,
        [
            "--project-root",
            str(tmp_path),
            "--output",
            str(output),
            "--language",
            "java",
            "--preset",
            "deep",
            "--no-interactive",
        ],
    )

    assert result.exit_code != 0
    assert "not currently available" in result.output
    assert not output.exists()


@pytest.mark.parametrize(
    "dirname",
    [
        "source # preserved",  # '#' would start a YAML comment
        "source: preserved",  # ': ' ends a plain scalar / invalid mapping
        "it's quoted",
        'say "hi"',
        "工程 目录",  # non-ASCII with a space
        "dir:",  # trailing colon ends a plain mapping value
    ],
)
def test_init_preserves_yaml_sensitive_project_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dirname: str
) -> None:
    project = tmp_path / dirname
    project.mkdir()
    (project / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    config = project / "zscope.yaml"
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://dummy-endpoint.invalid/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "dummy-model-name")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "dummy-api-key-material")

    result = CliRunner().invoke(
        init_main,
        [
            "--language",
            "c_cpp",
            "--project-root",
            str(project),
            "--output",
            str(config),
            "--no-interactive",
        ],
    )

    assert result.exit_code == 0, result.output
    # The document must parse as YAML at all (the ': ' name produced invalid
    # YAML before) and resolve back to exactly the requested project.
    model = parse_user_config_v3(str(config))
    assert model.project.root == project.resolve()
    config_loaded = ConfigLoader.load(str(config))
    assert config_loaded.project.project_root == project.resolve()


@pytest.mark.parametrize("dirname", ["100", "true", "null"])
def test_init_handles_numeric_and_boolean_looking_project_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, dirname: str
) -> None:
    # A project directory named 100/true/null sits directly under the config
    # directory, so the root scalar is exactly that name; unquoted it would
    # parse as a number/boolean/null and fail strict parsing.
    project = tmp_path / dirname
    project.mkdir()
    (project / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    config = project / "zscope.yaml"
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://dummy-endpoint.invalid/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "dummy-model-name")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "dummy-api-key-material")

    result = CliRunner().invoke(
        init_main,
        [
            "--language",
            "c_cpp",
            "--project-root",
            str(project),
            "--output",
            str(config),
            "--no-interactive",
        ],
    )

    assert result.exit_code == 0, result.output
    assert parse_user_config_v3(str(config)).project.root == project.resolve()


def test_init_serializes_yaml_sensitive_target_ids(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _materialize_cpp_project(tmp_path / "proj")
    output = project / "zscope.yaml"
    target_id = "svc #1: main"
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://dummy-endpoint.invalid/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "dummy-model-name")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "dummy-api-key-material")

    result = CliRunner().invoke(
        init_main,
        [
            "--project-root",
            str(project),
            "--output",
            str(output),
            "--target-id",
            target_id,
            "--no-interactive",
        ],
    )

    assert result.exit_code == 0, result.output
    model = parse_user_config_v3(str(output))
    assert model.project.targets[0].id == target_id


def test_init_interactive_prompts_preserve_yaml_sensitive_database_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CMakeLists.txt").write_text("project(p C)\n", encoding="utf-8")
    (project / "build").mkdir()
    (project / "build" / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    output = project / "zscope.yaml"
    database = "databases #1: main/commands.json"
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://dummy-endpoint.invalid/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "dummy-model-name")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "dummy-api-key-material")

    result = CliRunner().invoke(
        init_main,
        [
            "--project-root",
            str(project),
            "--output",
            str(output),
            "--interactive",
        ],
        input="\n".join(["c_cpp", "main", database, "deep"]) + "\n",
    )

    assert result.exit_code == 0, result.output
    model = parse_user_config_v3(str(output))
    assert model.project.targets[0].id == "main"
    assert model.project.targets[0].compile_commands == (project / database).resolve()


def test_init_round_trips_a_newline_inside_a_target_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A newline cannot be spelled as a plain YAML scalar at all; the JSON
    # escape keeps the generated document one parseable mapping per line.
    project = _materialize_cpp_project(tmp_path / "proj")
    output = project / "zscope.yaml"
    target_id = "two\nlines"
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://dummy-endpoint.invalid/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "dummy-model-name")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "dummy-api-key-material")

    result = CliRunner().invoke(
        init_main,
        [
            "--project-root",
            str(project),
            "--output",
            str(output),
            "--target-id",
            target_id,
            "--no-interactive",
        ],
    )

    assert result.exit_code == 0, result.output
    assert parse_user_config_v3(str(output)).project.targets[0].id == target_id


def test_v2_and_v3_share_the_same_config_directory_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    v2_path = _write(project, _v2_document(), name="zscope_v2.yaml")
    v3_path = _write(project, _v3_document(), name="zscope.yaml")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    # Both versions preserve the loaded file directory regardless of CWD.
    v2 = ConfigLoader.load(str(v2_path), read_only=True)
    assert v2.project.project_root == project.resolve()
    # The v3 formal model exposes the same computed root.
    assert parse_user_config_v3(str(v3_path)).project.root == project.resolve()


# --- Editor service: original document, actual version, atomic validated save ------


def test_editor_read_projection_keeps_the_original_document(tmp_path: Path) -> None:
    document = _v3_document()
    document["llms"]["wiki_compiler"] = {
        "base_urls": ["${Z_SCOPE_LLM_BASE_URL}"],
        "models": ["${Z_SCOPE_LLM_MODEL}"],
        "api_key": "${Z_SCOPE_API_KEY}",
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(yaml.safe_dump(document, allow_unicode=True, sort_keys=False), encoding="utf-8")

    payload = read_structured_document(path)

    assert payload["config"] == document
    assert payload["config_version"] == 3
    assert payload["language"] == "c_cpp"
    assert payload["config"]["llms"]["wiki_compiler"]["base_urls"] == ["${Z_SCOPE_LLM_BASE_URL}"]


def test_editor_read_projects_an_unconfigured_project_as_empty(tmp_path: Path) -> None:
    assert read_structured_document(tmp_path / "zscope.yaml") == {
        "config": {},
        "config_version": None,
        "language": None,
    }
    empty = tmp_path / "zscope.yaml"
    empty.write_text("\n", encoding="utf-8")
    assert read_structured_document(empty)["config"] == {}


def test_editor_saves_a_multi_target_document_but_execution_still_refuses(
    tmp_path: Path,
) -> None:
    path = _write(tmp_path, _v3_document())
    multi = _v3_document(
        targets=[
            {"id": "alpha", "compile_commands": "build/one.json"},
            {"id": "beta", "compile_commands": "build/two.json"},
        ]
    )
    text = yaml.safe_dump(multi, allow_unicode=True, sort_keys=False)

    result = save_document_text(path, text)

    assert result["success"] is True
    assert path.read_text(encoding="utf-8") == text
    model = parse_user_config_v3(str(path))
    assert [target.id for target in model.project.targets] == ["alpha", "beta"]
    with pytest.raises(ValueError, match="exactly one"):
        ConfigLoader.load(str(path))
    prepared = prepare_saved_config(str(path))
    assert [target["id"] for target in prepared["version3"]["targets"]] == ["alpha", "beta"]
    assert prepared["version3"]["start_capability"]["startable"] is False


def test_editor_invalid_save_never_overwrites_the_saved_file(tmp_path: Path) -> None:
    path = _write(tmp_path, _v3_document())
    before = path.read_bytes()
    invalid = _v3_document()
    invalid["indexing"] = {"backend": "unified"}  # unknown key in the v3 model

    with pytest.raises(ValueError, match="unknown configuration key"):
        save_document_text(path, yaml.safe_dump(invalid, sort_keys=False))

    assert path.read_bytes() == before
    assert not list(tmp_path.glob(".zscope.yaml.tmp-*"))
    assert not list(tmp_path.glob(".zscope-config-editor*"))
    # The same-directory text validation rejects the candidate without any file.
    with pytest.raises(ValueError, match="unknown configuration key"):
        validate_document_text(yaml.safe_dump(invalid, sort_keys=False), config_dir=tmp_path)


def test_editor_validates_v3_candidates_in_the_configuration_directory(tmp_path: Path) -> None:
    # Same-directory candidates preserve the sole project directory.
    document = _v3_document()
    text = yaml.safe_dump(document, sort_keys=False)

    validate_document_text(text, config_dir=tmp_path)

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    # Wrong on purpose: Java targets must not declare a compile database.
    document["project"]["language"] = "java"
    document["scan"]["preset"] = "fast"
    document["project"]["targets"] = [{"id": "main", "compile_commands": "build/db.json"}]
    bad_java = yaml.safe_dump(document, sort_keys=False)
    with pytest.raises(ValueError, match="not valid for Java"):
        validate_document_text(bad_java, config_dir=elsewhere)
    assert not list(elsewhere.glob(".zscope-config-editor*"))


def test_editor_v2_save_keeps_the_current_loader_gate(tmp_path: Path) -> None:
    path = _write(tmp_path, _v2_document())
    updated = _v2_document()
    updated["scan"] = {"task": "ownership"}

    save_document_text(path, yaml.safe_dump(updated, sort_keys=False))

    assert ConfigLoader.load(str(path)).scan.task == "ownership"
    broken = _v2_document()
    broken["concurrency"]["entry_workers"] = 0
    before = path.read_bytes()
    with pytest.raises(ValueError):
        save_document_text(path, yaml.safe_dump(broken, sort_keys=False))
    assert path.read_bytes() == before


def test_editor_structured_save_preserves_profiles_and_env_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("Z_SCOPE_LLM_BASE_URL", "http://localhost/v1")
    monkeypatch.setenv("Z_SCOPE_LLM_MODEL", "unit-model")
    monkeypatch.setenv("Z_SCOPE_API_KEY", "unit-key")
    document = _v3_document()
    document["llms"]["default"] = {
        "base_urls": ["${Z_SCOPE_LLM_BASE_URL}"],
        "models": ["${Z_SCOPE_LLM_MODEL}"],
        "api_key": "${Z_SCOPE_API_KEY}",
    }
    document["llms"]["wiki_compiler"] = dict(document["llms"]["default"])
    path = tmp_path / "zscope.yaml"

    save_document_data(path, document)

    payload = read_structured_document(path)
    assert payload["config"] == document
    assert payload["config_version"] == 3
    model = parse_user_config_v3(str(path))
    assert set(model.llms) == {"default", "wiki_compiler"}
    assert model.llms["wiki_compiler"].base_urls == ["http://localhost/v1"]
