"""Strict public configuration v3: formal model, parsing, and same-source schema.

All credentials and targets in this module are dummies; nothing here reads a
real key, a personal configuration, or runs a model/scan.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from zscope.config.config import ConfigLoader
from zscope.config.support import LLM_PROFILE_KEYS, load_runtime_spec
from zscope.config.v3 import (
    BLOCKED,
    DECLARED_ONLY,
    EXECUTION_KEYS,
    FOCUS_AREAS,
    LOADER_ENFORCED_CONSTRAINTS,
    PROJECT_KEYS,
    PROJECT_LANGUAGES,
    SCAN_KEYS,
    SCAN_PRESETS,
    TARGET_KEYS,
    V3_SVF_HEAP_LIMIT_MB,
    V3_TOP_LEVEL_KEYS,
    UserConfigV3,
    compose_effective_config,
    parse_user_config_v3,
    public_json_schema,
    resolve_stop_boundary,
)


def _document(**overrides: object) -> dict:
    document: dict = {
        "config_version": 3,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {
            "language": "c_cpp",
            "platform": "linux_user",
            "targets": [{"id": "service", "compile_commands": "build/compile_commands.json"}],
        },
        "scan": {
            "preset": "deep",
            "focus": ["memory", "resources", "async_lifecycle"],
            "reproduction": "auto",
        },
        "execution": {
            "timezone": "Asia/Taipei",
            "stop_at": "08:00",
            "max_workers": 4,
        },
    }
    for section, values in overrides.items():
        if isinstance(values, dict) and isinstance(document.get(section), dict):
            document[section].update(values)
        else:
            document[section] = values
    return document


def _write(root: Path, data: dict, name: str = "zscope.yaml") -> Path:
    path = root / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _v2_document() -> dict:
    return {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
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


# --- Formal model ---------------------------------------------------------------


@pytest.mark.parametrize("language", ["c_cpp", "java"])
@pytest.mark.parametrize("scan", [None, {}])
def test_every_language_defaults_to_fast_and_allows_cli_override(tmp_path, language, scan):
    document = _document()
    document["project"]["language"] = language
    if language == "java":
        document["project"]["targets"] = [{"id": "main"}]
    if scan is None:
        document.pop("scan")
    else:
        document["scan"] = scan
    path = _write(tmp_path, document)
    config = ConfigLoader.load(str(path), read_only=True)
    assert config.scan.depth == "fast"
    assert config.scan.depth_source == "default"
    depth = "deep" if language == "c_cpp" else "fast"
    overridden = ConfigLoader.load(str(path), read_only=True, scan_depth=depth)
    assert overridden.scan.depth == depth
    assert overridden.scan.depth_source == "cli"


def test_cli_override_cannot_bypass_invalid_java_yaml(tmp_path):
    document = _document()
    document["project"].update(language="java", targets=[{"id": "main"}])
    path = _write(tmp_path, document)
    with pytest.raises(ValueError, match="scan.preset 'deep'"):
        ConfigLoader.load(str(path), scan_depth="fast", read_only=True)


def test_full_document_parses_into_the_formal_model(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())
    model = parse_user_config_v3(str(path), now=datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc))

    assert isinstance(model, UserConfigV3)
    assert model.project.root == tmp_path.resolve()
    assert model.project.language == "c_cpp"
    assert model.project.platform == "linux_user"
    assert [target.id for target in model.project.targets] == ["service"]
    assert (
        model.project.targets[0].compile_commands
        == (tmp_path / "build" / "compile_commands.json").resolve()
    )
    assert model.scan.preset == "deep"
    assert model.scan.focus == ("memory", "resources", "async_lifecycle")
    assert model.scan.reproduction == "auto"
    assert model.scan.mapped_depth == "deep"
    assert model.scan.mapped_depth_source == "config"
    assert "same execution depth" in model.scan.mapping_note
    assert "experimental rules remain unchanged" in model.scan.mapping_note
    assert model.execution.timezone == "Asia/Taipei"
    assert model.execution.max_workers == 4
    window = model.execution.stop_window
    assert window is not None
    assert window.timezone == "Asia/Taipei"
    assert window.stop_at == "08:00"
    # 07:00 UTC is 15:00 Taipei, so the next 08:00 local is the next day.
    assert window.resolved_stop_time == datetime(2026, 10, 15, 8, 0, tzinfo=ZoneInfo("Asia/Taipei"))
    assert window.resolved_stop_time.utcoffset() == timedelta(hours=8)


def test_minimal_document_uses_declared_defaults(tmp_path: Path) -> None:
    document = _document()
    del document["scan"]
    del document["execution"]
    path = _write(tmp_path, document)

    model = parse_user_config_v3(str(path), now=datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc))

    assert model.scan.preset == "fast"
    assert model.scan.focus == FOCUS_AREAS
    assert model.scan.reproduction == "auto"
    # A defaulted preset is not an explicit user choice and stays rollout-gateable.
    assert model.scan.mapped_depth_source == "default"
    assert model.scan.mapped_depth == "fast"
    assert model.execution.timezone is None
    assert model.execution.stop_at is None
    assert model.execution.max_workers is None
    assert model.execution.stop_window is None


def test_wiring_notes_list_supported_and_unwired_surfaces(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())
    model = parse_user_config_v3(str(path), now=datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc))

    states = {note.field: note.state for note in model.wiring}
    assert states["llms"] == "wired"
    assert states["config_path"] == "wired"
    assert states["project.language"] == "wired"
    assert states["project.targets"] == "wired"
    assert states["scan.preset"] == "wired"
    assert states["project.platform"] == DECLARED_ONLY
    assert states["scan.focus"] == DECLARED_ONLY
    assert states["scan.reproduction"] == DECLARED_ONLY
    assert states["execution.max_workers"] == DECLARED_ONLY
    assert states["execution.timezone"] == "wired"
    assert states["execution.stop_at"] == "wired"


# --- Path semantics (the intentional v3 change) ---------------------------------


def test_root_resolves_relative_to_the_config_directory_not_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    other_cwd = tmp_path / "elsewhere"
    other_cwd.mkdir()
    path = _write(config_dir, _document())

    monkeypatch.chdir(other_cwd)
    from_other_cwd = parse_user_config_v3(str(path))
    monkeypatch.chdir(config_dir)
    from_config_dir = parse_user_config_v3(str(path))

    assert from_other_cwd.project.root == config_dir.resolve()
    assert from_other_cwd.project.root == from_config_dir.project.root
    assert (
        from_other_cwd.project.targets[0].compile_commands
        == (config_dir / "build" / "compile_commands.json").resolve()
    )


def test_compile_databases_anchor_to_config_directory_or_explicit_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    absolute_database = tmp_path / "external" / "compile_commands.json"
    document = _document()
    document["project"]["targets"] = [
        {"id": "lib", "compile_commands": "build/cc.json"},
        {"id": "hosted", "compile_commands": str(absolute_database)},
    ]
    path = _write(config_dir, document)
    monkeypatch.chdir(tmp_path)

    model = parse_user_config_v3(str(path))

    assert model.project.root == config_dir.resolve()
    by_id = {target.id: target.compile_commands for target in model.project.targets}
    assert by_id["lib"] == (config_dir / "build" / "cc.json").resolve()
    assert by_id["hosted"] == absolute_database.resolve()


def test_v2_is_rejected_before_other_fields(tmp_path: Path) -> None:
    path = _write(tmp_path, _v2_document())
    with pytest.raises(ValueError, match="config.config_version must be 3.*migrate"):
        ConfigLoader.load(str(path), read_only=True)


# --- Composition into the current execution chain -------------------------------


def test_config_loader_composes_a_single_target_v3_document(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    config = ConfigLoader.load(str(path))

    assert config.user_config_version == 3
    assert isinstance(config.user_config_v3, UserConfigV3)
    assert config.user_config_v3.scan.preset == "deep"
    assert config.scan.depth == "deep"
    assert config.scan.depth_source == "config"
    assert config.scan.task == ""
    assert config.project.project_root == tmp_path.resolve()
    assert (
        config.project.compile_commands_path
        == (tmp_path / "build" / "compile_commands.json").resolve()
    )
    assert config.indexing.backend == "unified"
    assert config.indexing.svf_heap_limit_mb == V3_SVF_HEAP_LIMIT_MB
    assert config.llm.models == ["unit-model"]
    assert config.llm.api_key == "unit-key"


def test_read_only_load_skips_rollout_preflight_and_ledger(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    config = ConfigLoader.load(str(path), read_only=True)

    assert config.user_config_version == 3
    assert config.scan_token_usage_ledger is None
    assert config.effective_rules is None


def test_quick_preset_maps_to_fast(tmp_path: Path) -> None:
    document = _document(scan={"preset": "fast"})
    path = _write(tmp_path, document)

    model = parse_user_config_v3(str(path))
    config = ConfigLoader.load(str(path), read_only=True)

    assert model.scan.mapped_depth == "fast"
    assert config.scan.depth == "fast"


def test_cli_depth_override_keeps_working_on_v3_documents(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    config = ConfigLoader.load(str(path), scan_depth="fast")

    assert config.scan.depth == "fast"
    assert config.scan.depth_source == "cli"


def test_java_document_composes_the_java_backend(tmp_path: Path) -> None:
    document = _document()
    document["project"]["language"] = "java"
    document["project"]["targets"] = [{"id": "app"}]
    document["scan"]["preset"] = "fast"
    path = _write(tmp_path, document)

    config = ConfigLoader.load(str(path), read_only=True)

    assert config.project.language == "java"
    assert config.indexing.backend == "java_unified"
    assert config.project.compile_commands_path is None
    assert config.user_config_v3.project.targets[0].compile_commands is None


def test_java_overnight_preset_is_rejected_with_an_explicit_reason(tmp_path: Path) -> None:
    document = _document()
    document["project"]["language"] = "java"
    document["project"]["targets"] = [{"id": "app"}]
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="scan.preset 'deep'.*java.*use 'fast'"):
        parse_user_config_v3(str(path))


def test_preset_does_not_enable_shadow_experiments(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    config = ConfigLoader.load(str(path), read_only=True)
    runtime = load_runtime_spec()

    assert config.analysis.dynamic_reproduction_mode == "off"
    assert config.analysis.dynamic_reproduction_mode == runtime.analysis.dynamic_reproduction_mode
    assert config.analysis.security_semantic_enrichment_mode == (
        runtime.analysis.security_semantic_enrichment_mode
    )
    assert config.analysis.active_investigation_mode == runtime.analysis.active_investigation_mode
    assert config.analysis.semantic_snapshot_candidate_mode == (
        runtime.analysis.semantic_snapshot_candidate_mode
    )
    assert config.analysis.semantic_model_demand_mode == runtime.analysis.semantic_model_demand_mode
    assert config.scan.task == ""  # legacy field untouched by the v3 intent


def test_v3_composition_enables_entry_discovery_for_direct_scans(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())

    config = ConfigLoader.load(str(path), read_only=True)

    assert config.project.entry_function is None
    assert config.project.entry_functions_list is None
    assert config.project.entry_discovery.enabled is True


def test_multi_target_identities_are_retained_and_composition_refuses(
    tmp_path: Path,
) -> None:
    document = _document()
    document["project"]["targets"] = [
        {"id": "service", "compile_commands": "build/one.json"},
        {"id": "tools", "compile_commands": "build/two.json"},
        {"id": "fuzzer", "compile_commands": "build/three.json"},
    ]
    path = _write(tmp_path, document)

    model = parse_user_config_v3(str(path))
    assert [target.id for target in model.project.targets] == ["service", "tools", "fuzzer"]
    assert [target.compile_commands for target in model.project.targets] == [
        (tmp_path / "build" / "one.json").resolve(),
        (tmp_path / "build" / "two.json").resolve(),
        (tmp_path / "build" / "three.json").resolve(),
    ]
    states = {note.field: note.state for note in model.wiring}
    assert states["project.targets"] == BLOCKED

    with pytest.raises(ValueError) as excinfo:
        compose_effective_config(model)
    message = str(excinfo.value)
    assert "exactly one" in message
    assert "3" in message
    assert "service, tools, fuzzer" in message
    assert "Multi-target selection is not wired" in message

    with pytest.raises(ValueError, match="Multi-target selection is not wired"):
        ConfigLoader.load(str(path), read_only=True)


def test_loading_never_modifies_the_user_authored_file(tmp_path: Path) -> None:
    path = _write(tmp_path, _document())
    before = path.read_bytes()

    ConfigLoader.load(str(path), read_only=True)
    parse_user_config_v3(str(path))
    ConfigLoader.load(str(path), scan_depth="fast")

    assert path.read_bytes() == before


def test_environment_expansion_applies_to_v3_documents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("Z_SCOPE_TEST_V3_URL", "http://dummy.example/v1")
    monkeypatch.setenv("Z_SCOPE_TEST_V3_MODEL", "dummy-model")
    monkeypatch.setenv("Z_SCOPE_TEST_V3_KEY", "dummy-key")
    document = _document()
    document["llms"]["default"] = {
        "base_urls": ["${Z_SCOPE_TEST_V3_URL}"],
        "models": ["${Z_SCOPE_TEST_V3_MODEL}"],
        "api_key": "${Z_SCOPE_TEST_V3_KEY}",
    }
    path = _write(tmp_path, document)

    model = parse_user_config_v3(str(path))

    assert model.llms["default"].base_urls == ["http://dummy.example/v1"]
    assert model.llms["default"].models == ["dummy-model"]
    assert model.llms["default"].api_key == "dummy-key"


# --- Strictness -----------------------------------------------------------------


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text(
        "config_version: 3\n"
        "llms:\n"
        "  default:\n"
        "    base_urls: [http://localhost/v1]\n"
        "    models: [unit-model]\n"
        "    api_key: unit-key\n"
        "project:\n"
        "  language: c_cpp\n"
        "  targets:\n"
        "    - id: service\n"
        "      compile_commands: build/cc.json\n"
        "scan:\n"
        "  preset: overnight\n"
        "scan:\n"
        "  preset: quick\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate YAML key 'scan'"):
        parse_user_config_v3(str(path))


@pytest.mark.parametrize(
    ("section", "key"),
    [
        ("project", "source_root"),
        ("project", "compile_commands_path"),
        ("scan", "depth"),
        ("execution", "deadline"),
        ("execution", "stop_after"),
    ],
)
def test_unknown_keys_are_rejected_in_every_section(
    tmp_path: Path, section: str | None, key: str
) -> None:
    document = _document()
    target = document if section is None else document[section]
    target[key] = {} if section is None else "value"
    path = _write(tmp_path, document)

    with pytest.raises(
        ValueError,
        match=(
            f"project.{key} removed"
            if section == "project" and key in {"root", "source_root"}
            else f"unknown configuration key .*{key}"
        ),
    ):
        parse_user_config_v3(str(path))


def test_unknown_llm_profile_field_is_rejected(tmp_path: Path) -> None:
    document = _document()
    document["llms"]["default"]["base_url"] = "http://localhost/v1"
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="unknown configuration key llms.default.base_url"):
        parse_user_config_v3(str(path))


@pytest.mark.parametrize("version", [4, "3", None])
def test_wrong_config_version_is_rejected(tmp_path: Path, version: object) -> None:
    document = _document()
    if version is None:
        del document["config_version"]
    else:
        document["config_version"] = version
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="config.config_version must be 3"):
        ConfigLoader.load(str(path), read_only=True)


def test_v3_document_mislabeled_as_v2_reports_the_offending_section(
    tmp_path: Path,
) -> None:
    document = _document(config_version=2)
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="config.config_version must be 3"):
        ConfigLoader.load(str(path), read_only=True)


@pytest.mark.parametrize(
    ("overrides", "pattern"),
    [
        ({"scan": {"preset": "quick"}}, "scan.preset quick/overnight removed"),
        ({"scan": {"preset": "overnight"}}, "scan.preset quick/overnight removed"),
        ({"scan": {"focus": ["concurrency"]}}, "scan.focus contains unknown area"),
        ({"scan": {"focus": []}}, "scan.focus must not be empty"),
        ({"scan": {"reproduction": "off"}}, "scan.reproduction must be one of: auto"),
        ({"project": {"platform": "windows_user"}}, "project.platform must be one of: linux_user"),
        ({"project": {"language": "python"}}, "project.language must be exactly 'c_cpp' or 'java'"),
    ],
)
def test_value_vocabularies_are_enforced(tmp_path: Path, overrides: dict, pattern: str) -> None:
    document = _document()
    for section, values in overrides.items():
        document[section].update(values)
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match=pattern):
        parse_user_config_v3(str(path))


@pytest.mark.parametrize(
    ("targets", "pattern"),
    [
        (None, "project.targets must be a non-empty list"),
        ([], "project.targets must be a non-empty list"),
        ([{"compile_commands": "build/cc.json"}], "project.targets\\[0\\].id must"),
        (
            [{"id": "a", "compile_commands": "x.json"}, {"id": "a", "compile_commands": "y.json"}],
            "duplicate target id 'a'",
        ),
        ([{"id": "a"}], "compile_commands.*required for C/C\\+\\+"),
    ],
)
def test_target_shapes_are_enforced(tmp_path: Path, targets: object, pattern: str) -> None:
    document = _document()
    if targets is None:
        del document["project"]["targets"]
    else:
        document["project"]["targets"] = targets
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match=pattern):
        parse_user_config_v3(str(path))


def test_java_target_cannot_declare_compile_commands(tmp_path: Path) -> None:
    document = _document()
    document["project"]["language"] = "java"
    document["project"]["targets"] = [{"id": "app", "compile_commands": "build/cc.json"}]
    document["scan"]["preset"] = "fast"
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="compile_commands is not valid for Java"):
        parse_user_config_v3(str(path))


def test_llms_default_profile_is_required(tmp_path: Path) -> None:
    document = _document()
    document["llms"] = {
        "extra": {
            "base_urls": ["http://localhost/v1"],
            "models": ["unit-model"],
            "api_key": "unit-key",
        }
    }
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="llms.default is required"):
        parse_user_config_v3(str(path))


# --- Stop-window resolution -------------------------------------------------------


def test_stop_boundary_resolves_the_next_local_occurrence() -> None:
    taipei = ZoneInfo("Asia/Taipei")

    # 07:00 UTC == 15:00 Taipei: the next 08:00 is tomorrow.
    resolved = resolve_stop_boundary(
        "08:00", taipei, now=datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc)
    )
    assert resolved == datetime(2026, 10, 15, 8, 0, tzinfo=taipei)

    # 22:00 UTC == 06:00 Taipei next day: the next 08:00 is that same local day.
    resolved = resolve_stop_boundary(
        "08:00", taipei, now=datetime(2026, 10, 14, 22, 0, tzinfo=timezone.utc)
    )
    assert resolved == datetime(2026, 10, 15, 8, 0, tzinfo=taipei)

    # Exactly at the boundary means it has passed; the next one is tomorrow.
    resolved = resolve_stop_boundary(
        "08:00", taipei, now=datetime(2026, 10, 15, 0, 0, tzinfo=timezone.utc)
    )
    assert resolved == datetime(2026, 10, 16, 8, 0, tzinfo=taipei)


def test_stop_boundary_rejects_dst_gap_and_fold_conservatively() -> None:
    new_york = ZoneInfo("America/New_York")
    saturday_before_gap = datetime(2027, 3, 13, 16, 0, tzinfo=timezone.utc)  # 11:00 EST

    # 2027-03-14 02:30 does not exist (spring-forward gap).
    with pytest.raises(ValueError, match="does not exist.*daylight-saving gap"):
        resolve_stop_boundary("02:30", new_york, now=saturday_before_gap)

    # 2027-03-14 03:30 exists after the gap.
    assert resolve_stop_boundary("03:30", new_york, now=saturday_before_gap) == datetime(
        2027, 3, 14, 3, 30, tzinfo=new_york
    )

    saturday_before_fold = datetime(2027, 11, 6, 16, 0, tzinfo=timezone.utc)  # 12:00 EDT

    # 2027-11-07 01:30 occurs twice (fall-back fold).
    with pytest.raises(ValueError, match="occurs twice.*daylight-saving fold"):
        resolve_stop_boundary("01:30", new_york, now=saturday_before_fold)

    # 2027-11-07 00:30 is before the fold and stays unique.
    assert resolve_stop_boundary("00:30", new_york, now=saturday_before_fold) == datetime(
        2027, 11, 7, 0, 30, tzinfo=new_york
    )


@pytest.mark.parametrize(
    "stop_at",
    ["8:00", "24:00", "08:0", "08:60", "08:00:00", "0800", "08-00", "prefix08:00suffix"],
)
def test_stop_at_format_is_strict(tmp_path: Path, stop_at: str) -> None:
    document = _document(execution={"stop_at": stop_at})
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="execution.stop_at must be a local 'HH:MM'"):
        parse_user_config_v3(str(path))


@pytest.mark.parametrize("zone", ["Mars/Olympus", "utc+8", "Local"])
def test_unknown_timezones_are_rejected(tmp_path: Path, zone: str) -> None:
    document = _document(execution={"timezone": zone})
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="not a known IANA timezone"):
        parse_user_config_v3(str(path))


def test_stop_at_without_an_explicit_timezone_is_rejected(tmp_path: Path) -> None:
    document = _document()
    del document["execution"]["timezone"]
    path = _write(tmp_path, document)

    with pytest.raises(
        ValueError, match="execution.stop_at requires an explicit execution.timezone"
    ):
        parse_user_config_v3(str(path))


def test_timezone_without_stop_at_is_recorded_but_produces_no_window(
    tmp_path: Path,
) -> None:
    document = _document()
    del document["execution"]["stop_at"]
    path = _write(tmp_path, document)

    model = parse_user_config_v3(str(path))

    assert model.execution.timezone == "Asia/Taipei"
    assert model.execution.stop_window is None
    states = {note.field: note.state for note in model.wiring}
    assert states["execution.timezone"] == DECLARED_ONLY
    assert states["execution.stop_at"] == DECLARED_ONLY


def test_naive_now_is_rejected_for_boundary_resolution() -> None:
    with pytest.raises(ValueError, match="timezone-aware 'now'"):
        resolve_stop_boundary("08:00", ZoneInfo("Asia/Taipei"), now=datetime(2026, 10, 14, 7, 0))


# --- Same-source schema ------------------------------------------------------------


def test_json_schema_is_generated_from_the_parsing_model() -> None:
    schema = public_json_schema()

    assert set(schema["properties"]) == set(V3_TOP_LEVEL_KEYS)
    assert schema["properties"]["config_version"]["const"] == 3
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"config_version", "llms", "project"}

    project = schema["properties"]["project"]
    assert set(project["properties"]) == set(PROJECT_KEYS)
    assert set(project["required"]) == {"language", "targets"}
    assert project["properties"]["language"]["enum"] == ["c_cpp", "java"]
    assert project["properties"]["platform"]["enum"] == ["linux_user"]

    target = project["properties"]["targets"]["items"]
    assert set(target["properties"]) == set(TARGET_KEYS)
    assert set(target["required"]) == {"id"}

    scan = schema["properties"]["scan"]
    assert set(scan["properties"]) == set(SCAN_KEYS)
    assert scan["properties"]["preset"]["enum"] == list(SCAN_PRESETS)
    assert scan["properties"]["focus"]["items"]["enum"] == list(FOCUS_AREAS)
    assert scan["properties"]["reproduction"]["enum"] == ["auto"]

    execution = schema["properties"]["execution"]
    assert set(execution["properties"]) == set(EXECUTION_KEYS)

    profile = schema["properties"]["llms"]["additionalProperties"]
    assert set(profile["properties"]) == set(LLM_PROFILE_KEYS)
    assert set(profile["required"]) == {"base_urls", "models", "api_key"}

    # The emitted document must stay valid, serializable JSON.
    json.dumps(schema)


def test_schema_key_tables_expose_the_parser_key_tables() -> None:
    schema = public_json_schema()

    # Every key the schema advertises is accepted by the parser (the full
    # document above already loads), and the unknown-key tests cover the
    # reverse direction.  This guard keeps the key tables from drifting when
    # a field is added to one side only; it deliberately does NOT claim full
    # semantic equivalence — the cross-field and value-level correspondences
    # have their own tests below, and loader-only semantics are disclosed in
    # x-loader-enforced-constraints.
    for section_keys, properties in (
        (V3_TOP_LEVEL_KEYS, schema["properties"]),
        (PROJECT_KEYS, schema["properties"]["project"]["properties"]),
        (
            TARGET_KEYS,
            schema["properties"]["project"]["properties"]["targets"]["items"]["properties"],
        ),
        (SCAN_KEYS, schema["properties"]["scan"]["properties"]),
        (EXECUTION_KEYS, schema["properties"]["execution"]["properties"]),
        (LLM_PROFILE_KEYS, schema["properties"]["llms"]["additionalProperties"]["properties"]),
    ):
        assert set(section_keys) == set(properties)


# --- Parser/schema behavioral correspondence (review drift fixes) -----------------


def test_stop_at_schema_pattern_is_a_full_string_match_like_the_parser() -> None:
    schema = public_json_schema()
    pattern = schema["properties"]["execution"]["properties"]["stop_at"]["pattern"]

    # JSON Schema `pattern` is an unanchored search, so the emitted pattern
    # must carry its own anchors to mirror the parser's fullmatch.
    assert pattern.startswith("^") and pattern.endswith("$")

    # Mirror JSON Schema search semantics with re.search: values the parser
    # rejects must fail the schema pattern, and values it accepts must pass.
    rejected = ["prefix08:00suffix", "08:00suffix", "prefix08:00", "8:00", "24:00"]
    for value in rejected:
        assert re.search(pattern, value) is None, value

    accepted = ["08:00", "23:59", "00:00", " 08:00 ", "\t07:30\n"]
    for value in accepted:
        assert re.search(pattern, value) is not None, value


def test_stop_at_surrounding_whitespace_is_normalized_like_the_schema_margins(
    tmp_path: Path,
) -> None:
    # _string strips before the fullmatch check, so the schema pattern keeps
    # \s* margins; both sides accept the padded value and normalize it.
    document = _document(execution={"stop_at": " 08:00 "})
    path = _write(tmp_path, document)

    model = parse_user_config_v3(str(path), now=datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc))

    assert model.execution.stop_at == "08:00"
    assert model.execution.stop_window is not None
    assert model.execution.stop_window.stop_at == "08:00"
    assert model.execution.stop_window.resolved_stop_time == datetime(
        2026, 10, 15, 8, 0, tzinfo=ZoneInfo("Asia/Taipei")
    )


def test_focus_duplicates_are_normalized_and_the_schema_declares_it(
    tmp_path: Path,
) -> None:
    schema = public_json_schema()
    focus_schema = schema["properties"]["scan"]["properties"]["focus"]

    # Chosen contract: keep the loader's declared normalization (order-
    # preserving deduplication) and let the schema say so instead of
    # claiming uniqueItems, which the loader does not enforce.
    assert "uniqueItems" not in focus_schema
    assert "dedup" in focus_schema["description"]

    document = _document(scan={"focus": ["memory", "memory", "resources", "memory"]})
    path = _write(tmp_path, document)

    model = parse_user_config_v3(str(path))
    assert model.scan.focus == ("memory", "resources")


def test_schema_requires_timezone_when_stop_at_is_present(tmp_path: Path) -> None:
    schema = public_json_schema()
    execution = schema["properties"]["execution"]

    assert execution["dependentRequired"] == {"stop_at": ["timezone"]}

    # Parser side of the same dependency (schema shape, loader message).
    document = _document()
    del document["execution"]["timezone"]
    path = _write(tmp_path, document)
    with pytest.raises(ValueError, match="requires an explicit execution.timezone"):
        parse_user_config_v3(str(path))


def test_target_database_rules_are_language_conditional_in_schema_and_parser(
    tmp_path: Path,
) -> None:
    schema = public_json_schema()
    project = schema["properties"]["project"]

    branches = {
        branch["if"]["properties"]["language"]["const"]: branch for branch in project["allOf"]
    }
    assert set(branches) == set(PROJECT_LANGUAGES)

    cpp_then = branches["c_cpp"]["then"]["properties"]["targets"]["items"]
    assert cpp_then["required"] == ["id", "compile_commands"]

    java_then = branches["java"]["then"]["properties"]["targets"]["items"]
    assert java_then["properties"]["compile_commands"] is False

    # Parser parity in both directions.
    cpp_document = _document()
    cpp_document["project"]["targets"] = [{"id": "app"}]
    cpp_path = _write(tmp_path, cpp_document, name="cpp.yaml")
    with pytest.raises(ValueError, match="compile_commands is required for C/C\\+\\+"):
        parse_user_config_v3(str(cpp_path))

    java_document = _document()
    java_document["project"]["language"] = "java"
    java_document["project"]["targets"] = [{"id": "app", "compile_commands": "cc.json"}]
    java_document["scan"]["preset"] = "fast"
    java_path = _write(tmp_path, java_document, name="java.yaml")
    with pytest.raises(ValueError, match="compile_commands is not valid for Java"):
        parse_user_config_v3(str(java_path))


def test_preset_availability_is_language_gated_in_schema_and_parser(
    tmp_path: Path,
) -> None:
    schema = public_json_schema()
    branches = schema["allOf"]

    # Only java is gated by the current mapping tables; c_cpp keeps every
    # preset, so no c_cpp branch is generated.
    assert len(branches) == 1
    branch = branches[0]
    assert branch["if"]["properties"]["project"]["properties"]["language"]["const"] == "java"
    # The shared fast default is valid for Java, including an omitted scan.
    assert "required" not in branch["then"]
    assert "required" not in branch["then"]["properties"]["scan"]
    assert branch["then"]["properties"]["scan"]["properties"]["preset"]["enum"] == ["fast"]

    # Parser parity: Java also defaults to fast.
    document = _document()
    document["project"]["language"] = "java"
    document["project"]["targets"] = [{"id": "app"}]
    del document["scan"]
    path = _write(tmp_path, document)
    assert parse_user_config_v3(str(path)).scan.preset == "fast"

    # And the schema-allowed explicit choice loads.
    document["scan"] = {"preset": "fast"}
    path = _write(tmp_path, document)
    assert parse_user_config_v3(str(path)).scan.preset == "fast"


def test_loader_enforced_constraints_are_disclosed_in_the_schema() -> None:
    schema = public_json_schema()

    assert schema["x-loader-enforced-constraints"] == list(LOADER_ENFORCED_CONSTRAINTS)
    # The schema must not claim full semantic coverage.
    assert "not guaranteed to load" in schema["description"]
    # Runtime-only semantics named by the review: IANA validity, DST
    # ambiguity, cross-item target id uniqueness.
    joined = "\n".join(LOADER_ENFORCED_CONSTRAINTS)
    assert "IANA" in joined
    assert "daylight-saving" in joined
    assert "unique across the list" in joined


def test_non_empty_string_fields_declare_min_length_and_the_parser_agrees(
    tmp_path: Path,
) -> None:
    schema = public_json_schema()

    fields = [
        schema["properties"]["project"]["properties"]["targets"]["items"]["properties"][
            "compile_commands"
        ],
        schema["properties"]["execution"]["properties"]["timezone"],
        schema["properties"]["llms"]["additionalProperties"]["properties"]["api_key"],
        schema["properties"]["llms"]["additionalProperties"]["properties"]["base_urls"]["items"],
        schema["properties"]["llms"]["additionalProperties"]["properties"]["models"]["items"],
    ]
    for field in fields:
        assert field.get("minLength") == 1, field
    assert schema["properties"]["llms"]["propertyNames"] == {"minLength": 1}

    # Parser parity for the same class: empty strings are rejected.
    empty_key = _document()
    empty_key["llms"]["default"]["api_key"] = ""
    path = _write(tmp_path, empty_key, name="empty-key.yaml")
    with pytest.raises(ValueError, match="llms.default.api_key must not be empty"):
        parse_user_config_v3(str(path))

    empty_root = _document()
    empty_root["project"]["root"] = ""
    path = _write(tmp_path, empty_root, name="empty-root.yaml")
    with pytest.raises(ValueError, match="project.root removed"):
        parse_user_config_v3(str(path))
