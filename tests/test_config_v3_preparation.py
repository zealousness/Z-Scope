"""Read-only v3 preparation projection: machine contract and leak/side-effect guards.

All credentials, endpoints, and targets are dummies; nothing here reads a
real key, a personal configuration, or runs a model, indexer, or scan.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from zscope.config.config import ConfigLoader
from zscope.config.preparation import prepare_project
from zscope.config.v3_preparation import prepare_saved_config

FIXED_NOW = datetime(2026, 10, 14, 7, 0, tzinfo=timezone.utc)


def _document() -> dict:
    return {
        "config_version": 3,
        "llms": {
            "default": {
                "base_urls": ["http://dummy-endpoint.invalid/v1"],
                "models": ["dummy-model-name"],
                "api_key": "dummy-api-key-material",
            }
        },
        "project": {
            "language": "c_cpp",
            "platform": "linux_user",
            "semantics_file": "zscope.semantics.yaml",
            "targets": [{"id": "service", "compile_commands": "build/compile_commands.json"}],
        },
        "scan": {
            "preset": "deep",
            "focus": ["memory", "resources", "async_lifecycle"],
            "reproduction": "auto",
        },
        "execution": {"timezone": "Asia/Taipei", "stop_at": "08:00", "max_workers": 4},
    }


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


def _database(root: Path, relative: str, rows: list | None) -> Path:
    """Materialize one compile database; ``rows=None`` writes invalid JSON."""

    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if rows is None:
        path.write_text("{not valid json", encoding="utf-8")
    else:
        path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def _valid_rows(root: Path) -> list:
    return [
        {
            "directory": str(root),
            "file": "unit.c",
            # Distinctive marker: the projection must never expose compile
            # command contents, and this name never matches a real tool.
            "arguments": ["leaky-compiler-marker", "-c", "unit.c"],
        }
    ]


def _materialize_project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    _database(root, "build/compile_commands.json", _valid_rows(root))
    return root


def _iter_keys(value: object):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _iter_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_keys(item)


# --- v2 passthrough ---------------------------------------------------------------


def test_v2_documents_keep_the_existing_preparation_envelope(tmp_path: Path) -> None:
    project = _materialize_project(tmp_path / "proj")
    document = _v2_document()
    # v2 keeps its CWD-relative root semantics; pin an absolute root plus an
    # explicit database so the comparison covers the available-build path.
    document["project"]["compile_commands_path"] = "build/compile_commands.json"
    path = _write(project, document)

    result = prepare_saved_config(str(path))
    expected = prepare_project(ConfigLoader.load(str(path), read_only=True), path)

    assert result == expected
    assert result["schema"] == "zscope.project-preparation.v1"
    assert result["build"]["status"] == "available"
    assert "version3" not in result


def test_invalid_versions_raise_the_existing_loader_error(tmp_path: Path) -> None:
    document = _document()
    document["config_version"] = 4
    path = _write(tmp_path, document)

    with pytest.raises(ValueError, match="config.config_version must be 2 or 3"):
        prepare_saved_config(str(path))


# --- Single target ---------------------------------------------------------------


def test_single_target_adds_version3_fields_to_the_base_envelope(
    tmp_path: Path,
) -> None:
    project = _materialize_project(tmp_path / "proj")
    path = _write(project, _document())

    result = prepare_saved_config(str(path), now=FIXED_NOW)

    # Same base envelope as the shared preparation.
    assert result["schema"] == "zscope.project-preparation.v1"
    assert result["read_only"] is True
    assert result["build"]["status"] == "available"
    assert result["tool_check"] == "executable_presence_only"
    assert all(entry["connection_checked"] is False for entry in result["models"])

    version3 = result["version3"]
    assert version3["schema"] == "zscope.config-v3-preparation.v1"
    assert version3["project_root"] == str(project.resolve())
    assert version3["platform"] == "linux_user"

    target = version3["targets"][0]
    assert target["id"] == "service"
    assert target["compile_commands"] == str(
        (project / "build" / "compile_commands.json").resolve()
    )
    assert target["database_exists"] is True
    assert target["build"]["status"] == "available"

    assert version3["preset"] == {
        "preset": "deep",
        "mapped_depth": "deep",
        "depth_source": "config",
        "mapping_note": version3["preset"]["mapping_note"],
    }
    assert "same execution depth" in version3["preset"]["mapping_note"]
    assert version3["focus"] == ["memory", "resources", "async_lifecycle"]
    assert version3["reproduction"] == "auto"
    assert version3["max_workers"] == 4
    assert version3["execution"]["resolved_stop_time"] == "2026-10-15T08:00:00+08:00"

    assert version3["start_capability"]["startable"] is False
    assert "project_semantics_not_ready" in [item["code"] for item in version3["start_capability"]["reasons"]]
    json.dumps(result)


def test_single_target_with_a_missing_database_is_untested_not_passed(
    tmp_path: Path,
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    document = _document()
    document["project"]["targets"][0]["compile_commands"] = "build/missing.json"
    path = _write(project, document)

    result = prepare_saved_config(str(path), now=FIXED_NOW)

    target = result["version3"]["targets"][0]
    assert target["database_exists"] is False
    assert target["build"]["status"] == "missing"
    codes = [message["code"] for message in target["messages"]]
    assert "compile_commands_missing" in codes

    capability = result["version3"]["start_capability"]
    assert capability["startable"] is False
    assert "compile_commands_missing" in [reason["code"] for reason in capability["reasons"]]


# --- Multi target -----------------------------------------------------------------


def test_multi_target_keeps_every_target_independent_and_refuses_start(
    tmp_path: Path,
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "unit.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    _database(project, "build/one.json", _valid_rows(project))
    _database(project, "build/two.json", None)  # exists but invalid JSON
    # build/three.json is never created: missing file.
    document = _document()
    document["project"]["targets"] = [
        {"id": "alpha", "compile_commands": "build/one.json"},
        {"id": "beta", "compile_commands": "build/two.json"},
        {"id": "gamma", "compile_commands": "build/three.json"},
    ]
    path = _write(project, document)

    result = prepare_saved_config(str(path), now=FIXED_NOW)

    targets = result["version3"]["targets"]
    assert [target["id"] for target in targets] == ["alpha", "beta", "gamma"]
    by_id = {target["id"]: target for target in targets}
    assert by_id["alpha"]["compile_commands"] == str((project / "build" / "one.json").resolve())
    assert by_id["beta"]["compile_commands"] == str((project / "build" / "two.json").resolve())
    assert by_id["gamma"]["compile_commands"] == str((project / "build" / "three.json").resolve())

    assert by_id["alpha"]["database_exists"] is True
    assert by_id["alpha"]["build"]["status"] == "available"
    assert by_id["beta"]["database_exists"] is True
    assert by_id["beta"]["build"]["status"] == "invalid"
    assert "compile_commands_invalid" in [message["code"] for message in by_id["beta"]["messages"]]
    assert by_id["gamma"]["database_exists"] is False
    assert by_id["gamma"]["build"]["status"] == "missing"

    # The document-level build never pretends one target's database is the
    # whole project.
    assert result["build"] == {"status": "multi_target", "link_targets": "unverified"}
    assert all(
        message["code"] not in {"compile_commands_missing", "compile_commands_invalid"}
        for message in result["messages"]
    )

    capability = result["version3"]["start_capability"]
    assert capability["startable"] is False
    assert "multi_target_execution_unwired" in [reason["code"] for reason in capability["reasons"]]
    json.dumps(result)


# --- Java -------------------------------------------------------------------------


def test_java_target_reports_the_database_as_not_applicable(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    document = _document()
    document["project"]["language"] = "java"
    document["project"].pop("semantics_file")
    document["project"]["targets"] = [{"id": "app"}]
    document["scan"]["preset"] = "fast"
    path = _write(project, document)

    result = prepare_saved_config(str(path), now=FIXED_NOW)

    target = result["version3"]["targets"][0]
    assert target["compile_commands"] is None
    # Null means untested/not applicable, never a fake pass or fail.
    assert target["database_exists"] is None
    assert result["build"]["status"] == "not_applicable"
    assert result["project"]["backend"] == "java_unified"
    assert result["version3"]["start_capability"]["startable"] is True


# --- Machine flags ----------------------------------------------------------------


def test_declared_only_fields_are_disclosed_as_not_enabled(tmp_path: Path) -> None:
    project = _materialize_project(tmp_path / "proj")
    path = _write(project, _document())

    result = prepare_saved_config(str(path), now=FIXED_NOW)
    version3 = result["version3"]

    assert version3["machine_flags"] == {
        "focus_wired": False,
        "reproduction_wired": False,
        "max_workers_wired": False,
        "platform_wired": False,
        "stop_window_scheduler_wired": True,
    }
    assert version3["execution"]["scheduler_consumer_wired"] is True
    assert set(version3["declared_not_consumed"]) == {
        "project.platform",
        "scan.focus",
        "scan.reproduction",
        "execution.max_workers",
    }
    states = {note["field"]: note["state"] for note in version3["wiring"]}
    assert states["scan.preset"] == "wired"
    assert states["project.targets"] == "wired"
    assert states["execution.stop_at"] == "wired"
    assert states["scan.focus"] == "declared_only"
    assert states["scan.reproduction"] == "declared_only"
    assert states["execution.max_workers"] == "declared_only"
    assert states["project.platform"] == "declared_only"


# --- Path stability across working directories ------------------------------------


def test_paths_are_stable_across_working_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    project = _materialize_project(tmp_path / "engine")
    document = _document()
    path = _write(project, document)

    elsewhere = tmp_path / "elsewhere-one"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    from_elsewhere = prepare_saved_config(str(path), now=FIXED_NOW)
    monkeypatch.chdir(config_dir)
    from_config_dir = prepare_saved_config(str(path), now=FIXED_NOW)

    assert from_elsewhere["version3"]["project_root"] == str(project.resolve())
    assert from_elsewhere["version3"]["project_root"] == from_config_dir["version3"]["project_root"]
    assert from_elsewhere["version3"]["targets"][0]["compile_commands"] == str(
        (project / "build" / "compile_commands.json").resolve()
    )
    assert from_elsewhere["version3"]["targets"][0]["compile_commands"] == (
        from_config_dir["version3"]["targets"][0]["compile_commands"]
    )
    # Only the informational working_directory legitimately tracks the CWD.
    del from_elsewhere["working_directory"]
    del from_config_dir["working_directory"]
    assert from_elsewhere == from_config_dir


# --- Leak and side-effect guards ----------------------------------------------------


def test_machine_output_leaks_no_credentials_endpoints_or_raw_documents(
    tmp_path: Path,
) -> None:
    project = _materialize_project(tmp_path / "proj")
    path = _write(project, _document())

    result = prepare_saved_config(str(path), now=FIXED_NOW)
    serialized = json.dumps(result, ensure_ascii=False)

    assert "dummy-api-key-material" not in serialized
    assert "dummy-endpoint.invalid" not in serialized
    assert "dummy-model-name" not in serialized
    assert "${" not in serialized
    assert "leaky-compiler-marker" not in serialized  # no compile command contents
    forbidden_keys = {"api_key", "base_urls"}
    assert not (set(_iter_keys(result)) & forbidden_keys)


def test_preparation_is_read_only_with_zero_side_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def prohibited(*args: object, **kwargs: object) -> None:
        raise AssertionError("preparation must not run tools, models, or providers")

    monkeypatch.setattr("subprocess.run", prohibited)
    project = _materialize_project(tmp_path / "proj")
    document = _document()
    document["project"]["targets"] = [
        {"id": "alpha", "compile_commands": "build/compile_commands.json"},
        {"id": "beta", "compile_commands": "build/other.json"},
    ]
    path = _write(project, document)
    before = {item: item.read_bytes() for item in tmp_path.rglob("*") if item.is_file()}

    prepare_saved_config(str(path), now=FIXED_NOW)

    after = {item: item.read_bytes() for item in tmp_path.rglob("*") if item.is_file()}
    assert before == after
    assert not (project / ".zscope_snapshots").exists()
    assert not (project / ".zscope_knowledge").exists()
