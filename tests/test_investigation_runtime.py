"""Integration boundaries for the internal, opt-in investigation experiment."""

import json
from pathlib import Path

import pytest

from zscope.config.config import AnalysisConfig, ConfigLoader
from zscope.config.support import load_runtime_spec
from zscope.core.validation.dynamic_reproduction import make_dynamic_reproduction_policy


def _public_config(tmp_path: Path) -> dict:
    return {
        "config_version": 3,
        "llms": {
            "default": {"base_urls": ["http://localhost/v1"], "models": ["fake"], "api_key": "fake"}
        },
        "project": {"targets": [{"id": "main", "compile_commands": "build/compile_commands.json"}], "language": "c_cpp"},
        "scan": {},
        "indexing": {"backend": "regex"},
        "concurrency": {
            key: 1
            for key in (
                "entry_workers",
                "validator_workers",
                "investigator_workers",
                "evidence_completion_workers",
                "index_workers",
                "svf_workers",
                "llm_max_inflight",
            )
        },
    }


def test_shipped_runtime_keeps_investigation_off(monkeypatch):
    monkeypatch.delenv("Z_SCOPE_RUNTIME_SPEC", raising=False)
    config = load_runtime_spec().analysis
    assert config.active_investigation_mode == "off"
    assert config.active_investigation_max_rounds == 4
    assert config.active_investigation_max_scope_extensions == 1
    assert config.active_investigation_timeout_seconds == 120
    assert config.semantic_snapshot_candidate_mode == "off"
    assert config.semantic_model_demand_mode == "off"
    # V01 controlled dynamic reproduction ships inert.
    assert config.dynamic_reproduction_mode == "off"
    assert config.dynamic_reproduction_required_replays == 2
    assert config.dynamic_reproduction_max_replays == 3
    assert config.dynamic_reproduction_timeout_seconds == 30
    assert config.dynamic_reproduction_deadline_seconds == 900
    assert config.dynamic_reproduction_memory_limit_mb == 512
    assert config.dynamic_reproduction_isolation == "process"
    assert make_dynamic_reproduction_policy(load_runtime_spec()).enabled is False


@pytest.mark.parametrize(
    "value",
    ["active", "", "ON", "on ", 1, 0, True, None, {}, []],
)
def test_dynamic_reproduction_mode_never_accepts_untyped_or_unknown_values(value):
    with pytest.raises(ValueError, match="dynamic_reproduction_mode"):
        AnalysisConfig(dynamic_reproduction_mode=value)


@pytest.mark.parametrize("value", ["container", "", "user-net-namespace", 1, None, {}, []])
def test_dynamic_reproduction_isolation_rejects_unknown_boundaries(value):
    with pytest.raises(ValueError, match="dynamic_reproduction_isolation"):
        AnalysisConfig(dynamic_reproduction_isolation=value)


def test_dynamic_reproduction_is_internal_runtime_only(tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime.yaml"
    runtime_path.write_text(
        json.dumps({"runtime_spec_version": 1, "analysis": {"dynamic_reproduction_mode": "on"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("Z_SCOPE_DEVELOPER_MODE", "1")
    monkeypatch.setenv("Z_SCOPE_RUNTIME_SPEC", str(runtime_path))
    assert load_runtime_spec().analysis.dynamic_reproduction_mode == "on"
    monkeypatch.delenv("Z_SCOPE_RUNTIME_SPEC")

    # ... but the mode is never reachable through public project YAML.
    public = _public_config(tmp_path)
    public["scan"]["dynamic_reproduction_mode"] = "on"
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(public), encoding="utf-8")
    with pytest.raises(ValueError):
        ConfigLoader.load(str(path), read_only=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("active_investigation_mode", "active"),
        ("active_investigation_max_rounds", 0),
        ("active_investigation_max_rounds", 5),
        ("active_investigation_max_rounds", True),
        ("active_investigation_max_scope_extensions", 2),
        ("active_investigation_max_scope_extensions", -1),
        ("active_investigation_timeout_seconds", None),
        ("active_investigation_timeout_seconds", 0),
        ("active_investigation_timeout_seconds", float("inf")),
        ("active_investigation_timeout_seconds", float("nan")),
        ("active_investigation_timeout_seconds", True),
        ("dynamic_reproduction_deadline_seconds", 0),
        ("dynamic_reproduction_deadline_seconds", 86401),
        ("dynamic_reproduction_deadline_seconds", True),
        ("dynamic_reproduction_deadline_seconds", None),
    ],
)
def test_investigation_cannot_disable_or_expand_its_hard_bounds(field, value):
    with pytest.raises(ValueError, match=field):
        AnalysisConfig(**{field: value})


def test_developer_override_and_public_config_boundary(tmp_path, monkeypatch):
    override = tmp_path / "runtime.yaml"
    override.write_text(
        json.dumps(
            {
                "runtime_spec_version": 1,
                "analysis": {
                    "active_investigation_mode": "shadow",
                    "active_investigation_max_rounds": 2,
                    "active_investigation_max_scope_extensions": 0,
                    "active_investigation_timeout_seconds": 3.5,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("Z_SCOPE_RUNTIME_SPEC", str(override))
    monkeypatch.delenv("Z_SCOPE_DEVELOPER_MODE", raising=False)
    with pytest.raises(ValueError, match="requires Z_SCOPE_DEVELOPER_MODE"):
        load_runtime_spec()
    monkeypatch.setenv("Z_SCOPE_DEVELOPER_MODE", "1")
    runtime = load_runtime_spec()
    assert runtime.analysis.active_investigation_mode == "shadow"
    assert runtime.analysis.active_investigation_max_rounds == 2
    assert runtime.analysis.active_investigation_max_scope_extensions == 0
    assert runtime.analysis.active_investigation_timeout_seconds == 3.5
    monkeypatch.delenv("Z_SCOPE_RUNTIME_SPEC")
    payload = _public_config(tmp_path)
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert ConfigLoader.load(str(path), read_only=True).scan.depth == "fast"
    payload["scan"]["active_investigation_mode"] = "shadow"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="active_investigation_mode"):
        ConfigLoader.load(str(path), read_only=True)


@pytest.mark.parametrize("name", ["semantic_snapshot_candidate_mode", "semantic_model_demand_mode"])
@pytest.mark.parametrize("value", ["active", "", True, None, 1, {}, []])
def test_semantic_experiments_never_accept_active_or_untyped_modes(name, value):
    with pytest.raises(ValueError, match=name):
        AnalysisConfig(**{name: value})


@pytest.mark.parametrize("name", ["semantic_snapshot_candidate_mode", "semantic_model_demand_mode"])
def test_semantic_shadow_modes_are_internal_runtime_only(name, tmp_path, monkeypatch):
    runtime_path = tmp_path / "runtime.yaml"
    runtime_path.write_text(
        json.dumps({"runtime_spec_version": 1, "analysis": {name: "shadow"}}), encoding="utf-8"
    )
    monkeypatch.setenv("Z_SCOPE_DEVELOPER_MODE", "1")
    monkeypatch.setenv("Z_SCOPE_RUNTIME_SPEC", str(runtime_path))
    assert getattr(load_runtime_spec().analysis, name) == "shadow"
    monkeypatch.delenv("Z_SCOPE_RUNTIME_SPEC")
    public = _public_config(tmp_path)
    public["scan"][name] = "shadow"
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(public), encoding="utf-8")
    with pytest.raises(ValueError, match=name):
        ConfigLoader.load(str(path), read_only=True)
