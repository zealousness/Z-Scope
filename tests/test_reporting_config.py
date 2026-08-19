import json

import pytest

from zscope.config.config import ConfigLoader, ReportingConfig


def _base_config(tmp_path):
    return {
        "config_version": 2,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unit-model"],
                "api_key": "unit-key",
            }
        },
        "project": {"root": str(tmp_path), "source_root": ".", "language": "c_cpp"},
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


def test_reporting_config_has_no_report_time_dedup_policy() -> None:
    config = ReportingConfig()

    assert not hasattr(config, "semantic_dedup")


def test_reporting_policy_comes_from_bundled_runtime_spec(tmp_path) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(_base_config(tmp_path)), encoding="utf-8")

    config = ConfigLoader.load(str(path))

    assert not hasattr(config.reporting, "semantic_dedup")
    assert config.runtime_provenance.version == 1
    assert len(config.runtime_provenance.sha256) == 64


@pytest.mark.parametrize(
    "removed_block",
    [
        {"reporting": {"semantic_dedup": {"llm_enabled": True}}},
        {"analysis": {"enable_global_model": True}},
        {"analysis": {"proof_providers_v12": False}},
    ],
)
def test_internal_and_rollout_settings_are_not_public_config(tmp_path, removed_block) -> None:
    data = _base_config(tmp_path)
    data.update(removed_block)
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown configuration key"):
        ConfigLoader.load(str(path))
