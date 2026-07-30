import json

import pytest

from zscope.config.config import AnalysisConfig, ConfigLoader, LLMConfig


def _base_config(tmp_path):
    return {
        "llms": {
            "default": {
                "model": "unit-model",
                "api_key": "unit-key",
            }
        },
        "project": {
            "root": str(tmp_path),
            "source_root": str(tmp_path),
        },
    }


def test_role_workers_inherit_legacy_parallel_workers() -> None:
    config = AnalysisConfig(parallel_workers=3)

    assert config.parallel_workers == 3
    assert config.entry_workers == 3
    assert config.investigator_workers == 2
    assert config.validator_workers == 4
    assert config.validation_parallel_workers == 4
    assert config.llm_max_inflight == 8
    assert config.validation_cache_entries == 4096


def test_role_workers_override_legacy_parallel_workers() -> None:
    config = AnalysisConfig(
        parallel_workers=3,
        entry_workers=7,
        llm_max_inflight=6,
        validator_workers=4,
        investigator_workers=2,
        validation_cache_entries=512,
    )

    assert config.parallel_workers == 3
    assert config.entry_workers == 7
    assert config.llm_max_inflight == 6
    assert config.validator_workers == 4
    assert config.validation_parallel_workers == 4
    assert config.investigator_workers == 2
    assert config.validation_cache_entries == 512


def test_legacy_nonpositive_llm_limit_maps_to_safe_default() -> None:
    assert AnalysisConfig(llm_max_inflight=0).llm_max_inflight == 8
    assert AnalysisConfig(llm_max_inflight=-1).llm_max_inflight == 8


def test_optional_endpoint_limits_normalize_legacy_sentinels_once() -> None:
    config = LLMConfig(
        base_url_rate_limit_per_minute="unlimited",
        base_url_max_concurrent_requests=-1,
    )

    assert config.base_url_rate_limit_per_minute is None
    assert config.base_url_max_concurrent_requests is None

    with pytest.raises(ValueError, match="Invalid positive integer limit"):
        LLMConfig(base_url_max_concurrent_requests="many")


@pytest.mark.parametrize("sentinel", [None, 0, -1, "unlimited"])
def test_svf_timeout_sentinels_normalize_to_unlimited(sentinel) -> None:
    from zscope.config.config import IndexingConfig

    assert IndexingConfig(svf_timeout=sentinel).svf_timeout is None


def test_explicit_null_deadlines_remain_unlimited() -> None:
    defaults = AnalysisConfig()
    unlimited = AnalysisConfig(
        request_deadline_seconds=None,
        validation_deadline_seconds=None,
        subagent_ticket_timeout=None,
        entry_deadline_seconds=None,
        scan_deadline_seconds=None,
    )

    assert defaults.request_deadline_seconds == 120.0
    assert defaults.validation_deadline_seconds == 240.0
    assert defaults.subagent_ticket_timeout == 300.0
    assert defaults.entry_deadline_seconds == 1800.0
    assert unlimited.request_deadline_seconds is None
    assert unlimited.validation_deadline_seconds is None
    assert unlimited.subagent_ticket_timeout is None
    assert unlimited.entry_deadline_seconds is None
    assert unlimited.scan_deadline_seconds is None


def test_budget_exhaustion_defaults_to_observe_and_normalizes_aliases() -> None:
    assert AnalysisConfig().budget_exhaustion_policy == "observe"
    assert (
        AnalysisConfig(budget_exhaustion_policy="observe-only")
        .budget_exhaustion_policy
        == "observe"
    )
    assert (
        AnalysisConfig(budget_exhaustion_policy="hard")
        .budget_exhaustion_policy
        == "observe"
    )

    with pytest.raises(ValueError, match="budget_exhaustion_policy"):
        AnalysisConfig(budget_exhaustion_policy="discard")


@pytest.mark.parametrize("sentinel", [None, 0, -1, "unlimited", "disabled"])
def test_validation_cache_sentinels_disable_cache(sentinel) -> None:
    assert AnalysisConfig(validation_cache_entries=sentinel).validation_cache_entries == 0


def test_legacy_validation_workers_feed_new_validator_workers() -> None:
    config = AnalysisConfig(
        parallel_workers=4,
        validation_parallel_workers=2,
    )

    assert config.validator_workers == 2
    assert config.validation_parallel_workers == 2


def test_config_loader_parses_role_specific_worker_limits(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["analysis"] = {
        "parallel_workers": 2,
        "entry_workers": 6,
        "llm_max_inflight": 7,
        "validator_workers": 3,
        "investigator_workers": 4,
        "validation_cache_entries": 1024,
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    config = ConfigLoader.load(str(path))

    assert config.analysis.parallel_workers == 2
    assert config.analysis.entry_workers == 6
    assert config.analysis.llm_max_inflight == 7
    assert config.analysis.validator_workers == 3
    assert config.analysis.investigator_workers == 4
    assert config.analysis.validation_cache_entries == 1024


def test_config_loader_parses_budget_exhaustion_policy(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["analysis"] = {
        "entry_deadline_seconds": 60,
        "budget_exhaustion_policy": "cancel",
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    config = ConfigLoader.load(str(path))

    assert config.analysis.entry_deadline_seconds == 60.0
    assert config.analysis.budget_exhaustion_policy == "observe"
