import json

import pytest

from zscope.config.config import ConfigLoader, ConcurrencyConfig


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
        "project": {
            "root": str(tmp_path),
            "source_root": ".",
            "language": "c_cpp",
        },
        "scan": {"task": ""},
        "indexing": {"backend": "regex"},
        "concurrency": {
            "entry_workers": 4,
            "validator_workers": 2,
            "investigator_workers": 1,
            "evidence_completion_workers": 2,
            "index_workers": 3,
            "svf_workers": 1,
            "llm_max_inflight": 4,
        },
    }


def test_concurrency_requires_positive_integers() -> None:
    config = ConcurrencyConfig()

    assert config.entry_workers == 4
    assert config.validator_workers == 2
    assert config.investigator_workers == 1
    assert config.evidence_completion_workers == 2
    assert config.index_workers == 4
    assert config.llm_max_inflight == 4

    with pytest.raises(ValueError, match="entry_workers"):
        ConcurrencyConfig(entry_workers=0)


@pytest.mark.parametrize("sentinel", [0, -1, "unlimited", None])
def test_public_concurrency_rejects_inherit_and_unlimited_sentinels(tmp_path, sentinel) -> None:
    data = _base_config(tmp_path)
    data["concurrency"]["llm_max_inflight"] = sentinel
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="concurrency.llm_max_inflight"):
        ConfigLoader.load(str(path))


def test_config_loader_maps_all_role_specific_worker_limits(tmp_path) -> None:
    data = _base_config(tmp_path)
    data["concurrency"] = {
        "entry_workers": 6,
        "validator_workers": 3,
        "investigator_workers": 4,
        "evidence_completion_workers": 5,
        "index_workers": 7,
        "svf_workers": 2,
        "llm_max_inflight": 8,
    }
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    config = ConfigLoader.load(str(path))

    assert config.concurrency == ConcurrencyConfig(**data["concurrency"])
    assert config.indexing.max_clangd_threads == 7


@pytest.mark.parametrize(
    "legacy_field",
    ["parallel_workers", "validation_parallel_workers"],
)
def test_removed_worker_aliases_are_rejected(tmp_path, legacy_field) -> None:
    data = _base_config(tmp_path)
    data["concurrency"][legacy_field] = 2
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match=legacy_field):
        ConfigLoader.load(str(path))


def test_runtime_deadlines_are_internal_defaults(tmp_path) -> None:
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(_base_config(tmp_path)), encoding="utf-8")

    config = ConfigLoader.load(str(path))

    assert config.analysis.request_deadline_seconds == 120.0
    assert config.analysis.validation_deadline_seconds == 600.0
    assert config.analysis.entry_deadline_seconds == 1800.0
    assert config.analysis.budget_exhaustion_policy == "observe"
