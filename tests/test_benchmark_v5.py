from __future__ import annotations

from copy import deepcopy

import pytest

from tests.test_truth_contract_v2 import truth_v16
from zscope.benchmarking.benchmark_v5 import (
    BENCHMARK_V5_SCHEMA_VERSION,
    FORMAL_BENCHMARK_V4_SCHEMA_VERSION,
    BenchmarkV5Error,
    _sha256_value,
    aggregate_benchmark_v5,
    load_benchmark_v5_policy,
    load_defect_taxonomy,
    score_benchmark_v5,
)


def _report(*, components: bool = False) -> dict:
    confirmed = {
        "category": "memory_leak",
        "function": "f_10",
        "location": "src/demo.c:10",
        "description": "resource is not released",
    }
    needs_review = {
        "category": "memory_leak",
        "function": "f_20",
        "location": "src/demo.c:20",
        "description": "caller contract remains open",
        "needs_review": True,
    }
    metadata = {
        "source_loc": 1000,
        "wall_time_seconds": 12.5,
        "llm_usage": {
            "total_tokens": 1000,
            "by_agent": {"proof_engine": {"total_tokens": 1000}},
            "by_stage": {"V1": {"total_tokens": 1000}},
            "provider_usage_coverage": 1.0,
            "token_conservation": True,
        },
    }
    if components:
        metadata["benchmark_v5_components"] = {
            "security_spec_mining": {"status": "available", "scope_accuracy": 1.0},
            "hypothesis_hunting": {"status": "available", "exclusive_tp": 1},
            "proof_engine": {
                "status": "available",
                "certificate_replay_rate": 1.0,
                "false_acceptance_count": 0,
                "trace_completeness": 1.0,
            },
        }
    return {
        "issues": [confirmed],
        "report_views": {
            "default": {"issues": [confirmed]},
            "with_needs_review": {"issues": [confirmed, needs_review]},
        },
        "metadata": metadata,
    }


def _pairs() -> dict:
    return {
        "T-1": {"vulnerable_alerted": True, "fixed_alerted": False},
        "T-2": {"vulnerable_alerted": True, "fixed_alerted": False},
    }


def _attestation() -> dict:
    value = {
        "schema_version": "zscope.e0-attestation.v1",
        "workflow": {
            "path": ".github/workflows/range-v16-benchmark-v5-attestation.yml",
            "run_id": "123",
            "head_sha": "a" * 40,
        },
        "invariants": {
            "matcher_v2_unchanged": True,
            "scanner_answer_isolated": True,
        },
        "content_sha256": "",
    }
    unsigned = dict(value)
    unsigned.pop("content_sha256")
    value["content_sha256"] = _sha256_value(unsigned)
    return value


def test_benchmark_v5_reuses_matcher_v2_and_separates_pattern_models() -> None:
    score = score_benchmark_v5(_report(), truth_v16())
    assert score["schema_version"] == BENCHMARK_V5_SCHEMA_VERSION
    assert score["scoring_contract"]["matcher_version"] == "zscope.truth-matcher.v2"
    assert score["product"]["default"]["ground_truth_count"] == 2
    assert score["product"]["default"]["true_positives"] == 1
    assert score["product"]["with_needs_review"]["true_positives"] == 2
    assert score["truth_contract"]["pattern_model_count"] == 1
    assert score["safe_pairs"]["status"] == "not_available"


def test_benchmark_v5_policy_has_no_runtime_token_limit_and_taxonomy_matches_v2() -> None:
    policy = load_benchmark_v5_policy()
    taxonomy = load_defect_taxonomy()
    assert policy["cost_contract"]["runtime_token_limit"] is False
    assert "per_run_tokens" not in policy["quality_gates"]
    assert taxonomy["matcher_version"] == "zscope.truth-matcher.v2"


def test_formal_v5_fails_closed_without_component_or_pair_metrics() -> None:
    with pytest.raises(BenchmarkV5Error, match="component metrics"):
        score_benchmark_v5(_report(), truth_v16(), pair_results=_pairs(), formal=True)
    with pytest.raises(BenchmarkV5Error, match="safe-pair"):
        score_benchmark_v5(_report(components=True), truth_v16(), formal=True)


def test_formal_v4_requires_five_component_complete_trials_and_attestation() -> None:
    score = score_benchmark_v5(
        _report(components=True), truth_v16(), pair_results=_pairs(), formal=True
    )
    trials = []
    for index in range(5):
        trial = deepcopy(score)
        trial["cost"]["total_tokens"] += index
        trials.append(trial)
    aggregate = aggregate_benchmark_v5(
        trials,
        e0_attestation=_attestation(),
        trusted_workflow_run_id="123",
        trusted_head_sha="a" * 40,
    )
    assert aggregate["schema_version"] == FORMAL_BENCHMARK_V4_SCHEMA_VERSION
    assert aggregate["trial_count"] == 5
    assert aggregate["cost"]["runtime_token_limit_applied"] is False
    with pytest.raises(BenchmarkV5Error, match="run identity"):
        aggregate_benchmark_v5(
            trials,
            e0_attestation=_attestation(),
            trusted_workflow_run_id="self-asserted",
            trusted_head_sha="a" * 40,
        )
