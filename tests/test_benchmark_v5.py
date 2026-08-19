from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from tests.test_truth_contract_v2 import truth_v16
from scripts.score_range_v5 import _load
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
            "security_spec_mining": {
                "status": "available",
                "atomic_clause_precision": 1.0,
                "atomic_clause_recall": 1.0,
                "scope_accuracy": 1.0,
                "overgeneralization_rate": 0.0,
                "evidence_parse_rate": 1.0,
                "compiler_acceptance_rate": 1.0,
            },
            "hypothesis_hunting": {
                "status": "available",
                "attack_surface_coverage": 1.0,
                "valid_hypothesis_rate": 1.0,
                "exclusive_confirmed_tp": 1,
                "wrong_family_rate": 0.0,
                "wrong_subject_rate": 0.0,
                "wrong_sink_rate": 0.0,
                "wrong_region_rate": 0.0,
                "tokens_per_exclusive_tp": 100.0,
            },
            "proof_engine": {
                "status": "available",
                "certificate_replay_rate": 1.0,
                "tamper_rejection_rate": 1.0,
                "false_acceptance_count": 0,
                "clause_closure_rate": 1.0,
                "unknown_conflict_rate": 0.0,
                "confirmed_certificate_coverage": 1.0,
                "post_proof_extra_calls": 0,
                "trace_completeness": 1.0,
            },
        }
    return {
        "answer_material_present": False,
        "issues": [confirmed],
        "run_manifest": {"finding_root_projection": {"schema_version": "zscope.finding-root.v2"}},
        "report_views": {
            "default": {"issues": [confirmed]},
            "with_needs_review": {"issues": [confirmed, needs_review]},
        },
        "metadata": metadata,
    }


def _pairs(*, formal: bool = False) -> dict:
    if formal:
        truth = truth_v16()
        result = {}
        for record in truth["vulnerabilities"][:2]:
            truth_id = record["id"]
            pair = record["verification_contract"]["safe_pair"]
            result[truth_id] = {
                "schema_version": "zscope.safe-pair-result.v1",
                "pair_uid": pair["pair_uid"],
                "pair_manifest_sha256": pair["manifest_sha256"],
                "answer_material_present": False,
                "vulnerable": {
                    "alerted": True,
                    "source_sha256": pair["vulnerable_sha256"],
                    "report_sha256": "a" * 64,
                },
                "fixed_or_near_miss": {
                    "alerted": False,
                    "source_sha256": pair["fixed_or_near_miss_sha256"],
                    "report_sha256": "b" * 64,
                },
            }
        return result
    return {
        "T-1": {"vulnerable_alerted": True, "fixed_alerted": False},
        "T-2": {"vulnerable_alerted": True, "fixed_alerted": False},
    }


def _attestation(score: dict) -> dict:
    bindings = score["artifact_bindings"]
    value = {
        "schema_version": "zscope.e0-attestation.v1",
        "issued_at": "2026-08-18T00:00:00+00:00",
        "workflow": {
            "path": ".github/workflows/range-v16-benchmark-v5-attestation.yml",
            "run_id": "123",
            "head_sha": "a" * 40,
            "environment": "sealed-benchmark",
        },
        "component_commits": {
            "governance": "b" * 40,
            "scorer": "c" * 40,
            "truth": "a" * 40,
        },
        "artifacts": {
            "truth_v16": "1" * 64,
            "truth_v16_content": bindings["truth_v16_content"],
            "truth_contract_manifest": bindings["truth_contract_manifest"],
            "truth_manifest": "2" * 64,
            "source_truth_v15": "7" * 64,
            "review_packet_catalog": "8" * 64,
            "review_packet_catalog_content": "9" * 64,
            "normalized_decisions": "a" * 64,
            "normalized_decisions_content": "b" * 64,
            "safe_pair_author_manifest": "c" * 64,
            "safe_pair_author_content": "d" * 64,
            "safe_pair_author_artifact": "e" * 64,
            "review_bundle": "3" * 64,
            "review_bundle_content": bindings["review_bundle_content"],
            "review_provenance": "4" * 64,
            "safe_pair_manifest": "5" * 64,
            "defect_taxonomy": bindings["defect_taxonomy"],
            "benchmark_policy": bindings["benchmark_policy"],
            "scorer_bundle": bindings["scorer_bundle"],
        },
        "review_summary": {
            "record_count": 136,
            "dual_review_count": 136,
            "opus_review_count": 9,
            "disputed_opus_count": 9,
        },
        "invariants": {
            "matcher_v2_unchanged": True,
            "v15_read_only": True,
            "safe_units_cover_confirmable_truth": True,
            "scanner_answer_isolated": True,
            "raw_reviews_artifact_only": True,
            "product_runtime_unchanged": True,
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
    assert score["design_risk"]["with_needs_review"]["truth_count"] == 1
    assert set(score["product"]["default"]["macro"]) == {
        "project",
        "cwe",
        "contract",
        "defect_taxonomy",
    }
    paired = score_benchmark_v5(_report(), truth_v16(), pair_results=_pairs())
    assert paired["safe_pairs"]["safe_entry_alert_rate"] == 0.0
    assert paired["safe_pairs"]["formal_bindings_verified"] is False


def test_benchmark_v5_policy_has_no_runtime_token_limit_and_taxonomy_matches_v2() -> None:
    policy = load_benchmark_v5_policy()
    taxonomy = load_defect_taxonomy()
    assert policy["cost_contract"]["runtime_token_limit"] is False
    assert "per_run_tokens" not in policy["quality_gates"]
    assert taxonomy["matcher_version"] == "zscope.truth-matcher.v2"


def test_formal_v5_fails_closed_without_component_or_pair_metrics() -> None:
    with pytest.raises(BenchmarkV5Error, match="component metrics"):
        score_benchmark_v5(_report(), truth_v16(), pair_results=_pairs(formal=True), formal=True)
    with pytest.raises(BenchmarkV5Error, match="safe-pair"):
        score_benchmark_v5(_report(components=True), truth_v16(), formal=True)


def test_formal_v4_requires_five_component_complete_trials_and_attestation() -> None:
    score = score_benchmark_v5(
        _report(components=True), truth_v16(), pair_results=_pairs(formal=True), formal=True
    )
    trials = []
    for index in range(5):
        trial = deepcopy(score)
        trial["cost"]["total_tokens"] += index
        trial["cost"]["tokens_per_kloc"] += index
        trial["cost"]["tokens_per_confirmed_tp"] += index
        trial["cost"]["usage_by_agent"]["proof_engine"]["total_tokens"] += index
        trial["cost"]["usage_by_stage"]["V1"]["total_tokens"] += index
        unsigned_trial = dict(trial)
        unsigned_trial.pop("score_sha256")
        trial["score_sha256"] = _sha256_value(unsigned_trial)
        trials.append(trial)
    aggregate = aggregate_benchmark_v5(
        trials,
        e0_attestation=_attestation(score),
        trusted_workflow_run_id="123",
        trusted_head_sha="a" * 40,
        baseline_actionable_precision=1.0,
    )
    assert aggregate["schema_version"] == FORMAL_BENCHMARK_V4_SCHEMA_VERSION
    assert aggregate["trial_count"] == 5
    assert aggregate["cost"]["runtime_token_limit_applied"] is False
    assert aggregate["quality"]["default"]["recall"]["median"] == 0.5
    assert aggregate["quality"]["with_needs_review"]["recall"]["median"] == 1.0
    assert aggregate["cost"]["total_tokens"]["median"] == 1002
    assert aggregate["components"]["proof_engine"]["certificate_replay_rate"]["median"] == 1.0
    assert aggregate["policy_evaluation"]["status"] == "failed"
    assert aggregate["policy_evaluation"]["gates"]["confirmed_recall"]["passed"] is False
    with pytest.raises(BenchmarkV5Error, match="run identity"):
        aggregate_benchmark_v5(
            trials,
            e0_attestation=_attestation(score),
            trusted_workflow_run_id="self-asserted",
            trusted_head_sha="a" * 40,
            baseline_actionable_precision=1.0,
        )
    wrong_truth = _attestation(score)
    wrong_truth["artifacts"]["truth_v16_content"] = "f" * 64
    unsigned = dict(wrong_truth)
    unsigned.pop("content_sha256")
    wrong_truth["content_sha256"] = _sha256_value(unsigned)
    with pytest.raises(BenchmarkV5Error, match="truth_v16_content"):
        aggregate_benchmark_v5(
            trials,
            e0_attestation=wrong_truth,
            trusted_workflow_run_id="123",
            trusted_head_sha="a" * 40,
            baseline_actionable_precision=1.0,
        )


def test_formal_v5_rejects_unbound_pair_or_incomplete_component() -> None:
    report = _report(components=True)
    report["metadata"]["benchmark_v5_components"]["proof_engine"].pop("tamper_rejection_rate")
    with pytest.raises(BenchmarkV5Error, match="component metrics"):
        score_benchmark_v5(report, truth_v16(), pair_results=_pairs(formal=True), formal=True)

    pairs = _pairs(formal=True)
    pairs["T-1"]["vulnerable"]["source_sha256"] = "f" * 64
    with pytest.raises(BenchmarkV5Error, match="source/report binding"):
        score_benchmark_v5(_report(components=True), truth_v16(), pair_results=pairs, formal=True)


def test_formal_v5_rejects_answer_or_telemetry_gaps_and_trial_tampering() -> None:
    report = _report(components=True)
    report["answer_material_present"] = True
    with pytest.raises(BenchmarkV5Error, match="answer-isolated"):
        score_benchmark_v5(report, truth_v16(), pair_results=_pairs(formal=True), formal=True)

    report = _report(components=True)
    report["metadata"]["llm_usage"]["provider_usage_coverage"] = 0.99
    with pytest.raises(BenchmarkV5Error, match="provider/token telemetry"):
        score_benchmark_v5(report, truth_v16(), pair_results=_pairs(formal=True), formal=True)

    report = _report(components=True)
    report["metadata"]["llm_usage"]["by_agent"]["proof_engine"]["total_tokens"] = 999
    with pytest.raises(BenchmarkV5Error, match="token dimensions"):
        score_benchmark_v5(report, truth_v16(), pair_results=_pairs(formal=True), formal=True)

    report = _report(components=True)
    report["run_manifest"]["finding_root_projection"]["schema_version"] = "legacy"
    with pytest.raises(BenchmarkV5Error, match="Finding-root v2"):
        score_benchmark_v5(report, truth_v16(), pair_results=_pairs(formal=True), formal=True)

    report = _report(components=True)
    report["metadata"]["benchmark_v5_components"]["proof_engine"]["certificate_replay_rate"] = (
        float("nan")
    )
    with pytest.raises(BenchmarkV5Error, match="component metrics"):
        score_benchmark_v5(report, truth_v16(), pair_results=_pairs(formal=True), formal=True)

    score = score_benchmark_v5(
        _report(components=True), truth_v16(), pair_results=_pairs(formal=True), formal=True
    )
    trials = [deepcopy(score) for _ in range(5)]
    trials[0]["product"]["default"]["recall"] = 0.0
    with pytest.raises(BenchmarkV5Error, match="score hash"):
        aggregate_benchmark_v5(
            trials,
            e0_attestation=_attestation(score),
            trusted_workflow_run_id="123",
            trusted_head_sha="a" * 40,
            baseline_actionable_precision=1.0,
        )

    score = score_benchmark_v5(
        _report(components=True), truth_v16(), pair_results=_pairs(formal=True), formal=True
    )
    trials = [deepcopy(score) for _ in range(5)]
    trials[0]["cost"]["total_tokens"] += 1
    unsigned_trial = dict(trials[0])
    unsigned_trial.pop("score_sha256")
    trials[0]["score_sha256"] = _sha256_value(unsigned_trial)
    with pytest.raises(BenchmarkV5Error, match="token dimensions"):
        aggregate_benchmark_v5(
            trials,
            e0_attestation=_attestation(score),
            trusted_workflow_run_id="123",
            trusted_head_sha="a" * 40,
            baseline_actionable_precision=1.0,
        )


def test_benchmark_v5_cli_loader_rejects_duplicate_and_nonfinite_json(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"report": {}, "report": {}}\n', encoding="utf-8")
    with pytest.raises(BenchmarkV5Error, match="duplicate JSON key"):
        _load(duplicate)

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"metric": NaN}\n', encoding="utf-8")
    with pytest.raises(BenchmarkV5Error, match="non-finite JSON"):
        _load(nonfinite)
