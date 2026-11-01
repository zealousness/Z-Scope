from __future__ import annotations

import json
from pathlib import Path

import pytest

from zscope.benchmarking.isolation import (
    BenchmarkIsolationError,
    build_oci_isolation_plan,
    oci_capability,
    require_release_isolation,
)
from zscope.benchmarking.policy import (
    DEFAULT_BENCHMARK_POLICY,
    BenchmarkPolicyError,
    load_benchmark_policy,
)
from zscope.benchmarking.protocol import (
    SCHEMA_VERSION,
    aggregate_usage_ledger,
    attribution_summary,
    build_cost_metrics,
    candidate_funnel,
    finding_attribution,
)
from zscope.benchmarking.replay_bundle import (
    ReplayBundleError,
    build_validator_replay_bundle,
    validate_validator_replay_bundle,
)


def _usage_row(**overrides: int) -> dict[str, int]:
    row = {
        "request_count": 1,
        "successful_calls": 1,
        "denied_requests": 0,
        "failed_or_unknown_calls": 0,
        "prompt_tokens": 100,
        "completion_tokens": 20,
        "total_tokens": 120,
        "provider_reported_calls": 1,
        "estimated_or_conservative_calls": 0,
        "budget_violation_count": 0,
    }
    row.update(overrides)
    return row


def test_policy_v1_is_the_single_v4_formal_v3_contract(tmp_path: Path) -> None:
    policy = DEFAULT_BENCHMARK_POLICY
    assert policy.benchmark_schema_version == SCHEMA_VERSION == "zscope.benchmark.v4"
    assert policy.formal_schema_version == "zscope.formal-benchmark.v3"
    assert policy.range_gates["median_confirmed_tp"] == (">=", 111.0)
    assert policy.range_gates["median_tokens"] == ("<=", 10_000_000.0)
    assert policy.range_gates["per_run_tokens"] == ("<=", 12_000_000.0)
    assert policy.range_depth_gates["fast"]["confirmed_precision"] == (">=", 0.9)
    assert policy.range_depth_gates["fast"]["confirmed_count"] == (">=", 1.0)
    assert policy.range_depth_gates["balanced"] == {}
    assert policy.range_depth_gates["deep"] == {}
    assert policy.sealed_delta_gates["sealed_confirmed_recall_delta_pp"] == (
        ">=",
        3.0,
    )
    assert policy.non_regression_gates["tokens_per_kloc_or_tp_growth"] == (
        "<=",
        0.25,
    )
    assert policy.requirements["require_oci_isolation_for_release"] is True

    payload = json.loads(Path(policy.source_path).read_text(encoding="utf-8"))
    del payload["range_gates"]["median_tokens"]
    invalid = tmp_path / "invalid-policy.json"
    invalid.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BenchmarkPolicyError, match="missing=.*median_tokens"):
        load_benchmark_policy(invalid)


def test_benchmark_policy_is_included_in_distribution_package_data() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    package_data = pyproject.read_text(encoding="utf-8").split("[tool.setuptools.package-data]", 1)[
        1
    ]
    assert '"benchmarking/*.json"' in package_data.split("[tool.setuptools.dynamic]", 1)[0]


def test_source_and_decision_attribution_are_independent_and_overlap() -> None:
    issues = [
        {
            "attribution": {
                "schema_version": "zscope.finding-attribution.v1",
                "discovered_by": ["deterministic_rule", "llm_active_discovery"],
                "discovery_details": [],
                "decided_by": "validator_llm",
                "decision_level": "V1",
            }
        },
        {
            "attribution": {
                "schema_version": "zscope.finding-attribution.v1",
                "discovered_by": ["llm_active_discovery"],
                "discovery_details": [],
                "decided_by": "validator_llm",
                "decision_level": "V2",
            },
        },
    ]

    result = attribution_summary(
        issues,
        matched_issue_indices=(0,),
        raw_false_positive_indices=(1,),
    )

    assert result["explicit_count"] == 2
    assert result["by_discovery"]["deterministic_rule"]["true_positives"] == 1
    assert result["by_discovery"]["llm_active_discovery"]["true_positives"] == 1
    assert result["by_discovery"]["llm_active_discovery"]["raw_false_positives"] == 1
    assert result["exclusive_by_discovery"]["llm_active_discovery"] == {
        "issues": 1,
        "true_positives": 0,
        "raw_false_positives": 1,
    }
    assert result["by_decision"]["validator_llm"]["issues"] == 2
    assert result["by_decision_level"]["V1"]["true_positives"] == 1
    assert result["by_decision_level"]["V2"]["raw_false_positives"] == 1

    invalid = finding_attribution(
        {
            "attribution": {
                "discovered_by": ["benchmark_magic"],
                "decided_by": "oracle",
            }
        }
    )
    assert invalid["inferred"] is False
    assert invalid["attribution_inferred"] is False
    assert invalid["valid"] is False


@pytest.mark.parametrize(
    "schema_version",
    [None, "zscope.finding-attribution.v0", "zscope.finding-attribution.v2"],
)
def test_explicit_attribution_requires_exact_schema_version(schema_version) -> None:
    attribution = {
        "discovered_by": ["deterministic_rule"],
        "discovery_details": [],
        "decided_by": "deterministic_proof",
        "decision_level": "V0",
    }
    if schema_version is not None:
        attribution["schema_version"] = schema_version

    result = attribution_summary(
        [{"attribution": attribution}],
        matched_issue_indices=(0,),
        raw_false_positive_indices=(),
    )

    assert result["explicit_count"] == 0
    assert result["explicit_coverage"] == 0.0
    [error] = [
        item
        for item in finding_attribution({"attribution": attribution})["errors"]
        if item.startswith("schema_version must be")
    ]
    assert "zscope.finding-attribution.v1" in error


def test_explicit_attribution_rejects_non_array_discovery_sources() -> None:
    result = finding_attribution(
        {
            "attribution": {
                "schema_version": "zscope.finding-attribution.v1",
                "discovered_by": "deterministic_rule",
                "discovery_details": [],
                "decided_by": "deterministic_proof",
                "decision_level": "V0",
            }
        }
    )

    assert result["attribution_inferred"] is False
    assert result["valid"] is False
    assert "discovered_by must be an array" in result["errors"]


def test_explicit_attribution_requires_discovery_details_field() -> None:
    result = finding_attribution(
        {
            "attribution": {
                "schema_version": "zscope.finding-attribution.v1",
                "discovered_by": ["deterministic_rule"],
                "decided_by": "deterministic_proof",
                "decision_level": "V0",
            }
        }
    )

    assert result["valid"] is False
    assert "discovery_details must be an array of objects" in result["errors"]


def test_usage_ledger_reuses_scan_budget_attribution_and_conserves_tokens() -> None:
    snapshot = {
        "telemetry_complete": True,
        "totals": _usage_row(),
        "by_agent": {"validator_agent": _usage_row()},
        "by_stage": {"validation": _usage_row()},
        "by_finish_reason": {"stop": _usage_row()},
    }
    report = {"run_manifest": {"llm_usage_attribution": snapshot}}

    ledger = aggregate_usage_ledger(report)
    assert ledger["source"] == "scan_token_usage_attribution"
    assert ledger["complete"] is True
    assert ledger["conservation_passed"] is True
    assert ledger["telemetry_complete"] is True
    assert ledger["totals"]["total_tokens"] == 120
    assert ledger["by_agent"]["validator_agent"]["total_tokens"] == 120
    assert ledger["by_stage"]["validation"]["total_tokens"] == 120
    assert ledger["finish_reasons"] == {"stop": 1}

    cost = build_cost_metrics(report, {"true_positives": 2})
    assert cost["billable_tokens"] == 120
    assert cost["tokens_per_verified_issue"] == 60
    assert cost["accounting_mode"] == "scan_token_usage_attribution"


def test_response_usage_spans_fail_closed_on_duplicates_and_estimates() -> None:
    span = {
        "call_id": "call-1",
        "agent": "validator_agent",
        "stage": "validation",
        "prompt_tokens": 100,
        "cached_prompt_tokens": 10,
        "completion_tokens": 20,
        "reasoning_tokens": 5,
        "total_tokens": 120,
        "tool_call_count": 2,
        "new_fact_count": 1,
        "provider_reported": True,
        "finish_reason": "stop",
    }
    complete = aggregate_usage_ledger({"llm_usage_spans": [span]})
    assert complete["complete"] is True
    assert complete["provider_usage_coverage"] == 1.0

    incomplete = aggregate_usage_ledger(
        {"llm_usage_spans": [span, {**span, "provider_reported": False}]}
    )
    assert incomplete["complete"] is False
    assert incomplete["call_count"] == 1
    assert "duplicate call_id: call-1" in incomplete["errors"]


def test_candidate_funnel_keeps_units_and_group_attribution_explicit() -> None:
    report = {
        "summary": {"scan_level_raw_occurrence_count": 3},
        "candidate_terminal_states": [
            {
                "validation_cluster_uid": "VAL-1",
                "candidate_uid": "CAND-1",
                "validation_attempt_count": 1,
                "issue": {
                    "validator_pass_history": [
                        {
                            "pass": "initial",
                            "verdict": "verified",
                            "stop_reason": "decision_complete",
                        }
                    ],
                    "validator_policy_outcome": {"stop_reason": "decision_complete"},
                    "attribution": {
                        "discovered_by": [
                            "deterministic_rule",
                            "llm_active_discovery",
                        ],
                        "decided_by": "validator_llm",
                        "decision_level": "V1",
                    },
                },
            },
            {
                "validation_cluster_uid": "VAL-2",
                "candidate_uid": "CAND-2",
                "issue": {
                    "candidate_kind": "backend_signal",
                    "deterministic_prevalidation_decision": "proved",
                },
            },
        ],
        "issues": [{"candidate_uid": "CAND-1"}],
        "report_views": {"with_needs_review": {"issues": [{}, {}]}},
    }

    funnel = candidate_funnel(report)
    assert funnel["stages"]["raw_occurrences"]["count"] == 3
    assert funnel["stages"]["raw_occurrences"]["unit"] == "occurrence"
    assert funnel["stages"]["canonical_validation_groups"]["count"] == 2
    assert funnel["stages"]["v0_prevalidation"]["count"] == 2
    assert funnel["stages"]["validator_invoked_groups"]["count"] == 1
    assert funnel["stages"]["v1_initial_decision"]["count"] == 1
    assert funnel["stages"]["v2_evidence_recheck"]["count"] == 0
    assert funnel["stages"]["v3_targeted_investigation"]["count"] == 0
    assert funnel["stages"]["v4_dynamic_reproduction"]["source"] == "reserved_not_implemented"
    assert funnel["stages"]["reported_findings"]["count"] == 1
    attribution = funnel["canonical_group_attribution"]
    assert attribution["by_discovery"]["deterministic_rule"] == 1
    assert attribution["by_discovery"]["llm_active_discovery"] == 1
    assert attribution["by_decision_level"] == {"V0": 1, "V1": 1}
    assert attribution["exclusive_by_discovery"] == {"backend_signal": 1}
    assert attribution["by_discovery_and_decision"]["backend_signal|deterministic_proof"] == 1
    assert attribution["reached_by_level"] == {
        "V0": 2,
        "V1": 1,
        "V2": 0,
        "V3": 0,
        "V4": 0,
    }
    assert attribution["transition_counts"]["V0->V1"] == 1
    assert attribution["transition_counts"]["V1->terminal:decision_complete"] == 1
    assert attribution["drop_reason"]["decision_complete"] == 1
    assert funnel["contract"]["linear_conversion_rates_valid"] is False


def test_candidate_funnel_prefers_scan_level_raw_count_over_report_view_count() -> None:
    report = {
        "summary": {
            "validation_performance": {"scan_level_raw_occurrence_count": 93},
        },
        # These projections contain only reportable/review findings and are
        # not the scan-level pre-dedup occurrence population.
        "run_manifest": {"raw_occurrence_count": 68},
        "needs_review_governance": {"raw_occurrence_count": 62},
        "candidate_terminal_states": [],
        "issues": [],
    }

    raw = candidate_funnel(report)["stages"]["raw_occurrences"]

    assert raw == {
        "count": 93,
        "available": True,
        "unit": "occurrence",
        "source": "scan_level_raw_occurrence_count",
    }


def test_candidate_funnel_reads_production_v0_summary_and_excludes_prevalidation_deferrals() -> (
    None
):
    report = {
        "summary": {
            "validation_performance": {
                "deterministic_prevalidation_decision_count": 7,
            }
        },
        "candidate_terminal_states": [
            {
                "candidate_schema_version": "zscope.entry-candidate.v1",
                "candidate_uid": "ENTRY-1",
                "candidate_disposition": "deferred_budget",
            },
            {
                "candidate_uid": "CAND-1",
                "validation_cluster_uid": "VAL-1",
                "candidate_disposition": "needs_review",
            },
        ],
        "issues": [],
    }

    funnel = candidate_funnel(report)
    assert funnel["stages"]["v0_prevalidation"]["count"] == 1
    assert funnel["stages"]["v0_deterministic_decisions"] == {
        "count": 7,
        "available": True,
        "unit": "validation_group",
        "source": "deterministic_prevalidation_decision_count",
    }
    assert (
        funnel["canonical_group_attribution"]["transition_counts"][
            "pre_validation->terminal:deferred_budget"
        ]
        == 1
    )


def test_candidate_funnel_reports_v3_eligibility_entry_and_fact_breakdown() -> None:
    report = {
        "candidate_terminal_states": [
            {
                "candidate_uid": "CAND-V3",
                "validation_cluster_uid": "VAL-V3",
                "candidate_disposition": "confirmed",
                "validation_attempt_count": 3,
                "issue": {
                    "attribution": {
                        "schema_version": "zscope.finding-attribution.v1",
                        "discovered_by": ["backend_signal"],
                        "discovery_details": [],
                        "decided_by": "validator_llm",
                        "decision_level": "V3",
                    },
                    "validator_v3_eligibility": {
                        "eligible": True,
                        "severity": "high",
                        "required_fact_kinds": ["value_range", "guard_dominance"],
                    },
                    "validator_v3_entered": True,
                    "validator_v3_confirmed": True,
                    "validator_pass_history": [
                        {"pass": "initial", "verdict": "uncertain"},
                        {"pass": "investigation_synthesis", "verdict": "verified"},
                    ],
                },
            }
        ],
        "issues": [{"candidate_uid": "CAND-V3"}],
    }

    funnel = candidate_funnel(report)
    v3 = funnel["v3_investigation"]

    assert v3["eligible"] == 1
    assert v3["entered"] == 1
    assert v3["confirmed"] == 1
    assert v3["by_source_terminal"] == {"backend_signal|confirmed": 1}
    assert v3["by_risk_layer"] == {"high": {"eligible": 1, "entered": 1, "confirmed": 1}}
    assert v3["by_fact_kind"] == {
        "guard_dominance": {"eligible": 1, "entered": 1, "confirmed": 1},
        "value_range": {"eligible": 1, "entered": 1, "confirmed": 1},
    }
    assert funnel["stages"]["v2_evidence_recheck"]["count"] == 0
    assert funnel["stages"]["v3_targeted_investigation"]["count"] == 1
    assert funnel["canonical_group_attribution"]["transition_counts"]["V1->V3"] == 1
    assert "V1->V2" not in funnel["canonical_group_attribution"]["transition_counts"]

    rung = funnel["canonical_group_attribution"]
    assert rung["reached_by_rung"]["R1_validator_v1"] == 1
    assert rung["reached_by_rung"]["R2_v3_reattempt"] == 1
    assert rung["reached_by_rung"]["R3_v2b_adjudication"] == 0
    assert rung["confirmed_by_rung"]["R2_v3_reattempt"] == 1
    assert rung["confirmed_by_rung"]["R1_validator_v1"] == 0
    assert rung["drop_reason_by_rung"]["R2_v3_reattempt"]


def test_candidate_funnel_rung_projection_covers_r1_only_and_r3_marker() -> None:
    report = {
        "candidate_terminal_states": [
            {
                "validation_cluster_uid": "VAL-R1",
                "candidate_uid": "CAND-R1",
                "candidate_disposition": "needs_review",
                "validation_attempt_count": 1,
                "issue": {
                    "attribution": {"decided_by": "unresolved", "decision_level": "V1"},
                    "validator_pass_history": [{"pass": "initial", "verdict": "uncertain"}],
                    "stop_reason": "no_evidence_gain",
                },
            },
            {
                "validation_cluster_uid": "VAL-R3",
                "candidate_uid": "CAND-R3",
                "candidate_disposition": "confirmed",
                "validation_attempt_count": 2,
                "issue": {
                    "attribution": {"decided_by": "validator_llm", "decision_level": "V3"},
                    "validator_v2b_entered": True,
                    "validator_pass_history": [
                        {"pass": "initial", "verdict": "uncertain"},
                        {"pass": "v2b_adjudication", "verdict": "verified"},
                    ],
                },
            },
        ],
        "issues": [],
    }

    funnel = candidate_funnel(report)
    rung = funnel["canonical_group_attribution"]
    assert rung["reached_by_rung"] == {
        "R1_validator_v1": 2,
        "R2_v3_reattempt": 0,
        "R3_v2b_adjudication": 1,
    }
    assert rung["confirmed_by_rung"]["R3_v2b_adjudication"] == 1
    assert rung["drop_reason_by_rung"]["R1_validator_v1"]["no_evidence_gain"] == 1


def test_validator_replay_bundle_excludes_truth_and_prior_outcomes() -> None:
    report = {
        "run_manifest": {
            "source_revision": "abc123",
            "source_tree_hash": "a" * 64,
            "finding_status": "vulnerable",
        },
        "candidate_terminal_states": [
            {
                "validation_cluster_uid": "VAL-1",
                "candidate_uid": "CAND-1",
                "occurrence_uids": ["OCC-2", "OCC-1"],
                "terminal_disposition": "confirmed",
                "validation_status": "validated",
                "decision_proof": {"outcome": "confirm"},
                "issue": {
                    "candidate_uid": "CAND-1",
                    "rule_id": "sample_rule",
                    "function": "sink",
                    "location": "src/demo.c:12",
                    "description": "unchecked length reaches copy",
                    "evidence_pack": {
                        "path": {"functions": ["entry", "sink"]},
                        "facts": [{"kind": "unchecked_length"}],
                        "status": "validated",
                        "ground_truth_id": "BUG-1",
                    },
                },
            }
        ],
    }

    bundle = build_validator_replay_bundle(report)
    validate_validator_replay_bundle(bundle)
    group = bundle["canonical_groups"][0]
    assert group["occurrence_uids"] == ["OCC-1", "OCC-2"]
    assert group["facts"]["facts"] == [{"kind": "unchecked_length"}]
    assert "status" not in group["evidence"]
    assert "ground_truth_id" not in group["evidence"]
    assert "terminal_disposition" not in group
    assert "finding_status" not in bundle["source_identity"]

    changed_outcome = json.loads(json.dumps(report))
    changed_outcome["candidate_terminal_states"][0]["terminal_disposition"] = "rejected_with_proof"
    changed_outcome["candidate_terminal_states"][0]["validation_status"] = "rejected"
    assert (
        build_validator_replay_bundle(changed_outcome)["bundle_sha256"] == bundle["bundle_sha256"]
    )

    bundle["canonical_groups"][0]["candidate"]["oracle"] = "BUG-1"
    with pytest.raises(ReplayBundleError):
        validate_validator_replay_bundle(bundle)


def test_oci_isolation_plan_is_non_release_evidence_until_executed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_input = tmp_path / "sealed-input"
    output = tmp_path / "artifacts"
    scan_input.mkdir()
    output.mkdir()
    (scan_input / "demo.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    monkeypatch.setattr(
        "zscope.benchmarking.isolation.shutil.which",
        lambda runtime: f"/usr/bin/{runtime}",
    )
    image = "registry.example/zscope@sha256:" + "a" * 64

    plan = build_oci_isolation_plan(
        runtime="podman",
        image=image,
        scan_input=scan_input,
        artifact_output=output,
        scan_command=("zscope", "-c", "/zscope-input/zscope.yaml"),
        environment={"Z_SCOPE_API_KEY": "secret", "GROUND_TRUTH_PATH": "forbidden"},
    )
    serialized = plan.as_dict()
    assert serialized["truth_mounted"] is False
    assert serialized["repository_mounted"] is False
    assert serialized["environment_keys"] == ["Z_SCOPE_API_KEY"]
    assert serialized["release_capable"] is False
    with pytest.raises(BenchmarkIsolationError, match="verified OCI"):
        require_release_isolation(required=True, capability=serialized)

    verified = {
        **oci_capability(runtime="podman", image=image),
        "rootless_verified": True,
        "image_digest_verified": True,
        "execution_verified": True,
        "actual_inspection_collected": True,
        "release_capable": True,
        "truth_mounted": False,
        "repository_mounted": False,
        "scanner_cwd_isolated": True,
        "mounts_verified": True,
        "security_verified": True,
        "network_restriction_verified": True,
        "network_mode": "model-endpoint-only",
        "network_policy_sha256": "c" * 64,
        "scanner_cwd": "/zscope-input",
        "mounts": [
            {
                "source": str(scan_input),
                "destination": "/zscope-input",
                "purpose": "scan_input",
                "read_only": True,
            },
            {
                "source": serialized["artifact_output"],
                "destination": "/zscope-output",
                "purpose": "artifact_output",
                "read_only": False,
            },
            {
                "source": serialized["cache_output"],
                "destination": "/zscope-cache",
                "purpose": "cache",
                "read_only": False,
            },
        ],
        "required_phases": ["scan"],
        "phase_executions": [
            {
                "phase": "scan",
                "inspect_verified": True,
                "security_verified": True,
                "network_peers_verified": True,
                "network_contract_verified": True,
                "proxy_verified": True,
                "scanner_labels_verified": True,
                "image_verified": True,
                "unexpected_mount_count": 0,
                "container_inspect_sha256": "d" * 64,
                "network_inspect_sha256": "e" * 64,
                "proxy_inspect_sha256": "f" * 64,
            }
        ],
        "errors": [],
    }
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    truth = checkout / "benchmark" / "ground_truth.json"
    truth.parent.mkdir()
    truth.write_text("{}", encoding="utf-8")
    require_release_isolation(
        required=True,
        capability=verified,
        repository_checkout=checkout,
        truth_paths=(truth,),
    )

    unsafe = json.loads(json.dumps(verified))
    unsafe["mounts"][0]["source"] = str(checkout)
    with pytest.raises(BenchmarkIsolationError, match="repository checkout"):
        require_release_isolation(
            required=True,
            capability=unsafe,
            repository_checkout=checkout,
            truth_paths=(truth,),
        )

    (scan_input / "ground_truth.json").write_text("{}", encoding="utf-8")
    with pytest.raises(BenchmarkIsolationError, match="truth material"):
        build_oci_isolation_plan(
            runtime="podman",
            image=image,
            scan_input=scan_input,
            artifact_output=output,
            scan_command=("zscope",),
            environment={},
        )
