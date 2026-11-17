from __future__ import annotations

import json
from pathlib import Path

from zscope.benchmarking.attestation import (
    ATTESTATION_SCHEMA_VERSION,
    finalize_balanced_attestation,
    load_balanced_attestation,
    validate_balanced_attestation,
)
from zscope.benchmarking.policy import DEFAULT_BENCHMARK_POLICY

RELEASE_SHA = "f" * 40


def _payload() -> dict:
    metrics = {
        "sealed_confirmed_recall_delta_pp": 3.0,
        "sealed_actionable_precision_delta_pp": -1.0,
        "sealed_high_critical_recall_delta_pp": 0.0,
        "semantic_blind_review_unit_count": 100,
        "semantic_critical_contract_recall": 0.85,
        "semantic_unsupported_claim_rate": 0.05,
        "semantic_warm_cache_llm_call_reduction": 0.80,
        "active_discovery_exclusive_project_count": 3,
        "active_discovery_exclusive_cwe_family_count": 2,
        "safe_entry_alert_rate": 0.10,
        "safe_entry_alert_rate_delta_pp": 1.0,
        "shadow_precision_at_25": 0.70,
        "shadow_high_critical_precision": 0.80,
        "incomplete_scan_rate": 0.05,
        "silent_rejection_without_proof_count": 0,
    }
    result = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "attestation_id": "sealed-2026q3-001",
        "issued_at": "2026-08-12T12:00:00Z",
        "issuer": {
            "team": "independent-security-test",
            "independent_test_team": True,
            "signed_by": "review-board-7",
        },
        "bindings": {
            "dataset_sha256": "1" * 64,
            "truth_sha256": "2" * 64,
            "scanner_bundle_sha256": "3" * 64,
            "scorer_sha256": "4" * 64,
            "git_sha": RELEASE_SHA,
            "config_sha256": "5" * 64,
            "rules_sha256": "6" * 64,
            "policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
            "model_spec_sha256": "7" * 64,
            "baseline_sha256": "8" * 64,
            "public_external_aggregate_sha256": "9" * 64,
        },
        "coverage": {
            "sealed_project_count": 6,
            "domain_count": 3,
            "vulnerable_fixed_pair_count": 120,
            "safe_audit_unit_count": 1200,
            "max_project_share": 0.25,
            "max_cwe_share": 0.25,
            "rotation_fraction": 0.20,
            "shadow_project_count": 3,
            "public_external_suite_count": 3,
        },
        "metrics": metrics,
        "evidence": {
            "protected_artifact": True,
            "workflow_run_id": "sealed-evaluation/8871",
            "all_alerts_double_blind_reviewed": True,
            "all_disagreements_adjudicated": True,
            "public_external_formal_passed": True,
            "public_external_suites": ["Juliet", "SV-COMP", "Magma"],
        },
    }
    return finalize_balanced_attestation(result)


def test_balanced_attestation_binds_all_locked_gates_and_hashes() -> None:
    result = validate_balanced_attestation(
        _payload(),
        release_sha=RELEASE_SHA,
        workflow_run_id="sealed-evaluation/8871",
    )

    assert result["passed"] is True
    assert set(result["metric_gates"]) == set(DEFAULT_BENCHMARK_POLICY.sealed_delta_gates)
    assert all(gate["passed"] for gate in result["metric_gates"].values())
    assert result["bindings"]["policy_sha256"] == DEFAULT_BENCHMARK_POLICY.sha256


def test_balanced_attestation_fails_closed_on_gate_or_digest_change() -> None:
    payload = _payload()
    payload["metrics"]["shadow_precision_at_25"] = 0.69

    result = validate_balanced_attestation(
        payload,
        release_sha=RELEASE_SHA,
        workflow_run_id="sealed-evaluation/8871",
    )

    assert result["passed"] is False
    assert "metric gate failed: shadow_precision_at_25" in result["errors"]
    assert "content_sha256 mismatch" in result["errors"]


def test_balanced_attestation_enforces_dataset_scale_and_rotation() -> None:
    payload = _payload()
    payload["coverage"]["sealed_project_count"] = 5
    payload["coverage"]["rotation_fraction"] = 0.19
    payload = finalize_balanced_attestation(payload)

    result = validate_balanced_attestation(
        payload,
        release_sha=RELEASE_SHA,
        workflow_run_id="sealed-evaluation/8871",
    )

    assert result["passed"] is False
    assert "coverage.sealed_project_count must be >= 6" in result["errors"]
    assert "coverage.rotation_fraction must be >= 0.2" in result["errors"]


def test_balanced_attestation_loader_rejects_wrong_release(tmp_path: Path) -> None:
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(_payload()), encoding="utf-8")

    result = load_balanced_attestation(
        path,
        release_sha="e" * 40,
        workflow_run_id="sealed-evaluation/8871",
    )

    assert result["passed"] is False
    assert "bindings.git_sha does not match the release SHA" in result["errors"]


def test_balanced_attestation_binds_protected_workflow_run_identity() -> None:
    accepted = validate_balanced_attestation(
        _payload(),
        release_sha=RELEASE_SHA,
        workflow_run_id="sealed-evaluation/8871",
    )
    rejected = validate_balanced_attestation(
        _payload(),
        release_sha=RELEASE_SHA,
        workflow_run_id="sealed-evaluation/8872",
    )

    assert accepted["passed"] is True
    assert rejected["passed"] is False
    assert (
        "evidence.workflow_run_id does not match the protected workflow run" in rejected["errors"]
    )


def test_balanced_attestation_rejects_self_asserted_workflow_identity() -> None:
    result = validate_balanced_attestation(_payload(), release_sha=RELEASE_SHA)

    assert result["passed"] is False
    assert "protected workflow_run_id binding is required" in result["errors"]
