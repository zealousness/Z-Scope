"""Fail-closed balanced-default attestation contract.

The JSON digest detects accidental mutation.  Trust in the issuer comes from
the protected artifact/environment that delivers this document; this module
does not pretend that a self-contained digest is a cryptographic signature.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .policy import BenchmarkPolicy, DEFAULT_BENCHMARK_POLICY


ATTESTATION_SCHEMA_VERSION = "zscope.balanced-default-attestation.v1"
_FIELDS = frozenset(
    {
        "schema_version",
        "attestation_id",
        "issued_at",
        "issuer",
        "bindings",
        "coverage",
        "metrics",
        "evidence",
        "content_sha256",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "dataset_sha256",
        "truth_sha256",
        "scanner_bundle_sha256",
        "scorer_sha256",
        "git_sha",
        "config_sha256",
        "rules_sha256",
        "policy_sha256",
        "model_spec_sha256",
        "baseline_sha256",
        "public_external_aggregate_sha256",
    }
)
_COVERAGE_FIELDS = frozenset(
    {
        "sealed_project_count",
        "domain_count",
        "vulnerable_fixed_pair_count",
        "safe_audit_unit_count",
        "max_project_share",
        "max_cwe_share",
        "rotation_fraction",
        "shadow_project_count",
        "public_external_suite_count",
    }
)


def attestation_content_sha256(payload: Mapping[str, Any]) -> str:
    canonical = {key: value for key, value in payload.items() if key != "content_sha256"}
    raw = json.dumps(
        canonical,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def validate_balanced_attestation(
    payload: Mapping[str, Any],
    *,
    release_sha: str,
    workflow_run_id: str = "",
    policy: BenchmarkPolicy = DEFAULT_BENCHMARK_POLICY,
) -> Dict[str, Any]:
    errors: list[str] = []
    if set(payload) != _FIELDS:
        errors.append(
            "invalid top-level fields: "
            f"missing={sorted(_FIELDS - set(payload))!r}, "
            f"unknown={sorted(set(payload) - _FIELDS)!r}"
        )
    if payload.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        errors.append(f"schema_version must be {ATTESTATION_SCHEMA_VERSION}")
    for field in ("attestation_id", "issued_at"):
        if not isinstance(payload.get(field), str) or not str(payload.get(field)).strip():
            errors.append(f"{field} must be a non-empty string")

    issuer = payload.get("issuer")
    if not isinstance(issuer, dict):
        errors.append("issuer must be an object")
        issuer = {}
    if not isinstance(issuer.get("team"), str) or not issuer.get("team"):
        errors.append("issuer.team must be a non-empty string")
    if issuer.get("independent_test_team") is not True:
        errors.append("issuer.independent_test_team must be true")
    if not isinstance(issuer.get("signed_by"), str) or not issuer.get("signed_by"):
        errors.append("issuer.signed_by must be a non-empty string")

    bindings = payload.get("bindings")
    if not isinstance(bindings, dict) or set(bindings) != _BINDING_FIELDS:
        errors.append("bindings must contain every required identity exactly once")
        bindings = {}
    for name in _BINDING_FIELDS - {"git_sha"}:
        value = str(bindings.get(name) or "")
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value.lower()):
            errors.append(f"bindings.{name} must be a SHA-256 hex digest")
    if str(bindings.get("git_sha") or "") != release_sha:
        errors.append("bindings.git_sha does not match the release SHA")
    if bindings.get("policy_sha256") != policy.sha256:
        errors.append("bindings.policy_sha256 does not match the active policy")

    coverage = payload.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != _COVERAGE_FIELDS:
        errors.append("coverage must contain the complete sealed/shadow coverage contract")
        coverage = {}
    coverage_minimums = {
        "sealed_project_count": 6,
        "domain_count": 3,
        "vulnerable_fixed_pair_count": 120,
        "safe_audit_unit_count": 1200,
        "rotation_fraction": 0.20,
        "shadow_project_count": 3,
        "public_external_suite_count": 3,
    }
    for name, threshold in coverage_minimums.items():
        coverage_value = coverage.get(name)
        if (
            isinstance(coverage_value, bool)
            or not isinstance(coverage_value, (int, float))
            or float(coverage_value) < threshold
        ):
            errors.append(f"coverage.{name} must be >= {threshold}")
    for name in ("max_project_share", "max_cwe_share"):
        share_value = coverage.get(name)
        if (
            isinstance(share_value, bool)
            or not isinstance(share_value, (int, float))
            or float(share_value) > 0.25
        ):
            errors.append(f"coverage.{name} must be <= 0.25")

    metrics = payload.get("metrics")
    expected_metrics = set(policy.sealed_delta_gates)
    if not isinstance(metrics, dict) or set(metrics) != expected_metrics:
        errors.append("metrics do not exactly match policy sealed_delta_gates")
        metrics = {}
    metric_results: Dict[str, Any] = {}
    for name, (operator, threshold) in policy.sealed_delta_gates.items():
        metric_value = metrics.get(name)
        available = isinstance(metric_value, (int, float)) and not isinstance(metric_value, bool)
        actual: Optional[float] = (
            float(metric_value) if available else None  # type: ignore[arg-type]
        )
        passed = bool(
            actual is not None
            and (actual >= threshold if operator == ">=" else actual <= threshold)
        )
        metric_results[name] = {
            "actual": actual,
            "operator": operator,
            "threshold": threshold,
            "passed": passed,
        }
        if not passed:
            errors.append(f"metric gate failed: {name}")

    evidence = payload.get("evidence")
    if not isinstance(evidence, dict):
        errors.append("evidence must be an object")
        evidence = {}
    if evidence.get("protected_artifact") is not True:
        errors.append("evidence.protected_artifact must be true")
    if not isinstance(evidence.get("workflow_run_id"), str) or not evidence.get("workflow_run_id"):
        errors.append("evidence.workflow_run_id must be a non-empty string")
    if not str(workflow_run_id or "").strip():
        errors.append("protected workflow_run_id binding is required")
    elif str(evidence.get("workflow_run_id") or "") != str(workflow_run_id):
        errors.append("evidence.workflow_run_id does not match the protected workflow run")
    if evidence.get("all_alerts_double_blind_reviewed") is not True:
        errors.append("evidence.all_alerts_double_blind_reviewed must be true")
    if evidence.get("all_disagreements_adjudicated") is not True:
        errors.append("evidence.all_disagreements_adjudicated must be true")
    if evidence.get("public_external_formal_passed") is not True:
        errors.append("evidence.public_external_formal_passed must be true")
    public_suites = evidence.get("public_external_suites")
    if not isinstance(public_suites, list) or {
        str(item).strip().lower().replace("-", "_") for item in public_suites
    } != {"juliet", "sv_comp", "magma"}:
        errors.append("evidence.public_external_suites must contain Juliet, SV-COMP, and Magma")

    expected_digest = attestation_content_sha256(payload)
    if payload.get("content_sha256") != expected_digest:
        errors.append("content_sha256 mismatch")
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "attestation_id": payload.get("attestation_id"),
        "content_sha256": expected_digest,
        "bindings": dict(bindings),
        "coverage": dict(coverage),
        "metric_gates": metric_results,
        "errors": errors,
        "passed": not errors,
    }


def load_balanced_attestation(
    path: Path,
    *,
    release_sha: str,
    workflow_run_id: str = "",
    policy: BenchmarkPolicy = DEFAULT_BENCHMARK_POLICY,
) -> Dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"passed": False, "errors": [f"cannot read attestation: {exc}"]}
    if not isinstance(payload, dict):
        return {"passed": False, "errors": ["attestation must be a JSON object"]}
    return validate_balanced_attestation(
        payload,
        release_sha=release_sha,
        workflow_run_id=workflow_run_id,
        policy=policy,
    )


def finalize_balanced_attestation(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Return a copy with the canonical content digest populated."""

    result = dict(payload)
    result["content_sha256"] = attestation_content_sha256(result)
    return result
