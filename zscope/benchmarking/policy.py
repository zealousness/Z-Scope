"""Single versioned policy contract shared by benchmark and release gates."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple

POLICY_SCHEMA_VERSION = "zscope.benchmark-policy.v1"
BENCHMARK_SCHEMA_VERSION = "zscope.benchmark.v4"
FORMAL_SCHEMA_VERSION = "zscope.formal-benchmark.v3"
RANGE_GATE_NAMES = frozenset(
    {
        "median_confirmed_tp",
        "median_tokens",
        "per_run_tokens",
        "actionable_fdr_delta_vs_arm_a_pp",
        "true_positive_jaccard",
        "recall_range_pp",
        "provider_usage_coverage",
        "explicit_attribution_coverage",
        "queue_drained_rate",
        "token_conservation_rate",
        "telemetry_complete_rate",
        "protocol_anomaly_count",
    }
)
RANGE_DEPTH_GATE_NAMES = MappingProxyType(
    {
        "fast": frozenset(
            {
                "confirmed_precision",
                "confirmed_count",
                "fast_static_active",
                "fast_static_formal_qualified",
                "fast_static_duplicate_local_executions",
                "fast_static_unresolved_terminal_count",
                "fast_static_backend_degraded",
            }
        ),
        "balanced": frozenset(),
        "deep": frozenset(),
    }
)
SEALED_DELTA_GATE_NAMES = frozenset(
    {
        "sealed_confirmed_recall_delta_pp",
        "sealed_actionable_precision_delta_pp",
        "sealed_high_critical_recall_delta_pp",
        "semantic_blind_review_unit_count",
        "semantic_critical_contract_recall",
        "semantic_unsupported_claim_rate",
        "semantic_warm_cache_llm_call_reduction",
        "active_discovery_exclusive_project_count",
        "active_discovery_exclusive_cwe_family_count",
        "safe_entry_alert_rate",
        "safe_entry_alert_rate_delta_pp",
        "shadow_precision_at_25",
        "shadow_high_critical_precision",
        "incomplete_scan_rate",
        "silent_rejection_without_proof_count",
    }
)
NON_REGRESSION_GATE_NAMES = frozenset(
    {
        "sealed_recall_delta_pp",
        "sealed_precision_delta_pp",
        "sealed_high_critical_recall_delta_pp",
        "tokens_per_kloc_or_tp_growth",
    }
)
MATRIX_THRESHOLD_NAMES = frozenset(
    {
        "arm_recall_tie_pp",
        "rollout_days_per_stage",
        "rollout_projects_per_stage",
        "stable_observation_windows",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "policy_id",
        "benchmark_schema_version",
        "formal_schema_version",
        "minimum_formal_trials",
        "range_depth_token_expectations",
        "range_depth_gates",
        "range_gates",
        "sealed_delta_gates",
        "non_regression_gates",
        "matrix_thresholds",
        "requirements",
    }
)
_REQUIREMENT_FIELDS = frozenset(
    {
        "require_provider_usage_for_release",
        "require_call_level_usage_events_for_release",
        "require_qualified_default_rules_for_release",
        "require_oci_isolation_for_release",
        "require_explicit_finding_attribution",
        "require_arm_a_baseline_for_release",
        "require_public_external_attestation_for_release",
        "require_sealed_attestation_for_release",
        "require_shadow_attestation_for_release",
    }
)


class BenchmarkPolicyError(ValueError):
    """Raised when release policy is incomplete or ambiguous."""


@dataclass(frozen=True)
class BenchmarkPolicy:
    policy_id: str
    benchmark_schema_version: str
    formal_schema_version: str
    minimum_formal_trials: int
    range_depth_token_expectations: Mapping[str, Mapping[str, float]]
    range_depth_gates: Mapping[str, Mapping[str, Tuple[str, float]]]
    range_gates: Mapping[str, Tuple[str, float]]
    sealed_delta_gates: Mapping[str, Tuple[str, float]]
    non_regression_gates: Mapping[str, Tuple[str, float]]
    matrix_thresholds: Mapping[str, float]
    requirements: Mapping[str, bool]
    source_path: str
    sha256: str
    schema_version: str = POLICY_SCHEMA_VERSION

    def as_dict(self) -> Dict[str, Any]:
        def gates(value: Mapping[str, Tuple[str, float]]) -> Dict[str, Any]:
            return {
                name: {"operator": operator, "threshold": threshold}
                for name, (operator, threshold) in value.items()
            }

        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "benchmark_schema_version": self.benchmark_schema_version,
            "formal_schema_version": self.formal_schema_version,
            "minimum_formal_trials": self.minimum_formal_trials,
            "range_depth_token_expectations": {
                depth: dict(expectations)
                for depth, expectations in self.range_depth_token_expectations.items()
            },
            "range_depth_gates": {
                depth: gates(depth_gates) for depth, depth_gates in self.range_depth_gates.items()
            },
            "range_gates": gates(self.range_gates),
            "sealed_delta_gates": gates(self.sealed_delta_gates),
            "non_regression_gates": gates(self.non_regression_gates),
            "matrix_thresholds": dict(self.matrix_thresholds),
            "requirements": dict(self.requirements),
            "source_path": self.source_path,
            "sha256": self.sha256,
        }


def load_benchmark_policy(path: Optional[Path] = None) -> BenchmarkPolicy:
    selected = (
        Path(path) if path is not None else Path(__file__).with_name("benchmark_policy.v1.json")
    )
    resolved = selected.expanduser().resolve()
    if not resolved.is_file():
        raise BenchmarkPolicyError(f"benchmark policy does not exist: {resolved}")
    raw = resolved.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkPolicyError(f"{resolved}: policy must be UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise BenchmarkPolicyError(f"{resolved}: policy must be an object")
    unknown = sorted(set(payload) - _POLICY_FIELDS)
    missing = sorted(_POLICY_FIELDS - set(payload))
    if unknown or missing:
        raise BenchmarkPolicyError(
            f"{resolved}: invalid policy fields; unknown={unknown!r}, missing={missing!r}"
        )
    if payload["schema_version"] != POLICY_SCHEMA_VERSION:
        raise BenchmarkPolicyError(f"{resolved}: schema_version must be {POLICY_SCHEMA_VERSION}")
    policy_id = payload["policy_id"]
    benchmark_schema = payload["benchmark_schema_version"]
    formal_schema = payload["formal_schema_version"]
    minimum_trials = payload["minimum_formal_trials"]
    if not all(
        isinstance(value, str) and value for value in (policy_id, benchmark_schema, formal_schema)
    ):
        raise BenchmarkPolicyError(f"{resolved}: policy and schema IDs must be non-empty strings")
    if benchmark_schema != BENCHMARK_SCHEMA_VERSION:
        raise BenchmarkPolicyError(
            f"{resolved}: benchmark_schema_version must be {BENCHMARK_SCHEMA_VERSION}"
        )
    if formal_schema != FORMAL_SCHEMA_VERSION:
        raise BenchmarkPolicyError(
            f"{resolved}: formal_schema_version must be {FORMAL_SCHEMA_VERSION}"
        )
    if (
        isinstance(minimum_trials, bool)
        or not isinstance(minimum_trials, int)
        or minimum_trials < 1
    ):
        raise BenchmarkPolicyError(f"{resolved}: minimum_formal_trials must be positive")
    range_gates = _parse_gates(payload["range_gates"], path=f"{resolved}:range_gates")
    raw_depth_expectations = payload["range_depth_token_expectations"]
    if not isinstance(raw_depth_expectations, dict) or set(raw_depth_expectations) != {
        "fast",
        "balanced",
        "deep",
    }:
        raise BenchmarkPolicyError(
            f"{resolved}: range_depth_token_expectations must define fast, balanced, and deep"
        )
    depth_expectations: Dict[str, Mapping[str, float]] = {}
    for depth, values in raw_depth_expectations.items():
        if not isinstance(values, dict) or set(values) != {"median_tokens", "per_run_tokens"}:
            raise BenchmarkPolicyError(
                f"{resolved}: range_depth_token_expectations.{depth} is invalid"
            )
        normalized: Dict[str, float] = {}
        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise BenchmarkPolicyError(
                    f"{resolved}: range_depth_token_expectations.{depth}.{name} must be positive"
                )
            normalized[name] = float(value)
        depth_expectations[depth] = MappingProxyType(normalized)
    raw_depth_gates = payload["range_depth_gates"]
    if not isinstance(raw_depth_gates, dict) or set(raw_depth_gates) != set(RANGE_DEPTH_GATE_NAMES):
        raise BenchmarkPolicyError(
            f"{resolved}: range_depth_gates must define fast, balanced, and deep"
        )
    depth_gates: Dict[str, Mapping[str, Tuple[str, float]]] = {}
    for depth, values in raw_depth_gates.items():
        parsed = _parse_gates(
            values,
            path=f"{resolved}:range_depth_gates.{depth}",
            allow_empty=True,
        )
        _require_exact_names(
            parsed,
            RANGE_DEPTH_GATE_NAMES[depth],
            path=f"{resolved}:range_depth_gates.{depth}",
        )
        depth_gates[depth] = MappingProxyType(parsed)
    sealed_gates = _parse_gates(
        payload["sealed_delta_gates"], path=f"{resolved}:sealed_delta_gates"
    )
    non_regression_gates = _parse_gates(
        payload["non_regression_gates"], path=f"{resolved}:non_regression_gates"
    )
    _require_exact_names(
        range_gates,
        RANGE_GATE_NAMES,
        path=f"{resolved}:range_gates",
    )
    _require_exact_names(
        sealed_gates,
        SEALED_DELTA_GATE_NAMES,
        path=f"{resolved}:sealed_delta_gates",
    )
    _require_exact_names(
        non_regression_gates,
        NON_REGRESSION_GATE_NAMES,
        path=f"{resolved}:non_regression_gates",
    )
    raw_matrix = payload["matrix_thresholds"]
    if (
        not isinstance(raw_matrix, dict)
        or not raw_matrix
        or any(
            not isinstance(name, str)
            or not name
            or isinstance(value, bool)
            or not isinstance(value, (int, float))
            for name, value in raw_matrix.items()
        )
    ):
        raise BenchmarkPolicyError(
            f"{resolved}: matrix_thresholds must be a non-empty numeric object"
        )
    matrix_thresholds = {name: float(value) for name, value in raw_matrix.items()}
    _require_exact_names(
        matrix_thresholds,
        MATRIX_THRESHOLD_NAMES,
        path=f"{resolved}:matrix_thresholds",
    )
    requirements = payload["requirements"]
    if not isinstance(requirements, dict):
        raise BenchmarkPolicyError(f"{resolved}: requirements must be an object")
    if set(requirements) != _REQUIREMENT_FIELDS or any(
        not isinstance(value, bool) for value in requirements.values()
    ):
        raise BenchmarkPolicyError(
            f"{resolved}: requirements must contain exactly "
            f"{sorted(_REQUIREMENT_FIELDS)!r} booleans"
        )
    return BenchmarkPolicy(
        policy_id=policy_id,
        benchmark_schema_version=benchmark_schema,
        formal_schema_version=formal_schema,
        minimum_formal_trials=minimum_trials,
        range_depth_token_expectations=MappingProxyType(depth_expectations),
        range_depth_gates=MappingProxyType(depth_gates),
        range_gates=MappingProxyType(range_gates),
        sealed_delta_gates=MappingProxyType(sealed_gates),
        non_regression_gates=MappingProxyType(non_regression_gates),
        matrix_thresholds=MappingProxyType(matrix_thresholds),
        requirements=MappingProxyType(dict(requirements)),
        source_path=str(resolved),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _parse_gates(raw: Any, *, path: str, allow_empty: bool = False) -> Dict[str, Tuple[str, float]]:
    if not isinstance(raw, dict) or (not raw and not allow_empty):
        qualifier = "an object" if allow_empty else "a non-empty object"
        raise BenchmarkPolicyError(f"{path}: gates must be {qualifier}")
    result: Dict[str, Tuple[str, float]] = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not name or not isinstance(value, dict):
            raise BenchmarkPolicyError(f"{path}: invalid gate {name!r}")
        if set(value) != {"operator", "threshold"}:
            raise BenchmarkPolicyError(f"{path}.{name}: requires operator and threshold")
        operator = value["operator"]
        threshold = value["threshold"]
        if operator not in {">=", "<="}:
            raise BenchmarkPolicyError(f"{path}.{name}: invalid operator {operator!r}")
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise BenchmarkPolicyError(f"{path}.{name}: threshold must be numeric")
        result[name] = (operator, float(threshold))
    return result


def _require_exact_names(
    values: Mapping[str, Any],
    expected: frozenset[str],
    *,
    path: str,
) -> None:
    missing = sorted(expected - set(values))
    unknown = sorted(set(values) - expected)
    if missing or unknown:
        raise BenchmarkPolicyError(
            f"{path}: invalid names; missing={missing!r}, unknown={unknown!r}"
        )


DEFAULT_BENCHMARK_POLICY = load_benchmark_policy()
