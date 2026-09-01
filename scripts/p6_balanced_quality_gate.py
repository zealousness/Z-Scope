#!/usr/bin/env python3
"""Seal the answer-isolated P6 balanced dual-view quality decision.

The scanner must finish and its report must be frozen before this module is
invoked.  This module never loads Truth itself and does not implement matching;
it only validates two independently produced score artifacts and the physical
usage/conservation evidence emitted for the selected cold balanced attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from zscope.benchmarking.p6_protocol import (
    P6ProtocolError,
    load_json_strict,
    sha256_file,
    validate_depth_projection,
)
from zscope.benchmarking.provider_runtime import (
    P6_PROVIDER_MODEL,
    P6_PROVIDER_RESPONSE_MODEL,
)
from zscope.reporting.finding_roots import _has_complete_deterministic_proof


SCHEMA_VERSION = "zscope.p6-balanced-quality-gate.v1"
FAILURE_AGGREGATE_SCHEMA_VERSION = "zscope.p6-balanced-quality-aggregate.v1"
MAX_BALANCED_TOKENS = 11_999_999
LEGACY_TRUTH_COUNT = 136
V16_PRODUCT_TRUTH_COUNT = 61
V16_DESIGN_RISK_TRUTH_COUNT = 75


class P6BalancedQualityGateError(ValueError):
    """A frozen P6 quality input is missing, inconsistent, or below a gate."""


class P6BalancedQualityGateFailure(P6BalancedQualityGateError):
    """A fully validated score bundle missed a hard gate.

    ``aggregate`` is deliberately answer-free: it contains only integer
    counters and already-computed invariant booleans.  It never carries
    matched IDs, source locations, Truth rows, or scorer diagnostics.
    """

    def __init__(self, aggregate: Mapping[str, Any]) -> None:
        super().__init__("P6 balanced hard quality gate failed")
        self.aggregate = dict(aggregate)


_BINDING_FIELDS = frozenset(
    {
        "git_commit",
        "git_tree",
        "candidate_sha256",
        "provider_identity_sha256",
        "runtime_sha256",
        "config_sha256",
        "oci_image_digest",
        "cold_cache_identity",
        "selected_attempt_id",
    }
)
_VIEW_FIELDS = frozenset(
    {
        "ground_truth_count",
        "true_positives",
        "false_negatives",
        "false_positives_raw",
        "matched",
    }
)
_BUNDLE_FILES = {
    "bindings": "bindings.json",
    "frozen_manifest": "frozen-manifest.json",
    "legacy_score": "legacy-score.json",
    "producer_projection": "producer-projection.json",
    "report": "frozen-report.json",
    "usage_evidence": "usage-evidence.json",
    "v16_score": "v16-score.json",
}
_BUNDLE_GATE = "p6-balanced-quality-gate.json"


def _exact_fields(
    value: Any, expected: set[str] | frozenset[str], *, field: str
) -> Mapping[str, Any]:
    row = _mapping(value, field=field)
    if set(row) != set(expected):
        raise P6BalancedQualityGateError(f"{field} does not match the v1 schema")
    return row


def _boolean_map(
    value: Any, expected: set[str] | frozenset[str], *, field: str
) -> Mapping[str, Any]:
    row = _exact_fields(value, expected, field=field)
    if any(item is not True for item in row.values()):
        raise P6BalancedQualityGateError(f"{field} contains a failed invariant")
    return row


def _validate_output_view(
    value: Any,
    *,
    field: str,
    expected_truth_count: int,
    hard_min_tp: int,
    hard_precision_multiple: int,
    challenge_min_tp: int,
    challenge_precision_numerator: int,
    challenge_precision_denominator: int = 1,
    exact_tp: int | None = None,
) -> Mapping[str, Any]:
    row = _exact_fields(
        value,
        {
            "ground_truth_count",
            "true_positives",
            "false_negatives",
            "false_positives_raw",
            "actionable_denominator",
            "matched_sha256",
            "hard",
            "challenge",
        },
        field=field,
    )
    for name in (
        "ground_truth_count",
        "true_positives",
        "false_negatives",
        "false_positives_raw",
        "actionable_denominator",
    ):
        _integer(row[name], field=f"{field}.{name}")
    truth_count = _integer(row["ground_truth_count"], field=f"{field}.ground_truth_count")
    tp = _integer(row["true_positives"], field=f"{field}.true_positives")
    fn = _integer(row["false_negatives"], field=f"{field}.false_negatives")
    raw_fp = _integer(row["false_positives_raw"], field=f"{field}.false_positives_raw")
    actionable = _integer(row["actionable_denominator"], field=f"{field}.actionable_denominator")
    if truth_count != expected_truth_count:
        raise P6BalancedQualityGateError(f"{field} has the wrong truth denominator")
    if tp + fn != truth_count:
        raise P6BalancedQualityGateError(f"{field} does not conserve its denominator")
    if tp + raw_fp != actionable:
        raise P6BalancedQualityGateError(f"{field} does not conserve its actionable denominator")
    if re.fullmatch(r"[0-9a-f]{64}", str(row["matched_sha256"])) is None:
        raise P6BalancedQualityGateError(f"{field}.matched_sha256 is invalid")
    expected_decisions = {
        "hard": {
            "tp": tp == exact_tp if exact_tp is not None else tp >= hard_min_tp,
            "actionable_precision_cross_product": tp >= hard_precision_multiple * raw_fp,
        },
        "challenge": {
            "tp": tp >= challenge_min_tp,
            "actionable_precision_cross_product": (
                challenge_precision_denominator * tp >= challenge_precision_numerator * raw_fp
            ),
        },
    }
    for decision, expected in expected_decisions.items():
        decision_row = _exact_fields(
            row[decision],
            {"tp", "actionable_precision_cross_product", "passed"},
            field=f"{field}.{decision}",
        )
        if any(not isinstance(item, bool) for item in decision_row.values()):
            raise P6BalancedQualityGateError(f"{field}.{decision} is invalid")
        expected_passed = expected["tp"] and expected["actionable_precision_cross_product"]
        if (
            decision_row["tp"] is not expected["tp"]
            or decision_row["actionable_precision_cross_product"]
            is not expected["actionable_precision_cross_product"]
            or decision_row["passed"] is not expected_passed
        ):
            raise P6BalancedQualityGateError(
                f"{field}.{decision} does not match the fixed integer threshold"
            )
    return row


def validate_quality_gate(value: Mapping[str, Any]) -> None:
    """Validate a persisted v1 gate with the same closed shape as its schema."""

    root = _exact_fields(
        value,
        {
            "schema_version",
            "bindings",
            "artifacts",
            "legacy_v15",
            "truth_v16",
            "cross_view",
            "balanced_scan_usage",
            "producer_invariants",
            "invariants",
            "hard_gate_passed",
            "challenge_passed",
            "formal_benchmark",
            "release_eligible",
            "content_sha256",
        },
        field="quality gate",
    )
    if (
        root["schema_version"] != SCHEMA_VERSION
        or not isinstance(root["hard_gate_passed"], bool)
        or not isinstance(root["challenge_passed"], bool)
        or root["formal_benchmark"] is not False
        or root["release_eligible"] is not False
    ):
        raise P6BalancedQualityGateError("quality gate constants are invalid")
    supplied = str(root["content_sha256"])
    unsigned = dict(root)
    unsigned.pop("content_sha256", None)
    if supplied != _sha256_value(unsigned):
        raise P6BalancedQualityGateError("quality gate content SHA-256 is invalid")
    _validate_bindings(_mapping(root["bindings"], field="quality gate.bindings"))
    artifacts = _exact_fields(
        root["artifacts"],
        {
            "bindings",
            "frozen_manifest",
            "legacy_score",
            "producer_projection",
            "report",
            "usage_evidence",
            "v16_score",
        },
        field="quality gate.artifacts",
    )
    for name, item in artifacts.items():
        row = _exact_fields(item, {"sha256"}, field=f"quality gate.artifacts.{name}")
        if re.fullmatch(r"[0-9a-f]{64}", str(row["sha256"])) is None:
            raise P6BalancedQualityGateError("quality gate artifact SHA-256 is invalid")
    legacy = _exact_fields(
        root["legacy_v15"], {"default", "with_needs_review"}, field="quality gate.legacy_v15"
    )
    truth = _exact_fields(
        root["truth_v16"], {"product", "design_risk"}, field="quality gate.truth_v16"
    )
    product = _exact_fields(
        truth["product"], {"default", "with_needs_review"}, field="quality gate.truth_v16.product"
    )
    view_rows = (
        _validate_output_view(
            legacy["default"],
            field="quality gate.legacy_v15.default",
            expected_truth_count=LEGACY_TRUTH_COUNT,
            hard_min_tp=82,
            hard_precision_multiple=4,
            challenge_min_tp=96,
            challenge_precision_numerator=9,
        ),
        _validate_output_view(
            legacy["with_needs_review"],
            field="quality gate.legacy_v15.with_needs_review",
            expected_truth_count=LEGACY_TRUTH_COUNT,
            hard_min_tp=125,
            hard_precision_multiple=1,
            challenge_min_tp=125,
            challenge_precision_numerator=3,
            challenge_precision_denominator=2,
        ),
        _validate_output_view(
            product["default"],
            field="quality gate.truth_v16.product.default",
            expected_truth_count=V16_PRODUCT_TRUTH_COUNT,
            hard_min_tp=37,
            hard_precision_multiple=4,
            challenge_min_tp=43,
            challenge_precision_numerator=9,
        ),
        _validate_output_view(
            product["with_needs_review"],
            field="quality gate.truth_v16.product.with_needs_review",
            expected_truth_count=V16_PRODUCT_TRUTH_COUNT,
            hard_min_tp=61,
            hard_precision_multiple=1,
            challenge_min_tp=61,
            challenge_precision_numerator=3,
            challenge_precision_denominator=2,
            exact_tp=61,
        ),
    )
    design = _exact_fields(
        truth["design_risk"],
        {"default", "with_needs_review"},
        field="quality gate.truth_v16.design_risk",
    )
    for name in ("default", "with_needs_review"):
        row = _exact_fields(
            design[name],
            {
                "truth_count",
                "true_positives",
                "false_negatives",
                "matched_sha256",
                "counting_contract",
            },
            field=f"quality gate.truth_v16.design_risk.{name}",
        )
        if (
            row["truth_count"] != V16_DESIGN_RISK_TRUTH_COUNT
            or _integer(row["true_positives"], field="design TP")
            + _integer(row["false_negatives"], field="design FN")
            != V16_DESIGN_RISK_TRUTH_COUNT
            or row["counting_contract"] != "separate_from_product_quality_gates"
            or re.fullmatch(r"[0-9a-f]{64}", str(row["matched_sha256"])) is None
        ):
            raise P6BalancedQualityGateError("quality gate design-risk projection is invalid")
    cross_view = _boolean_map(
        root["cross_view"],
        {"legacy_v15", "truth_v16_product"},
        field="quality gate.cross_view",
    )
    usage = _exact_fields(
        root["balanced_scan_usage"],
        {
            "total_tokens",
            "maximum_tokens",
            "provider_usage_coverage",
            "estimated_call_count",
            "provider_response_model_missing_count",
            "provider_response_model_mismatch_count",
            "requested_model_mismatch_count",
            "admission_request_count",
            "admission_admitted_count",
            "admission_denied_count",
            "soft_watermark_denied_count",
            "hard_limit_denied_count",
            "retry_conservation",
            "dimensions",
            "gates",
            "passed",
        },
        field="quality gate.balanced_scan_usage",
    )
    if (
        _integer(usage["total_tokens"], field="quality gate total tokens") > MAX_BALANCED_TOKENS
        or usage["maximum_tokens"] != MAX_BALANCED_TOKENS
        or usage["provider_usage_coverage"] != 1.0
        or any(
            usage[name] != 0
            for name in (
                "estimated_call_count",
                "provider_response_model_missing_count",
                "provider_response_model_mismatch_count",
                "requested_model_mismatch_count",
            )
        )
        or _integer(usage["hard_limit_denied_count"], field="hard admission denials") != 0
        or usage["passed"] is not True
    ):
        raise P6BalancedQualityGateError("quality gate usage evidence is invalid")
    usage_dimensions = _boolean_map(
        usage["dimensions"],
        {"call", "finding", "terminal", "token", "tool", "trace"},
        field="quality gate usage dimensions",
    )
    usage_gates = _boolean_map(
        usage["gates"],
        {
            "usage_complete",
            "usage_coverage",
            "no_estimated_calls",
            "model_identity",
            "queue_drained",
            "token_ledger_matches_score",
            "token_conservation",
            "token_limit",
            "admission_conservation",
            "no_hard_limit_denials",
            "retry_bounds",
        },
        field="quality gate usage gates",
    )
    retry = _exact_fields(
        usage["retry_conservation"],
        {
            "maximum_transport_retries",
            "maximum_contract_regenerations",
            "logical_call_chain_count",
            "physical_attempt_count",
            "pre_model_rejection_count",
            "transport_retry_count",
            "maximum_observed_attempt_index",
            "contract_regeneration_operation_count",
            "maximum_observed_contract_regenerations",
        },
        field="quality gate retry conservation",
    )
    if (
        retry["maximum_transport_retries"] != 1
        or retry["maximum_contract_regenerations"] != 1
        or _integer(retry["maximum_observed_attempt_index"], field="retry attempt index") > 2
        or _integer(
            retry["maximum_observed_contract_regenerations"],
            field="contract regeneration count",
        )
        > 1
    ):
        raise P6BalancedQualityGateError("quality gate retry conservation is invalid")
    producer_invariants = _boolean_map(
        root["producer_invariants"],
        {
            "git_commit",
            "git_tree",
            "candidate",
            "provider",
            "runtime",
            "oci_image",
            "cold_cache",
            "selected_attempt",
            "formal_benchmark_false",
            "release_eligible_false",
        },
        field="quality gate producer invariants",
    )
    invariants = _boolean_map(
        root["invariants"],
        {
            "scanner_answer_isolated",
            "queue_drained",
            "report_view_membership_conserved",
            "terminal_outcome_conserved",
            "default_is_subset_of_with_needs_review",
            "v16_design_risk_separate",
            "formal_benchmark_false",
            "release_eligible_false",
        },
        field="quality gate invariants",
    )
    expected_hard = (
        all(row["hard"]["passed"] is True for row in view_rows)
        and usage["passed"] is True
        and all(item is True for item in usage_dimensions.values())
        and all(item is True for item in usage_gates.values())
        and all(item is True for item in producer_invariants.values())
        and all(item is True for item in invariants.values())
        and all(item is True for item in cross_view.values())
    )
    expected_challenge = all(row["challenge"]["passed"] is True for row in view_rows)
    if root["hard_gate_passed"] is not expected_hard or expected_hard is not True:
        raise P6BalancedQualityGateError("quality gate hard decision is inconsistent")
    if root["challenge_passed"] is not expected_challenge:
        raise P6BalancedQualityGateError("quality gate challenge decision is inconsistent")


def load_quality_gate(path: Path) -> dict[str, Any]:
    """Load and validate one aggregate gate shape.

    This is not authoritative evidence validation because matched-set subset
    membership and input hashes require the accompanying score bundle.  Formal
    consumers must call :func:`validate_quality_gate_bundle`.
    """

    value = _load_object(path, field="quality gate")
    validate_quality_gate(value)
    return value


def validate_quality_gate_bundle(root: Path) -> dict[str, Any]:
    """Rebuild a persisted gate from its exact post-freeze scoring materials.

    A content hash authenticates bytes, not the computation that produced
    them.  Review and final-seal consumers therefore accept a quality gate
    only together with the exact frozen inputs it hashes.  Rebuilding also
    independently proves matched-set subset semantics that cannot be recovered
    from the public aggregate hashes alone.
    """

    if root.is_symlink() or not root.is_dir():
        raise P6BalancedQualityGateError("quality gate bundle must be a directory")
    expected_names = {*_BUNDLE_FILES.values(), _BUNDLE_GATE}
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise P6BalancedQualityGateError("quality gate bundle cannot be read") from exc
    if {entry.name for entry in entries} != expected_names or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise P6BalancedQualityGateError("quality gate bundle members are invalid")

    paths = {name: root / filename for name, filename in _BUNDLE_FILES.items()}
    supplied = load_quality_gate(root / _BUNDLE_GATE)
    artifact_sha256s = {name: _sha256_file(path) for name, path in paths.items()}
    supplied_artifacts = _mapping(supplied["artifacts"], field="quality gate.artifacts")
    if any(
        _mapping(supplied_artifacts.get(name), field=f"quality gate.artifacts.{name}").get("sha256")
        != digest
        for name, digest in artifact_sha256s.items()
    ):
        raise P6BalancedQualityGateError("quality gate bundle digest binding is invalid")

    rebuilt = build_quality_gate(
        report=_load_object(paths["report"], field="report"),
        legacy_score=_load_object(paths["legacy_score"], field="legacy score"),
        v16_score=_load_object(paths["v16_score"], field="v16 score"),
        producer_projection=_load_object(paths["producer_projection"], field="producer projection"),
        bindings=_load_object(paths["bindings"], field="bindings"),
        frozen_manifest=_load_object(paths["frozen_manifest"], field="frozen manifest"),
        usage_evidence=_load_object(paths["usage_evidence"], field="usage evidence"),
        artifact_sha256s=artifact_sha256s,
    )
    if rebuilt != supplied:
        raise P6BalancedQualityGateError("quality gate bundle does not reproduce the gate")
    return supplied


def _mapping(value: Any, *, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise P6BalancedQualityGateError(f"{field} must be an object")
    return value


def _integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise P6BalancedQualityGateError(f"{field} must be a non-negative integer")
    return int(value)


def _sha256_value(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return sha256_file(path)
    except P6ProtocolError as exc:
        raise P6BalancedQualityGateError("quality artifact cannot be securely hashed") from exc


def _load_object(path: Path, *, field: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise P6BalancedQualityGateError(f"{field} must be a regular file")
    try:
        value = load_json_strict(path)
    except (OSError, UnicodeError, json.JSONDecodeError, P6ProtocolError) as exc:
        raise P6BalancedQualityGateError(f"{field} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise P6BalancedQualityGateError(f"{field} must contain a JSON object")
    return value


def _validate_bindings(value: Mapping[str, Any]) -> dict[str, str]:
    if set(value) != _BINDING_FIELDS:
        missing = sorted(_BINDING_FIELDS - set(value))
        unknown = sorted(set(value) - _BINDING_FIELDS)
        raise P6BalancedQualityGateError(
            f"binding fields do not match v1: missing={missing}; unknown={unknown}"
        )
    output: dict[str, str] = {}
    for field in sorted(_BINDING_FIELDS):
        text = str(value[field]).strip()
        if not text:
            raise P6BalancedQualityGateError(f"binding {field} must be non-empty")
        output[field] = text
    for field in (
        "candidate_sha256",
        "provider_identity_sha256",
        "runtime_sha256",
        "config_sha256",
        "cold_cache_identity",
    ):
        if re.fullmatch(r"[0-9a-f]{64}", output[field]) is None:
            raise P6BalancedQualityGateError(f"binding {field} must be a lowercase SHA-256")
    for field in ("git_commit", "git_tree"):
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", output[field]) is None:
            raise P6BalancedQualityGateError(f"binding {field} must be a lowercase Git object ID")
    if (
        not output["oci_image_digest"].startswith("sha256:")
        or re.fullmatch(r"sha256:[0-9a-f]{64}", output["oci_image_digest"]) is None
    ):
        raise P6BalancedQualityGateError(
            "binding oci_image_digest must be a sha256-pinned image digest"
        )
    return output


def _view_metrics(
    value: Mapping[str, Any],
    *,
    field: str,
    expected_truth_count: int,
    hard_min_tp: int,
    hard_precision_multiple: int,
    challenge_min_tp: int,
    challenge_precision_numerator: int,
    challenge_precision_denominator: int = 1,
    exact_tp: int | None = None,
) -> dict[str, Any]:
    missing = _VIEW_FIELDS - set(value)
    if missing:
        raise P6BalancedQualityGateError(f"{field} is missing {sorted(missing)}")
    truth_count = _integer(value["ground_truth_count"], field=f"{field}.ground_truth_count")
    tp = _integer(value["true_positives"], field=f"{field}.true_positives")
    fn = _integer(value["false_negatives"], field=f"{field}.false_negatives")
    raw_fp = _integer(value["false_positives_raw"], field=f"{field}.false_positives_raw")
    if truth_count != expected_truth_count:
        raise P6BalancedQualityGateError(
            f"{field}.ground_truth_count={truth_count}, expected {expected_truth_count}"
        )
    if tp + fn != truth_count:
        raise P6BalancedQualityGateError(f"{field} TP/FN do not conserve the truth denominator")
    if tp > truth_count:
        raise P6BalancedQualityGateError(f"{field}.true_positives exceeds the truth denominator")
    matched = value["matched"]
    if not isinstance(matched, list) or any(
        not isinstance(item, str) or not item for item in matched
    ):
        raise P6BalancedQualityGateError(f"{field}.matched must be a non-empty-string array")
    if len(set(matched)) != len(matched) or len(matched) != tp:
        raise P6BalancedQualityGateError(f"{field}.matched does not bind one unique ID per TP")

    tp_gate = tp == exact_tp if exact_tp is not None else tp >= hard_min_tp
    precision_gate = tp >= hard_precision_multiple * raw_fp
    challenge_tp_gate = tp >= challenge_min_tp
    challenge_precision_gate = (
        challenge_precision_denominator * tp >= challenge_precision_numerator * raw_fp
    )
    return {
        "ground_truth_count": truth_count,
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives_raw": raw_fp,
        "actionable_denominator": tp + raw_fp,
        "matched_sha256": _sha256_value(sorted(matched)),
        "hard": {
            "tp": tp_gate,
            "actionable_precision_cross_product": precision_gate,
            "passed": tp_gate and precision_gate,
        },
        "challenge": {
            "tp": challenge_tp_gate,
            "actionable_precision_cross_product": challenge_precision_gate,
            "passed": challenge_tp_gate and challenge_precision_gate,
        },
        "_matched": frozenset(matched),
    }


def _usage_evidence(
    legacy_score: Mapping[str, Any], *, confirmed_terminal_count: int
) -> dict[str, Any]:
    usage = _mapping(legacy_score.get("usage_accounting"), field="legacy.usage_accounting")
    totals = _mapping(usage.get("totals"), field="legacy.usage_accounting.totals")
    conservation = _mapping(legacy_score.get("p6_conservation"), field="legacy.p6_conservation")
    dimensions = _mapping(conservation.get("dimensions"), field="legacy.p6_conservation.dimensions")
    required_dimensions = frozenset({"call", "token", "tool", "trace", "finding", "terminal"})
    # Older P6 producers expose physical calls as a scalar rather than a
    # dimension.  Bind that scalar as the call conservation evidence.
    dimension_names = set(dimensions)
    if "call" not in dimension_names:
        physical = _integer(
            conservation.get("physical_call_count"),
            field="legacy.p6_conservation.physical_call_count",
        )
        provider = _integer(
            conservation.get("provider_reported_call_count"),
            field="legacy.p6_conservation.provider_reported_call_count",
        )
        dimensions = {
            **dimensions,
            "call": {
                "numerator": provider,
                "denominator": physical,
                "conserved": provider == physical,
            },
        }
        dimension_names.add("call")
    if not required_dimensions.issubset(dimension_names):
        raise P6BalancedQualityGateError(
            "p6 conservation is missing dimensions "
            + ",".join(sorted(required_dimensions - dimension_names))
        )
    conserved: dict[str, bool] = {}
    for name in sorted(required_dimensions):
        row = _mapping(dimensions[name], field=f"legacy.p6_conservation.dimensions.{name}")
        numerator = _integer(row.get("numerator"), field=f"usage.{name}.numerator")
        denominator = _integer(row.get("denominator"), field=f"usage.{name}.denominator")
        conserved[name] = row.get("conserved") is True and numerator == denominator

    total_tokens = _integer(
        totals.get("total_tokens"), field="legacy.usage_accounting.totals.total_tokens"
    )
    score_tokens = _integer(legacy_score.get("tokens"), field="legacy.tokens")
    estimated = max(
        _integer(
            totals.get("estimated_or_conservative_calls", 0),
            field="legacy.usage_accounting.totals.estimated_or_conservative_calls",
        ),
        _integer(
            conservation.get("estimated_call_count"),
            field="legacy.p6_conservation.estimated_call_count",
        ),
    )
    coverage = usage.get("provider_usage_coverage")
    if (
        isinstance(coverage, bool)
        or not isinstance(coverage, (int, float))
        or not math.isfinite(float(coverage))
    ):
        raise P6BalancedQualityGateError("provider usage coverage must be numeric")
    identity_counts = {
        field: _integer(legacy_score.get(field), field=f"legacy.{field}")
        for field in (
            "provider_response_model_missing_count",
            "provider_response_model_mismatch_count",
            "requested_model_mismatch_count",
        )
    }
    producer_completeness = {
        "estimated_provider_call_count": _integer(
            legacy_score.get("estimated_provider_call_count"),
            field="legacy.estimated_provider_call_count",
        ),
        "failed_or_unknown_call_count": _integer(
            legacy_score.get("failed_or_unknown_call_count"),
            field="legacy.failed_or_unknown_call_count",
        ),
        "budget_violation_count": _integer(
            legacy_score.get("budget_violation_count"),
            field="legacy.budget_violation_count",
        ),
        "protocol_anomaly_count": _integer(
            legacy_score.get("protocol_anomaly_count"),
            field="legacy.protocol_anomaly_count",
        ),
    }
    telemetry_complete_rate = legacy_score.get("telemetry_complete_rate")
    producer_usage_coverage = legacy_score.get("provider_usage_coverage")
    response_model_coverage = legacy_score.get("provider_response_model_coverage")
    successful_response_count = _integer(
        legacy_score.get("provider_response_model_successful_call_count"),
        field="legacy.provider_response_model_successful_call_count",
    )
    response_model_counts = _mapping(
        legacy_score.get("provider_response_model_counts"),
        field="legacy.provider_response_model_counts",
    )
    accepted_response_models = {P6_PROVIDER_MODEL, P6_PROVIDER_RESPONSE_MODEL}
    if set(response_model_counts) != accepted_response_models:
        raise P6BalancedQualityGateError("provider response model count identity is invalid")
    accepted_response_count = sum(
        _integer(
            response_model_counts[name],
            field=f"legacy.provider_response_model_counts.{name}",
        )
        for name in sorted(accepted_response_models)
    )
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        for value in (
            telemetry_complete_rate,
            producer_usage_coverage,
            response_model_coverage,
        )
    ):
        raise P6BalancedQualityGateError("producer completeness rates must be numeric")
    telemetry_complete_rate_value = float(telemetry_complete_rate)  # type: ignore[arg-type]
    producer_usage_coverage_value = float(producer_usage_coverage)  # type: ignore[arg-type]
    response_model_coverage_value = float(response_model_coverage)  # type: ignore[arg-type]
    authority = _exact_fields(
        legacy_score.get("p6_terminal_authority"),
        {
            "terminal_trace_count",
            "confirmed_terminal_count",
            "confirmed_v4_report_count",
            "confirmed_v4_trace_count",
            "post_terminal_model_call_count",
            "post_terminal_tool_call_count",
            "call_trace_conservation_passed",
            "tool_trace_conservation_passed",
            "model_event_trace_conservation_passed",
            "passed",
        },
        field="legacy.p6_terminal_authority",
    )
    authority_counts = {
        name: _integer(authority.get(name), field=f"legacy.p6_terminal_authority.{name}")
        for name in (
            "terminal_trace_count",
            "confirmed_terminal_count",
            "confirmed_v4_report_count",
            "confirmed_v4_trace_count",
            "post_terminal_model_call_count",
            "post_terminal_tool_call_count",
        )
    }
    authority_conserved = bool(
        authority.get("passed") is True
        and authority.get("call_trace_conservation_passed") is True
        and authority.get("tool_trace_conservation_passed") is True
        and authority.get("model_event_trace_conservation_passed") is True
        and authority_counts["confirmed_terminal_count"] == confirmed_terminal_count
        and authority_counts["confirmed_v4_report_count"] == confirmed_terminal_count
        and authority_counts["confirmed_v4_trace_count"] == confirmed_terminal_count
        and authority_counts["post_terminal_model_call_count"] == 0
        and authority_counts["post_terminal_tool_call_count"] == 0
    )
    admission = _mapping(
        legacy_score.get("p6_admission_conservation"),
        field="legacy.p6_admission_conservation",
    )
    admission_counts = {
        name: _integer(admission.get(name), field=f"legacy.p6_admission_conservation.{name}")
        for name in (
            "request_count",
            "admitted_request_count",
            "denied_request_count",
        )
    }
    denied_reasons = _mapping(
        admission.get("denied_reasons"),
        field="legacy.p6_admission_conservation.denied_reasons",
    )
    if set(denied_reasons) - {"p6_token_soft_watermark", "p6_token_hard_limit"}:
        raise P6BalancedQualityGateError("P6 admission denial reason is invalid")
    soft_denials = _integer(
        denied_reasons.get("p6_token_soft_watermark", 0),
        field="legacy P6 soft admission denials",
    )
    hard_denials = _integer(
        denied_reasons.get("p6_token_hard_limit", 0),
        field="legacy P6 hard admission denials",
    )
    admission_conserved = bool(
        admission.get("enabled") is True
        and admission.get("request_conservation_passed") is True
        and admission.get("zero_call_denial_conservation_passed") is True
        and admission_counts["request_count"]
        == admission_counts["admitted_request_count"] + admission_counts["denied_request_count"]
        and admission_counts["denied_request_count"] == soft_denials + hard_denials
    )
    retry = _exact_fields(
        legacy_score.get("p6_retry_conservation"),
        {
            "maximum_transport_retries",
            "maximum_contract_regenerations",
            "logical_call_chain_count",
            "physical_attempt_count",
            "pre_model_rejection_count",
            "transport_retry_count",
            "maximum_observed_attempt_index",
            "contract_regeneration_operation_count",
            "maximum_observed_contract_regenerations",
            "call_chain_conservation_passed",
            "contract_regeneration_conservation_passed",
            "passed",
        },
        field="legacy.p6_retry_conservation",
    )
    retry_counts = {
        name: _integer(retry.get(name), field=f"legacy.p6_retry_conservation.{name}")
        for name in (
            "maximum_transport_retries",
            "maximum_contract_regenerations",
            "logical_call_chain_count",
            "physical_attempt_count",
            "pre_model_rejection_count",
            "transport_retry_count",
            "maximum_observed_attempt_index",
            "contract_regeneration_operation_count",
            "maximum_observed_contract_regenerations",
        )
    }
    retry_conserved = bool(
        retry.get("passed") is True
        and retry.get("call_chain_conservation_passed") is True
        and retry.get("contract_regeneration_conservation_passed") is True
        and retry_counts["maximum_transport_retries"] == 1
        and retry_counts["maximum_contract_regenerations"] == 1
        and retry_counts["maximum_observed_attempt_index"] <= 2
        and retry_counts["maximum_observed_contract_regenerations"] <= 1
    )
    gates = {
        "usage_complete": bool(
            usage.get("complete") is True
            and not any(producer_completeness.values())
            and telemetry_complete_rate_value == 1.0
            and producer_usage_coverage_value == 1.0
            and response_model_coverage_value == 1.0
            and legacy_score.get("provider_response_model_counts_conserved") is True
            and accepted_response_count == successful_response_count
            and producer_completeness["estimated_provider_call_count"] == estimated
            and producer_usage_coverage_value == float(coverage)
            and authority_conserved
        ),
        "usage_coverage": float(coverage) == 1.0,
        "no_estimated_calls": estimated == 0,
        "model_identity": not any(identity_counts.values()),
        "queue_drained": legacy_score.get("queue_empty") is True
        and conservation.get("queue_empty") is True,
        "token_ledger_matches_score": total_tokens == score_tokens,
        "token_conservation": usage.get("conservation_passed") is True
        and legacy_score.get("token_conservation_passed") is True
        and all(conserved.values()),
        "token_limit": total_tokens <= MAX_BALANCED_TOKENS,
        "admission_conservation": admission_conserved,
        "no_hard_limit_denials": hard_denials == 0,
        "retry_bounds": retry_conserved,
    }
    return {
        "total_tokens": total_tokens,
        "maximum_tokens": MAX_BALANCED_TOKENS,
        "provider_usage_coverage": float(coverage),
        "estimated_call_count": estimated,
        **identity_counts,
        "admission_request_count": admission_counts["request_count"],
        "admission_admitted_count": admission_counts["admitted_request_count"],
        "admission_denied_count": admission_counts["denied_request_count"],
        "soft_watermark_denied_count": soft_denials,
        "hard_limit_denied_count": hard_denials,
        "retry_conservation": {**retry_counts},
        "dimensions": conserved,
        "gates": gates,
        "passed": all(gates.values()),
    }


def _producer_invariants(
    value: Mapping[str, Any], *, bindings: Mapping[str, str]
) -> dict[str, bool]:
    """Revalidate the exact cold-balanced producer projection.

    The gate never trusts its own non-release flags.  They come from the
    answer-free projection sealed by the cold producer and are cross-bound to
    the same Git/provider/runtime/OCI/cache/attempt identity as the score.
    """

    try:
        validate_depth_projection(value, scan_depth="balanced")
    except P6ProtocolError as exc:
        raise P6BalancedQualityGateError("balanced producer projection is invalid") from exc
    candidate_sha = hashlib.sha256(bindings["git_commit"].encode("utf-8")).hexdigest()
    gates = {
        "git_commit": value.get("git_sha") == bindings["git_commit"],
        "git_tree": value.get("git_tree") == bindings["git_tree"],
        "candidate": candidate_sha == bindings["candidate_sha256"],
        "provider": (value.get("provider_identity_sha256") == bindings["provider_identity_sha256"]),
        "runtime": value.get("runtime_source_sha256") == bindings["runtime_sha256"],
        "oci_image": value.get("oci_image_digest") == bindings["oci_image_digest"],
        "cold_cache": (value.get("cache_identity_sha256") == bindings["cold_cache_identity"]),
        "selected_attempt": (value.get("producer_attempt_id") == bindings["selected_attempt_id"]),
        "formal_benchmark_false": value.get("formal_benchmark") is False,
        "release_eligible_false": value.get("release_eligible") is False,
    }
    if not all(gates.values()):
        raise P6BalancedQualityGateError("balanced producer projection binding is invalid")
    return gates


def _strip_private_matched(value: dict[str, Any]) -> tuple[dict[str, Any], frozenset[str]]:
    matched = value.pop("_matched")
    assert isinstance(matched, frozenset)
    return value, matched


def _aggregate_view(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "truth_count": int(value["ground_truth_count"]),
        "true_positives": int(value["true_positives"]),
        "false_negatives": int(value["false_negatives"]),
        "false_positives_raw": int(value["false_positives_raw"]),
        "hard_passed": value["hard"]["passed"] is True,
        "challenge_passed": value["challenge"]["passed"] is True,
    }


def _report_invariants(report: Mapping[str, Any]) -> tuple[dict[str, bool], int]:
    """Recompute actual dual-view membership from the frozen report bytes."""

    from zscope.reporting.schema import report_invariant_status, terminal_candidate_identity

    raw_terminal = report.get("candidate_terminal_states")
    raw_issues = report.get("issues")
    if (
        not isinstance(raw_terminal, list)
        or any(not isinstance(item, Mapping) for item in raw_terminal)
        or not isinstance(raw_issues, list)
        or any(not isinstance(item, Mapping) for item in raw_issues)
    ):
        raise P6BalancedQualityGateError("frozen report terminal collections are malformed")
    terminal = [dict(item) for item in raw_terminal]
    issues = [dict(item) for item in raw_issues]
    observations = [
        item
        for item in terminal
        if str(item.get("candidate_disposition") or "").lower() == "needs_review"
    ]
    metadata = _mapping(report.get("metadata"), field="report.metadata")
    raw_audit = metadata.get("audit_observations")
    audit_count = metadata.get("audit_observation_count")
    if (
        not isinstance(raw_audit, list)
        or any(not isinstance(item, Mapping) for item in raw_audit)
        or isinstance(audit_count, bool)
        or not isinstance(audit_count, int)
        or audit_count != len(raw_audit)
    ):
        raise P6BalancedQualityGateError("frozen report audit observations are malformed")
    audit_items = [dict(item) for item in raw_audit]
    terminal_audit = [
        item
        for item in terminal
        if str(item.get("candidate_disposition") or "").lower() == "shadow_observation"
    ]
    audit_identities = [terminal_candidate_identity(item) for item in audit_items]
    terminal_audit_identities = [terminal_candidate_identity(item) for item in terminal_audit]
    audit_conserved = bool(
        all(audit_identities)
        and all(terminal_audit_identities)
        and len(audit_identities) == len(set(audit_identities))
        and len(terminal_audit_identities) == len(set(terminal_audit_identities))
        and set(audit_identities) == set(terminal_audit_identities)
        and len(audit_items) == len(terminal_audit)
    )
    views = _mapping(report.get("report_views"), field="report.report_views")
    default = _mapping(views.get("default"), field="report.report_views.default")
    with_review = _mapping(
        views.get("with_needs_review"), field="report.report_views.with_needs_review"
    )
    default_items = default.get("issues")
    with_review_items = with_review.get("issues")
    if not isinstance(default_items, list) or not isinstance(with_review_items, list):
        raise P6BalancedQualityGateError("frozen report views are unavailable")
    status = report_invariant_status(
        issues,
        observations,
        terminal,
        canonical_projection=True,
        default_items=default_items,
        with_needs_review_items=with_review_items,
    )
    confirmed = [
        item
        for item in terminal
        if str(item.get("candidate_disposition") or "").lower() == "confirmed"
        and str(item.get("record_role") or "") != "operational_obligation"
    ]
    confirmed_v4 = all(_has_complete_deterministic_proof(item) for item in confirmed)
    return {
        "report_view_membership_conserved": (
            status.get("valid") is True
            and status.get("view_membership_conservation_passed") is True
            and status.get("actual_default_membership_exact") is True
            and status.get("actual_with_needs_review_membership_exact") is True
        ),
        "terminal_outcome_conserved": (
            status.get("terminal_outcome_conservation_passed") is True
            and int(status.get("open_evidence_completion_count") or 0) == 0
            and int(status.get("open_validation_group_count") or 0) == 0
            and audit_conserved
            and confirmed_v4
        ),
    }, len(confirmed)


def _build_failure_aggregate(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project a hard-gate miss to answer-free aggregate counters only."""

    legacy = _mapping(payload["legacy_v15"], field="quality gate.legacy_v15")
    truth = _mapping(payload["truth_v16"], field="quality gate.truth_v16")
    product = _mapping(truth["product"], field="quality gate.truth_v16.product")
    design = _mapping(truth["design_risk"], field="quality gate.truth_v16.design_risk")
    usage = _mapping(payload["balanced_scan_usage"], field="quality gate.balanced_scan_usage")
    aggregate: dict[str, Any] = {
        "schema_version": FAILURE_AGGREGATE_SCHEMA_VERSION,
        "evidence_binding_sha256": _sha256_value(
            {
                "bindings": payload["bindings"],
                "artifacts": payload["artifacts"],
            }
        ),
        "legacy_v15": {
            "default": _aggregate_view(
                _mapping(legacy["default"], field="quality gate.legacy_v15.default")
            ),
            "with_needs_review": _aggregate_view(
                _mapping(
                    legacy["with_needs_review"],
                    field="quality gate.legacy_v15.with_needs_review",
                )
            ),
        },
        "truth_v16_product": {
            "default": _aggregate_view(
                _mapping(product["default"], field="quality gate.truth_v16.product.default")
            ),
            "with_needs_review": _aggregate_view(
                _mapping(
                    product["with_needs_review"],
                    field="quality gate.truth_v16.product.with_needs_review",
                )
            ),
        },
        "truth_v16_design_risk": {
            name: {
                "truth_count": int(design[name]["truth_count"]),
                "true_positives": int(design[name]["true_positives"]),
                "false_negatives": int(design[name]["false_negatives"]),
            }
            for name in ("default", "with_needs_review")
        },
        "cross_view": dict(payload["cross_view"]),
        "balanced_scan_usage": {
            name: usage[name]
            for name in (
                "total_tokens",
                "maximum_tokens",
                "provider_usage_coverage",
                "estimated_call_count",
                "provider_response_model_missing_count",
                "provider_response_model_mismatch_count",
                "requested_model_mismatch_count",
                "admission_request_count",
                "admission_admitted_count",
                "admission_denied_count",
                "soft_watermark_denied_count",
                "hard_limit_denied_count",
                "passed",
            )
        },
        "producer_invariants": dict(payload["producer_invariants"]),
        "invariants": dict(payload["invariants"]),
        "hard_gate_passed": False,
        "challenge_passed": payload["challenge_passed"] is True,
        "answer_material_present": False,
        "formal_benchmark": False,
        "release_eligible": False,
    }
    aggregate["content_sha256"] = _sha256_value(aggregate)
    validate_quality_failure_aggregate(aggregate)
    return aggregate


def _validate_failure_view(
    value: Any,
    *,
    field: str,
    truth_count: int,
    hard_min_tp: int,
    hard_precision_multiple: int,
    challenge_min_tp: int,
    challenge_precision_numerator: int,
    challenge_precision_denominator: int = 1,
    exact_tp: int | None = None,
) -> None:
    row = _exact_fields(
        value,
        {
            "truth_count",
            "true_positives",
            "false_negatives",
            "false_positives_raw",
            "hard_passed",
            "challenge_passed",
        },
        field=field,
    )
    tp = _integer(row["true_positives"], field=f"{field}.true_positives")
    fn = _integer(row["false_negatives"], field=f"{field}.false_negatives")
    fp = _integer(row["false_positives_raw"], field=f"{field}.false_positives_raw")
    if row["truth_count"] != truth_count or tp + fn != truth_count:
        raise P6BalancedQualityGateError(f"{field} denominator is invalid")
    if not isinstance(row["hard_passed"], bool) or not isinstance(row["challenge_passed"], bool):
        raise P6BalancedQualityGateError(f"{field} decisions are invalid")
    expected_hard = (
        tp == exact_tp if exact_tp is not None else tp >= hard_min_tp
    ) and tp >= hard_precision_multiple * fp
    expected_challenge = (
        tp >= challenge_min_tp
        and challenge_precision_denominator * tp >= challenge_precision_numerator * fp
    )
    if row["hard_passed"] is not expected_hard or row["challenge_passed"] is not expected_challenge:
        raise P6BalancedQualityGateError(f"{field} decisions are inconsistent")


def validate_quality_failure_aggregate(value: Mapping[str, Any]) -> None:
    """Validate the closed, answer-free projection emitted only on a hard miss."""

    root = _exact_fields(
        value,
        {
            "schema_version",
            "evidence_binding_sha256",
            "legacy_v15",
            "truth_v16_product",
            "truth_v16_design_risk",
            "cross_view",
            "balanced_scan_usage",
            "producer_invariants",
            "invariants",
            "hard_gate_passed",
            "challenge_passed",
            "answer_material_present",
            "formal_benchmark",
            "release_eligible",
            "content_sha256",
        },
        field="quality failure aggregate",
    )
    supplied = root["content_sha256"]
    unsigned = dict(root)
    unsigned.pop("content_sha256", None)
    if (
        root["schema_version"] != FAILURE_AGGREGATE_SCHEMA_VERSION
        or re.fullmatch(r"[0-9a-f]{64}", str(root["evidence_binding_sha256"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(supplied)) is None
        or supplied != _sha256_value(unsigned)
        or root["hard_gate_passed"] is not False
        or not isinstance(root["challenge_passed"], bool)
        or root["answer_material_present"] is not False
        or root["formal_benchmark"] is not False
        or root["release_eligible"] is not False
    ):
        raise P6BalancedQualityGateError("quality failure aggregate constants are invalid")
    legacy = _exact_fields(
        root["legacy_v15"], {"default", "with_needs_review"}, field="aggregate.legacy_v15"
    )
    product = _exact_fields(
        root["truth_v16_product"],
        {"default", "with_needs_review"},
        field="aggregate.truth_v16_product",
    )
    specifications = (
        (legacy["default"], "aggregate.legacy_v15.default", 136, 82, 4, 96, 9, 1, None),
        (
            legacy["with_needs_review"],
            "aggregate.legacy_v15.with_needs_review",
            136,
            125,
            1,
            125,
            3,
            2,
            None,
        ),
        (product["default"], "aggregate.truth_v16_product.default", 61, 37, 4, 43, 9, 1, None),
        (
            product["with_needs_review"],
            "aggregate.truth_v16_product.with_needs_review",
            61,
            61,
            1,
            61,
            3,
            2,
            61,
        ),
    )
    for (
        row,
        field,
        count,
        hard_tp,
        hard_multiple,
        challenge_tp,
        challenge_n,
        challenge_d,
        exact,
    ) in specifications:
        _validate_failure_view(
            row,
            field=field,
            truth_count=count,
            hard_min_tp=hard_tp,
            hard_precision_multiple=hard_multiple,
            challenge_min_tp=challenge_tp,
            challenge_precision_numerator=challenge_n,
            challenge_precision_denominator=challenge_d,
            exact_tp=exact,
        )
    design = _exact_fields(
        root["truth_v16_design_risk"],
        {"default", "with_needs_review"},
        field="aggregate.truth_v16_design_risk",
    )
    for name in ("default", "with_needs_review"):
        row = _exact_fields(
            design[name],
            {"truth_count", "true_positives", "false_negatives"},
            field=f"aggregate.truth_v16_design_risk.{name}",
        )
        tp = _integer(row["true_positives"], field="design-risk true positives")
        fn = _integer(row["false_negatives"], field="design-risk false negatives")
        if (
            row["truth_count"] != V16_DESIGN_RISK_TRUTH_COUNT
            or tp + fn != V16_DESIGN_RISK_TRUTH_COUNT
        ):
            raise P6BalancedQualityGateError("quality failure design-risk aggregate is invalid")
    cross = _exact_fields(
        root["cross_view"], {"legacy_v15", "truth_v16_product"}, field="aggregate.cross_view"
    )
    if any(not isinstance(item, bool) for item in cross.values()):
        raise P6BalancedQualityGateError("quality failure cross-view aggregate is invalid")
    usage = _exact_fields(
        root["balanced_scan_usage"],
        {
            "total_tokens",
            "maximum_tokens",
            "provider_usage_coverage",
            "estimated_call_count",
            "provider_response_model_missing_count",
            "provider_response_model_mismatch_count",
            "requested_model_mismatch_count",
            "admission_request_count",
            "admission_admitted_count",
            "admission_denied_count",
            "soft_watermark_denied_count",
            "hard_limit_denied_count",
            "passed",
        },
        field="aggregate.balanced_scan_usage",
    )
    for name in (
        "total_tokens",
        "maximum_tokens",
        "estimated_call_count",
        "provider_response_model_missing_count",
        "provider_response_model_mismatch_count",
        "requested_model_mismatch_count",
        "admission_request_count",
        "admission_admitted_count",
        "admission_denied_count",
        "soft_watermark_denied_count",
        "hard_limit_denied_count",
    ):
        _integer(usage[name], field=f"aggregate.balanced_scan_usage.{name}")
    if (
        isinstance(usage["provider_usage_coverage"], bool)
        or not isinstance(usage["provider_usage_coverage"], (int, float))
        or not math.isfinite(float(usage["provider_usage_coverage"]))
        or usage["maximum_tokens"] != MAX_BALANCED_TOKENS
        or not isinstance(usage["passed"], bool)
    ):
        raise P6BalancedQualityGateError("quality failure usage aggregate is invalid")
    for name, expected in (
        ("producer_invariants", _producer_gate_names()),
        ("invariants", _invariant_gate_names()),
    ):
        row = _exact_fields(root[name], expected, field=f"aggregate.{name}")
        if any(not isinstance(item, bool) for item in row.values()):
            raise P6BalancedQualityGateError(f"aggregate.{name} is invalid")
    view_rows = [
        legacy["default"],
        legacy["with_needs_review"],
        product["default"],
        product["with_needs_review"],
    ]
    expected_hard = (
        all(row["hard_passed"] is True for row in view_rows)
        and usage["passed"] is True
        and all(cross.values())
        and all(root["producer_invariants"].values())
        and all(root["invariants"].values())
    )
    expected_challenge = all(row["challenge_passed"] is True for row in view_rows)
    if expected_hard is not False or root["challenge_passed"] is not expected_challenge:
        raise P6BalancedQualityGateError("quality failure root decisions are inconsistent")


def _producer_gate_names() -> frozenset[str]:
    return frozenset(
        {
            "git_commit",
            "git_tree",
            "candidate",
            "provider",
            "runtime",
            "oci_image",
            "cold_cache",
            "selected_attempt",
            "formal_benchmark_false",
            "release_eligible_false",
        }
    )


def _invariant_gate_names() -> frozenset[str]:
    return frozenset(
        {
            "scanner_answer_isolated",
            "queue_drained",
            "report_view_membership_conserved",
            "terminal_outcome_conserved",
            "default_is_subset_of_with_needs_review",
            "v16_design_risk_separate",
            "formal_benchmark_false",
            "release_eligible_false",
        }
    )


def build_quality_gate(
    *,
    report: Mapping[str, Any],
    legacy_score: Mapping[str, Any],
    v16_score: Mapping[str, Any],
    producer_projection: Mapping[str, Any],
    bindings: Mapping[str, Any],
    frozen_manifest: Mapping[str, Any],
    usage_evidence: Mapping[str, Any],
    artifact_sha256s: Mapping[str, str],
) -> dict[str, Any]:
    """Build and validate the immutable P6 balanced quality gate object."""

    frozen_bindings = _validate_bindings(bindings)
    if set(artifact_sha256s) != {
        "bindings",
        "frozen_manifest",
        "report",
        "legacy_score",
        "v16_score",
        "producer_projection",
        "usage_evidence",
    }:
        raise P6BalancedQualityGateError("artifact SHA-256 map must bind every bundle input")
    for name, digest in artifact_sha256s.items():
        if re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None:
            raise P6BalancedQualityGateError(f"artifact {name} has an invalid SHA-256")
    frozen = _exact_fields(
        frozen_manifest,
        {
            "schema_version",
            "workflow_run_id",
            "workflow_run_attempt",
            "control_plane_commit",
            "candidate_git_sha",
            "candidate_git_tree",
            "attempt_id",
            "report_sha256",
            "bindings_sha256",
            "usage_evidence_sha256",
            "projection_sha256",
            "answer_material_present",
            "formal_benchmark",
            "release_eligible",
            "content_sha256",
        },
        field="frozen manifest",
    )
    frozen_unsigned = dict(frozen)
    frozen_content = frozen_unsigned.pop("content_sha256", None)
    if (
        frozen.get("schema_version") != "zscope.p6-balanced-frozen-scan.v1"
        or frozen_content != _sha256_value(frozen_unsigned)
        or frozen.get("candidate_git_sha") != frozen_bindings["git_commit"]
        or frozen.get("candidate_git_tree") != frozen_bindings["git_tree"]
        or frozen.get("attempt_id") != frozen_bindings["selected_attempt_id"]
        or frozen.get("report_sha256") != artifact_sha256s["report"]
        or frozen.get("bindings_sha256") != artifact_sha256s["bindings"]
        or frozen.get("usage_evidence_sha256") != artifact_sha256s["usage_evidence"]
        or frozen.get("projection_sha256") != artifact_sha256s["producer_projection"]
        or frozen.get("answer_material_present") is not False
        or frozen.get("formal_benchmark") is not False
        or frozen.get("release_eligible") is not False
    ):
        raise P6BalancedQualityGateError("frozen manifest binding is invalid")
    usage_row = _exact_fields(
        usage_evidence,
        {
            "schema_version",
            "workflow_run_id",
            "workflow_run_attempt",
            "attempt_id",
            "score_fields",
            "answer_material_present",
            "formal_benchmark",
            "release_eligible",
            "content_sha256",
        },
        field="usage evidence",
    )
    usage_unsigned = dict(usage_row)
    usage_content = usage_unsigned.pop("content_sha256", None)
    score_fields = _mapping(usage_row.get("score_fields"), field="usage evidence.score_fields")
    expected_usage_fields = {
        "tokens",
        "queue_empty",
        "token_conservation_passed",
        "provider_response_model_missing_count",
        "provider_response_model_mismatch_count",
        "requested_model_mismatch_count",
        "provider_usage_coverage",
        "provider_response_model_coverage",
        "provider_response_model_successful_call_count",
        "provider_response_model_counts",
        "provider_response_model_counts_conserved",
        "estimated_provider_call_count",
        "failed_or_unknown_call_count",
        "budget_violation_count",
        "telemetry_complete_rate",
        "protocol_anomaly_count",
        "usage_accounting",
        "p6_conservation",
        "p6_admission_conservation",
        "p6_retry_conservation",
        "p6_terminal_authority",
    }
    if (
        usage_row.get("schema_version") != "zscope.p6-balanced-usage-evidence.v1"
        or usage_content != _sha256_value(usage_unsigned)
        or usage_row.get("workflow_run_id") != frozen.get("workflow_run_id")
        or usage_row.get("workflow_run_attempt") != frozen.get("workflow_run_attempt")
        or usage_row.get("attempt_id") != frozen.get("attempt_id")
        or usage_row.get("answer_material_present") is not False
        or usage_row.get("formal_benchmark") is not False
        or usage_row.get("release_eligible") is not False
        or set(score_fields) != expected_usage_fields
        or any(legacy_score.get(name) != score_fields.get(name) for name in expected_usage_fields)
    ):
        raise P6BalancedQualityGateError("usage evidence binding is invalid")
    frozen_report_sha256 = artifact_sha256s["report"]
    for field, score in (("legacy", legacy_score), ("v16", v16_score)):
        if score.get("p6_frozen_report_sha256") != frozen_report_sha256:
            raise P6BalancedQualityGateError(
                f"{field} score is not bound to the exact frozen report"
            )

    legacy_views = _mapping(legacy_score.get("report_views"), field="legacy.report_views")
    legacy_default, legacy_default_ids = _strip_private_matched(
        _view_metrics(
            _mapping(legacy_views.get("default"), field="legacy.report_views.default"),
            field="legacy.default",
            expected_truth_count=LEGACY_TRUTH_COUNT,
            hard_min_tp=82,
            hard_precision_multiple=4,
            challenge_min_tp=96,
            challenge_precision_numerator=9,
        )
    )
    legacy_review, legacy_review_ids = _strip_private_matched(
        _view_metrics(
            _mapping(
                legacy_views.get("with_needs_review"),
                field="legacy.report_views.with_needs_review",
            ),
            field="legacy.with_needs_review",
            expected_truth_count=LEGACY_TRUTH_COUNT,
            hard_min_tp=125,
            hard_precision_multiple=1,
            challenge_min_tp=125,
            challenge_precision_numerator=3,
            challenge_precision_denominator=2,
        )
    )

    product = _mapping(v16_score.get("product"), field="v16.product")
    v16_default, v16_default_ids = _strip_private_matched(
        _view_metrics(
            _mapping(product.get("default"), field="v16.product.default"),
            field="v16.product.default",
            expected_truth_count=V16_PRODUCT_TRUTH_COUNT,
            hard_min_tp=37,
            hard_precision_multiple=4,
            challenge_min_tp=43,
            challenge_precision_numerator=9,
        )
    )
    v16_review, v16_review_ids = _strip_private_matched(
        _view_metrics(
            _mapping(product.get("with_needs_review"), field="v16.product.with_needs_review"),
            field="v16.product.with_needs_review",
            expected_truth_count=V16_PRODUCT_TRUTH_COUNT,
            hard_min_tp=61,
            hard_precision_multiple=1,
            challenge_min_tp=61,
            challenge_precision_numerator=3,
            challenge_precision_denominator=2,
            exact_tp=61,
        )
    )

    design = _mapping(v16_score.get("design_risk"), field="v16.design_risk")
    design_projection: dict[str, Any] = {}
    for name in ("default", "with_needs_review"):
        row = _mapping(design.get(name), field=f"v16.design_risk.{name}")
        truth_count = _integer(row.get("truth_count"), field=f"v16.design_risk.{name}.truth_count")
        tp = _integer(row.get("true_positives"), field=f"v16.design_risk.{name}.true_positives")
        matched = row.get("matched")
        if truth_count != V16_DESIGN_RISK_TRUTH_COUNT:
            raise P6BalancedQualityGateError(
                f"v16.design_risk.{name}.truth_count must be {V16_DESIGN_RISK_TRUTH_COUNT}"
            )
        if (
            tp > truth_count
            or not isinstance(matched, list)
            or any(not isinstance(item, str) or not item for item in matched)
            or len(set(matched)) != tp
            or len(matched) != tp
        ):
            raise P6BalancedQualityGateError(f"v16.design_risk.{name}.matched is inconsistent")
        design_projection[name] = {
            "truth_count": truth_count,
            "true_positives": tp,
            "false_negatives": truth_count - tp,
            "matched_sha256": _sha256_value(sorted(matched)),
            "counting_contract": "separate_from_product_quality_gates",
        }

    default_subset = {
        "legacy_v15": legacy_default_ids.issubset(legacy_review_ids),
        "truth_v16_product": v16_default_ids.issubset(v16_review_ids),
    }
    report_invariants, confirmed_terminal_count = _report_invariants(report)
    usage = _usage_evidence(
        legacy_score,
        confirmed_terminal_count=confirmed_terminal_count,
    )
    producer = _producer_invariants(producer_projection, bindings=frozen_bindings)
    quality_rows = (legacy_default, legacy_review, v16_default, v16_review)
    hard_passed = all(row["hard"]["passed"] for row in quality_rows)
    challenge_passed = all(row["challenge"]["passed"] for row in quality_rows)
    report_manifest = _mapping(report.get("run_manifest"), field="report.run_manifest")
    invariants = {
        "scanner_answer_isolated": report.get("answer_material_present") is False,
        "queue_drained": report_manifest.get("validation_queue_drained") is True,
        **report_invariants,
        "default_is_subset_of_with_needs_review": all(default_subset.values()),
        "v16_design_risk_separate": True,
        "formal_benchmark_false": producer["formal_benchmark_false"],
        "release_eligible_false": producer["release_eligible_false"],
    }
    gate_passed = (
        hard_passed
        and usage["passed"]
        and all(default_subset.values())
        and all(producer.values())
        and all(invariants.values())
    )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "bindings": frozen_bindings,
        "artifacts": {
            name: {"sha256": artifact_sha256s[name]} for name in sorted(artifact_sha256s)
        },
        "legacy_v15": {
            "default": legacy_default,
            "with_needs_review": legacy_review,
        },
        "truth_v16": {
            "product": {
                "default": v16_default,
                "with_needs_review": v16_review,
            },
            "design_risk": design_projection,
        },
        "cross_view": default_subset,
        "balanced_scan_usage": usage,
        "producer_invariants": producer,
        "invariants": invariants,
        "hard_gate_passed": gate_passed,
        "challenge_passed": challenge_passed,
        "formal_benchmark": False,
        "release_eligible": False,
    }
    unsigned = dict(payload)
    payload["content_sha256"] = _sha256_value(unsigned)
    if not gate_passed:
        raise P6BalancedQualityGateFailure(_build_failure_aggregate(payload))
    validate_quality_gate(payload)
    return payload


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--legacy-score", type=Path, required=True)
    parser.add_argument("--v16-score", type=Path, required=True)
    parser.add_argument("--producer-projection", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--frozen-manifest", type=Path, required=True)
    parser.add_argument("--usage-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-aggregate", type=Path)
    return parser


def _write_failure_aggregate(path: Path, value: Mapping[str, Any]) -> None:
    validate_quality_failure_aggregate(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise P6BalancedQualityGateError("quality failure aggregate output already exists")
    encoded = (
        json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    with path.open("xb") as stream:
        stream.write(encoded)


def main(argv: Sequence[str] | None = None) -> int:
    args: argparse.Namespace | None = None
    try:
        args = _parser().parse_args(argv)
        report = _load_object(args.report, field="report")
        legacy = _load_object(args.legacy_score, field="legacy score")
        v16 = _load_object(args.v16_score, field="v16 score")
        producer = _load_object(args.producer_projection, field="producer projection")
        bindings = _load_object(args.bindings, field="bindings")
        frozen_manifest = _load_object(args.frozen_manifest, field="frozen manifest")
        usage_evidence = _load_object(args.usage_evidence, field="usage evidence")
        result = build_quality_gate(
            report=report,
            legacy_score=legacy,
            v16_score=v16,
            producer_projection=producer,
            bindings=bindings,
            frozen_manifest=frozen_manifest,
            usage_evidence=usage_evidence,
            artifact_sha256s={
                "bindings": _sha256_file(args.bindings),
                "frozen_manifest": _sha256_file(args.frozen_manifest),
                "report": _sha256_file(args.report),
                "legacy_score": _sha256_file(args.legacy_score),
                "v16_score": _sha256_file(args.v16_score),
                "producer_projection": _sha256_file(args.producer_projection),
                "usage_evidence": _sha256_file(args.usage_evidence),
            },
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists() or args.output.is_symlink():
            raise P6BalancedQualityGateError("quality gate output already exists")
        args.output.write_text(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n",
            encoding="utf-8",
        )
        load_quality_gate(args.output)
        return 0
    except P6BalancedQualityGateFailure as exc:
        try:
            if args is not None and args.failure_aggregate is not None:
                _write_failure_aggregate(args.failure_aggregate, exc.aggregate)
        except (P6BalancedQualityGateError, OSError, UnicodeError, json.JSONDecodeError):
            pass
        print(
            "stage=report_finding; class=quality_no_progress_gate_failed:1; count=1",
            file=sys.stderr,
        )
        return 2
    except (P6BalancedQualityGateError, OSError, UnicodeError, json.JSONDecodeError):
        print(
            "stage=report_finding; class=quality_no_progress_gate_failed:1; count=1",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
