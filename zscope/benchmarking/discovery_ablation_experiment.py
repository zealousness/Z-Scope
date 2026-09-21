"""Independent post-scoring for frozen D0-D4 discovery ablation runs.

The scanner-facing ablation protocol is answer-free.  This module keeps that
boundary explicit: it freezes and validates the plan, all 25 execution
artifacts, all 25 corresponding scanner reports, and all 25 raw usage
sidecars before opening benchmark truth for the first time.  It never
executes a scanner or a model.
"""

from __future__ import annotations

import copy
import hashlib
import json
import statistics
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .discovery_ablation import (
    ABLATION_ARM_IDS,
    ABLATION_COLD_TRIALS,
    ABLATION_EXECUTION_SCHEMA_VERSION,
    ABLATION_EXPECTED_MAX_TOKENS,
    DiscoveryAblationError,
    build_discovery_ablation_run_request,
    discovery_ablation_runtime_override_from_request,
    load_discovery_ablation_plan,
    validate_discovery_ablation_execution,
    validate_discovery_ablation_report,
    validate_discovery_ablation_usage_sidecar,
)
from .protocol import aggregate_usage_ledger, score_report_views
from .replay_bundle import canonical_json_sha256
from ..framework.llm_usage import TOKEN_USAGE_STAGES


DISCOVERY_ABLATION_EXPERIMENT_SCHEMA_VERSION = "zscope.discovery-ablation-experiment.v1"

TrialKey = Tuple[str, int]

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "scorer",
        "inputs",
        "contract",
        "arms",
        "interpretation",
        "release_eligible",
        "experiment_sha256",
    }
)
_SCORER_FIELDS = frozenset({"component", "revision", "source_sha256", "line_tolerance"})
_INPUT_FIELDS = frozenset({"plan", "truth", "runs"})
_PLAN_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "plan_sha256",
        "file_sha256",
        "dataset_id",
        "answer_free_input_payload_sha256",
        "config_identity_sha256",
        "validator_config_sha256",
        "validator_arm_spec_sha256",
        "catalog_sha256",
    }
)
_TRUTH_INPUT_FIELDS = frozenset(
    {
        "benchmark",
        "suite",
        "version",
        "ground_truth_count",
        "safe_entry_count",
        "file_sha256",
        "payload_sha256",
    }
)
_RUN_INPUT_FIELDS = frozenset(
    {
        "arm_id",
        "trial_index",
        "run_id",
        "request_sha256",
        "execution_schema_version",
        "execution_sha256",
        "execution_file_sha256",
        "report_sha256",
        "report_file_sha256",
        "usage_sidecar_name",
        "usage_sidecar_sha256",
        "executor_sha256",
        "release_eligible",
    }
)
_CONTRACT_FIELDS = frozenset(
    {
        "scoring_order",
        "required_arms",
        "trials_per_arm",
        "scan_depth",
        "per_run_cost_expectation_tokens",
        "cache_mode",
        "cold_trials_attested",
        "fixed_plan_identity",
        "fixed_config_identity",
        "fixed_validator_identity",
        "truth_loaded_by",
        "model_execution",
        "release_policy",
        "warm_cache_benefit_policy",
    }
)
_ARM_FIELDS = frozenset(
    {
        "arm_id",
        "arm_revision",
        "arm_spec_sha256",
        "baseline",
        "cost_upper_bound",
        "role",
        "trial_count",
        "configured_cost_expectation_tokens",
        "trials",
        "aggregates",
        "warm_cache_benefit",
        "release_eligible",
    }
)
_TRIAL_FIELDS = frozenset(
    {
        "trial_index",
        "run_id",
        "execution_sha256",
        "report_sha256",
        "usage_sidecar_sha256",
        "completeness",
        "total_tokens",
        "usage",
        "views",
        "warm_cache_benefit",
        "release_eligible",
    }
)
_USAGE_FIELDS = frozenset(
    {
        "complete",
        "conservation_passed",
        "telemetry_complete",
        "call_count",
        "provider_reported_call_count",
        "provider_usage_coverage",
        "prompt_tokens",
        "cached_prompt_tokens",
        "completion_tokens",
        "reasoning_tokens",
        "total_tokens",
        "by_agent",
        "by_stage",
    }
)
_VIEW_FIELDS = frozenset(
    {
        "report_issue_count",
        "true_positives",
        "recall",
        "false_positives_raw",
        "actionable_precision",
        "actionable_false_discovery_rate",
        "true_positive_truth_ids",
        "discovery",
        "tokens_per_exclusive_true_positive",
    }
)
_DISCOVERY_FIELDS = frozenset(
    {
        "by_source",
        "exclusive_by_source",
        "source_set_outcomes",
        "intersections_by_source_set",
        "counting_contract",
    }
)
_AGGREGATE_FIELDS = frozenset({"cost", "views", "discovery"})
_VIEW_AGGREGATE_FIELDS = frozenset(
    {"metric_distributions", "true_positive_jaccard", "recall_range_pp"}
)
_INTERPRETATION_FIELDS = frozenset(
    {
        "quality_comparable_arms",
        "cost_upper_bound_arms",
        "selection_performed",
        "release_use",
    }
)
_WARM_CACHE_FIELDS = frozenset({"available", "value", "unit", "reason"})
_DISTRIBUTION_FIELDS = frozenset({"count", "minimum", "maximum", "median", "p50", "p95", "range"})


class DiscoveryAblationExperimentError(ValueError):
    """Raised when frozen D0-D4 artifacts cannot be independently scored."""


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256_bytes(Path(path).read_bytes())
    except OSError as exc:
        raise DiscoveryAblationExperimentError(
            f"cannot hash ablation scorer input: {path}"
        ) from exc


def _strict_json_bytes(raw: bytes, *, label: str) -> Dict[str, Any]:
    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DiscoveryAblationExperimentError(
                    f"{label} contains duplicate JSON key: {key}"
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise DiscoveryAblationExperimentError(f"{label} contains non-finite JSON value: {value}")

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DiscoveryAblationExperimentError(f"{label} must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise DiscoveryAblationExperimentError(f"{label} must be a JSON object")
    return value


def _stable_json_load(path: Path, *, label: str) -> Tuple[Dict[str, Any], str]:
    selected = Path(path)
    try:
        before = selected.read_bytes()
        value = _strict_json_bytes(before, label=label)
        after = selected.read_bytes()
    except OSError as exc:
        raise DiscoveryAblationExperimentError(f"cannot load {label}: {selected}") from exc
    if before != after:
        raise DiscoveryAblationExperimentError(f"{label} changed while it was being frozen")
    from ..reporting.shared_objects import decode_storage
    return decode_storage(value), _sha256_bytes(before)


def _stable_plan_load(path: Path, *, expected_plan_sha256: str) -> Tuple[Dict[str, Any], str]:
    selected = Path(path)
    try:
        before = selected.read_bytes()
        plan = load_discovery_ablation_plan(
            selected,
            expected_plan_sha256=expected_plan_sha256,
        )
        after = selected.read_bytes()
    except (OSError, DiscoveryAblationError) as exc:
        raise DiscoveryAblationExperimentError(str(exc)) from exc
    if before != after:
        raise DiscoveryAblationExperimentError("ablation plan changed while it was being frozen")
    return plan, _sha256_bytes(before)


def _stable_usage_load(path: Path, *, expected_sha256: str) -> Dict[str, Any]:
    selected = Path(path)
    try:
        before = selected.read_bytes()
        evidence = dict(
            validate_discovery_ablation_usage_sidecar(
                selected,
                expected_sha256=expected_sha256,
            )
        )
        after = selected.read_bytes()
    except (OSError, DiscoveryAblationError) as exc:
        raise DiscoveryAblationExperimentError(str(exc)) from exc
    if before != after:
        raise DiscoveryAblationExperimentError(
            "ablation usage sidecar changed while it was being frozen"
        )
    return evidence


def _require_external_hash(value: Any, *, label: str) -> str:
    if not _is_sha256(value):
        raise DiscoveryAblationExperimentError(f"{label} must be a lowercase SHA-256")
    return str(value)


def _expected_trial_keys() -> set[TrialKey]:
    return {
        (arm_id, trial_index)
        for arm_id in ABLATION_ARM_IDS
        for trial_index in range(1, ABLATION_COLD_TRIALS + 1)
    }


def _validate_truth(truth: Mapping[str, Any]) -> None:
    vulnerabilities = truth.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise DiscoveryAblationExperimentError(
            "ablation truth must contain a non-empty vulnerabilities array"
        )
    if truth.get("total_vulnerabilities") is not None and truth.get("total_vulnerabilities") != len(
        vulnerabilities
    ):
        raise DiscoveryAblationExperimentError(
            "truth total_vulnerabilities does not match vulnerabilities"
        )
    truth_ids: list[str] = []
    for index, raw in enumerate(vulnerabilities):
        if not isinstance(raw, Mapping):
            raise DiscoveryAblationExperimentError(
                f"truth vulnerabilities[{index}] is not an object"
            )
        identity = raw.get("id")
        if not isinstance(identity, str) or not identity.strip():
            raise DiscoveryAblationExperimentError(
                f"truth vulnerabilities[{index}] has no stable id"
            )
        truth_ids.append(identity)
    if len(set(truth_ids)) != len(truth_ids):
        raise DiscoveryAblationExperimentError("truth vulnerability ids are not unique")
    safe_entries = truth.get("safe_entries", [])
    if not isinstance(safe_entries, list) or any(
        not isinstance(value, Mapping) for value in safe_entries
    ):
        raise DiscoveryAblationExperimentError("truth safe_entries must be an array of objects")


def _validate_report_scoring_shape(report: Mapping[str, Any], *, label: str) -> None:
    if report.get("schema_version") not in {2, "2", "zscope.report.v2"}:
        raise DiscoveryAblationExperimentError(f"{label} is not a supported Z-SCOPE report")
    views = report.get("report_views")
    if not isinstance(views, Mapping):
        raise DiscoveryAblationExperimentError(f"{label} has no report_views object")
    for view_name in ("default", "with_needs_review"):
        view = views.get(view_name)
        if not isinstance(view, Mapping) or not isinstance(view.get("issues"), list):
            raise DiscoveryAblationExperimentError(
                f"{label} cannot provide the required {view_name} scoring view"
            )
        if any(not isinstance(issue, Mapping) for issue in view["issues"]):
            raise DiscoveryAblationExperimentError(
                f"{label} {view_name} issues must contain only objects"
            )


def _validate_usage(report: Mapping[str, Any], *, expected_total_tokens: int) -> Dict[str, Any]:
    ledger = aggregate_usage_ledger(dict(report))
    if (
        ledger.get("present") is not True
        or ledger.get("complete") is not True
        or ledger.get("conservation_passed") is not True
        or ledger.get("telemetry_complete") is not True
    ):
        errors = "; ".join(str(value) for value in ledger.get("errors") or [])
        raise DiscoveryAblationExperimentError(
            "ablation report usage ledger is missing or incomplete"
            + (f": {errors}" if errors else "")
        )
    totals = ledger.get("totals")
    if not isinstance(totals, Mapping):
        raise DiscoveryAblationExperimentError("ablation report usage totals are missing")
    total_tokens = totals.get("total_tokens")
    if (
        isinstance(total_tokens, bool)
        or not isinstance(total_tokens, int)
        or total_tokens != expected_total_tokens
    ):
        raise DiscoveryAblationExperimentError(
            "ablation report usage total does not match the frozen budget settlement"
        )
    request_count = totals.get("request_count", ledger.get("call_count"))
    successful_calls = totals.get("successful_calls", ledger.get("provider_reported_call_count"))
    if (
        isinstance(request_count, bool)
        or not isinstance(request_count, int)
        or isinstance(successful_calls, bool)
        or not isinstance(successful_calls, int)
        or request_count != successful_calls
        or successful_calls != int(ledger["provider_reported_call_count"])
        or int(totals.get("denied_requests") or 0) != 0
        or int(totals.get("failed_or_unknown_calls") or 0) != 0
        or int(totals.get("budget_violation_count") or 0) != 0
        or float(ledger["provider_usage_coverage"]) != 1.0
    ):
        raise DiscoveryAblationExperimentError(
            "ablation report requires one provider usage settlement per admitted request"
        )
    prompt_tokens = totals.get("prompt_tokens")
    completion_tokens = totals.get("completion_tokens")
    if (
        isinstance(prompt_tokens, bool)
        or not isinstance(prompt_tokens, int)
        or isinstance(completion_tokens, bool)
        or not isinstance(completion_tokens, int)
        or prompt_tokens + completion_tokens != total_tokens
    ):
        raise DiscoveryAblationExperimentError(
            "ablation report raw total must equal prompt plus completion tokens"
        )
    for dimension_name in ("by_agent", "by_stage"):
        dimension = ledger.get(dimension_name)
        if not isinstance(dimension, Mapping) or not dimension:
            raise DiscoveryAblationExperimentError(
                f"ablation report usage {dimension_name} is missing"
            )
        for field in (
            "prompt_tokens",
            "cached_prompt_tokens",
            "completion_tokens",
            "reasoning_tokens",
            "total_tokens",
        ):
            expected = int(totals.get(field) or 0)
            observed = 0
            for row in dimension.values():
                if not isinstance(row, Mapping):
                    raise DiscoveryAblationExperimentError(
                        f"ablation report usage {dimension_name} row is invalid"
                    )
                raw = row.get(field, 0)
                if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
                    raise DiscoveryAblationExperimentError(
                        f"ablation report usage {dimension_name}.{field} is invalid"
                    )
                observed += raw
            if observed != expected:
                raise DiscoveryAblationExperimentError(
                    f"ablation report usage {dimension_name}.{field} does not conserve"
                )
    return {
        "complete": True,
        "conservation_passed": True,
        "telemetry_complete": True,
        "call_count": int(ledger["call_count"]),
        "provider_reported_call_count": int(ledger["provider_reported_call_count"]),
        "provider_usage_coverage": float(ledger["provider_usage_coverage"]),
        "prompt_tokens": prompt_tokens,
        "cached_prompt_tokens": int(totals.get("cached_prompt_tokens") or 0),
        "completion_tokens": completion_tokens,
        "reasoning_tokens": int(totals.get("reasoning_tokens") or 0),
        "total_tokens": total_tokens,
        "by_agent": copy.deepcopy(dict(ledger["by_agent"])),
        "by_stage": copy.deepcopy(dict(ledger["by_stage"])),
    }


def _validate_stage_budget(
    usage: Mapping[str, Any],
    *,
    expected_stage_tokens: Mapping[str, Any],
) -> None:
    raw_expected_budget = {
        "semantic_modeling": expected_stage_tokens.get("semantic_completion"),
        "active_discovery": expected_stage_tokens.get("active_discovery"),
        "validation": expected_stage_tokens.get("validator"),
        "reserve": expected_stage_tokens.get("investigation_remediation_reserve"),
    }
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in raw_expected_budget.values()
    ):
        raise DiscoveryAblationExperimentError("frozen ablation stage budget is invalid")
    expected_budget: Dict[str, int] = {}
    for stage, value in raw_expected_budget.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise DiscoveryAblationExperimentError("frozen ablation stage budget is invalid")
        expected_budget[stage] = value
    if sum(expected_budget.values()) != ABLATION_EXPECTED_MAX_TOKENS:
        raise DiscoveryAblationExperimentError("frozen ablation stage budget is invalid")
    by_stage = usage.get("by_stage")
    if not isinstance(by_stage, Mapping) or not by_stage:
        raise DiscoveryAblationExperimentError("ablation report usage by_stage is missing")
    unknown = sorted(set(str(value) for value in by_stage) - set(TOKEN_USAGE_STAGES))
    if unknown:
        raise DiscoveryAblationExperimentError(
            "ablation usage has unknown budget stages: " + ", ".join(unknown)
        )
    prefix_consumed = 0
    prefix_limit = 0
    for stage in TOKEN_USAGE_STAGES:
        row = by_stage.get(stage, {})
        if row and not isinstance(row, Mapping):
            raise DiscoveryAblationExperimentError(f"ablation usage stage {stage} is not an object")
        raw_tokens = row.get("total_tokens", 0) if isinstance(row, Mapping) else 0
        if isinstance(raw_tokens, bool) or not isinstance(raw_tokens, int) or raw_tokens < 0:
            raise DiscoveryAblationExperimentError(
                f"ablation usage stage {stage} token count is invalid"
            )
        prefix_consumed += raw_tokens
        prefix_limit += expected_budget[stage]
        if prefix_consumed > prefix_limit:
            raise DiscoveryAblationExperimentError(
                f"ablation usage violates forward-only stage budget at {stage}"
            )
    if prefix_consumed != int(usage["total_tokens"]):
        raise DiscoveryAblationExperimentError(
            "ablation stage usage does not conserve the report total"
        )


def _source_set_key(attribution: Mapping[str, Any]) -> str:
    raw = attribution.get("discovered_by")
    sources = sorted(
        {str(value).strip() for value in raw or [] if isinstance(value, str) and str(value).strip()}
    )
    return "+".join(sources or ["unknown"])


def _source_set_outcomes(score: Mapping[str, Any]) -> Dict[str, Dict[str, int]]:
    result: Dict[str, Dict[str, int]] = {}

    def add(attribution: Any, outcome: str) -> None:
        value = attribution if isinstance(attribution, Mapping) else {}
        key = _source_set_key(value)
        row = result.setdefault(
            key,
            {"issues": 0, "true_positives": 0, "raw_false_positives": 0},
        )
        row["issues"] += 1
        row[outcome] += 1

    for pair in score.get("matched_pairs") or []:
        if isinstance(pair, Mapping):
            add(pair.get("attribution"), "true_positives")
    for record in score.get("false_positive_issue_records_raw") or []:
        if isinstance(record, Mapping):
            add(record.get("attribution"), "raw_false_positives")
    return dict(sorted(result.items()))


def _score_view(
    score: Mapping[str, Any],
    *,
    total_tokens: int,
) -> Dict[str, Any]:
    attribution = score.get("attribution")
    if not isinstance(attribution, Mapping):
        raise DiscoveryAblationExperimentError("benchmark scorer did not return attribution")
    by_source = attribution.get("by_discovery")
    exclusive = attribution.get("exclusive_by_discovery")
    if not isinstance(by_source, Mapping) or not isinstance(exclusive, Mapping):
        raise DiscoveryAblationExperimentError(
            "benchmark scorer attribution is not suitable for discovery ablation"
        )
    source_sets = _source_set_outcomes(score)
    intersections = {key: dict(value) for key, value in source_sets.items() if "+" in key}
    tokens_per_exclusive: Dict[str, Optional[float]] = {}
    for source, raw in sorted(exclusive.items()):
        if not isinstance(raw, Mapping):
            raise DiscoveryAblationExperimentError(
                "benchmark scorer exclusive discovery row is invalid"
            )
        true_positives = raw.get("true_positives")
        if isinstance(true_positives, bool) or not isinstance(true_positives, int):
            raise DiscoveryAblationExperimentError(
                "benchmark scorer exclusive discovery TP count is invalid"
            )
        tokens_per_exclusive[str(source)] = (
            total_tokens / true_positives if true_positives else None
        )
    true_positive_ids = score.get("true_positive_truth_ids")
    if not isinstance(true_positive_ids, list) or any(
        not isinstance(value, str) or not value for value in true_positive_ids
    ):
        raise DiscoveryAblationExperimentError("benchmark scorer TP identities are invalid")
    normalized_true_positive_ids = sorted(set(true_positive_ids))
    result: Dict[str, Any] = {
        "report_issue_count": int(score["report_issue_count"]),
        "true_positives": int(score["true_positives"]),
        "recall": float(score["recall"]),
        "false_positives_raw": int(score["false_positives_raw"]),
        "actionable_precision": float(score["actionable_precision"]),
        "actionable_false_discovery_rate": float(score["actionable_false_discovery_rate"]),
        "true_positive_truth_ids": normalized_true_positive_ids,
        "discovery": {
            "by_source": copy.deepcopy(dict(by_source)),
            "exclusive_by_source": copy.deepcopy(dict(exclusive)),
            "source_set_outcomes": source_sets,
            "intersections_by_source_set": intersections,
            "counting_contract": (
                "discovered_by is a set; exclusive rows have one source and intersections "
                "are exact multi-source sets"
            ),
        },
        "tokens_per_exclusive_true_positive": tokens_per_exclusive,
    }
    if len(normalized_true_positive_ids) != int(result["true_positives"]):
        raise DiscoveryAblationExperimentError("benchmark scorer TP identities do not conserve")
    return result


def _distribution(values: Sequence[float | int]) -> Dict[str, Any]:
    if not values:
        raise DiscoveryAblationExperimentError("cannot aggregate an empty metric distribution")
    normalized = [float(value) for value in values]
    p50 = float(statistics.median(normalized))
    p95 = float(statistics.quantiles(normalized, n=100, method="inclusive")[94])
    return {
        "count": len(normalized),
        "minimum": min(normalized),
        "maximum": max(normalized),
        "median": p50,
        "p50": p50,
        "p95": p95,
        "range": max(normalized) - min(normalized),
    }


def _pairwise_jaccard(trials: Sequence[Mapping[str, Any]]) -> Dict[str, float]:
    sets = [set(str(value) for value in trial["true_positive_truth_ids"]) for trial in trials]
    values: list[float] = []
    for index, left in enumerate(sets):
        for right in sets[index + 1 :]:
            union = left | right
            values.append(len(left & right) / len(union) if union else 1.0)
    return {
        "mean_pairwise": sum(values) / len(values) if values else 1.0,
        "minimum_pairwise": min(values) if values else 1.0,
    }


def _aggregate_outcome_rows(
    rows: Sequence[Mapping[str, Mapping[str, int]]],
) -> Dict[str, Dict[str, Dict[str, Any]]]:
    keys = sorted({str(key) for row in rows for key in row})
    result: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for key in keys:
        result[key] = {}
        for metric in ("issues", "true_positives", "raw_false_positives"):
            result[key][metric] = _distribution(
                [int(row.get(key, {}).get(metric, 0)) for row in rows]
            )
    return result


def _aggregate_tokens_per_exclusive(
    trials: Sequence[Mapping[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    sources = sorted(
        {str(source) for trial in trials for source in trial["tokens_per_exclusive_true_positive"]}
    )
    result: Dict[str, Dict[str, Any]] = {}
    for source in sources:
        values = [
            float(value)
            for trial in trials
            for value in [trial["tokens_per_exclusive_true_positive"].get(source)]
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        ]
        result[source] = {
            "available_trial_count": len(values),
            "unavailable_trial_count": len(trials) - len(values),
            "distribution": _distribution(values) if values else None,
        }
    return result


def _warm_cache_unavailable() -> Dict[str, Any]:
    return {
        "available": False,
        "value": None,
        "unit": "fractional_token_reduction",
        "reason": (
            "N/A: the frozen protocol contains isolated cold trials only; no paired warm-cache "
            "run exists"
        ),
    }


def _aggregate_arm_trials(trials: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    cost_fields = (
        "total_tokens",
        "prompt_tokens",
        "cached_prompt_tokens",
        "completion_tokens",
        "reasoning_tokens",
    )
    cost = {
        field: _distribution(
            [
                (
                    int(trial["total_tokens"])
                    if field == "total_tokens"
                    else int(trial["usage"][field])
                )
                for trial in trials
            ]
        )
        for field in cost_fields
    }
    views: Dict[str, Any] = {}
    discovery: Dict[str, Any] = {}
    for view_name in ("confirmed", "with_review"):
        rows = [trial["views"][view_name] for trial in trials]
        metric_names = (
            "report_issue_count",
            "true_positives",
            "recall",
            "false_positives_raw",
            "actionable_precision",
            "actionable_false_discovery_rate",
        )
        recalls = [float(row["recall"]) for row in rows]
        views[view_name] = {
            "metric_distributions": {
                metric: _distribution([row[metric] for row in rows]) for metric in metric_names
            },
            "true_positive_jaccard": _pairwise_jaccard(rows),
            "recall_range_pp": (max(recalls) - min(recalls)) * 100.0,
        }
        discovery[view_name] = {
            "by_source": _aggregate_outcome_rows([row["discovery"]["by_source"] for row in rows]),
            "exclusive_by_source": _aggregate_outcome_rows(
                [row["discovery"]["exclusive_by_source"] for row in rows]
            ),
            "intersections_by_source_set": _aggregate_outcome_rows(
                [row["discovery"]["intersections_by_source_set"] for row in rows]
            ),
            "tokens_per_exclusive_true_positive": _aggregate_tokens_per_exclusive(rows),
        }
    return {"cost": cost, "views": views, "discovery": discovery}


def _arm_spec(plan: Mapping[str, Any], arm_id: str) -> Mapping[str, Any]:
    for row in plan["arms"]:
        spec = row["arm_spec"]
        if isinstance(spec, Mapping) and spec.get("arm_id") == arm_id:
            return spec
    raise DiscoveryAblationExperimentError(f"plan has no ablation arm {arm_id}")


def score_discovery_ablation_experiment(
    *,
    plan_path: Path,
    execution_paths: Mapping[TrialKey, Path],
    report_paths: Mapping[TrialKey, Path],
    usage_sidecar_paths: Mapping[TrialKey, Path],
    truth_path: Path,
    expected_plan_sha256: str,
    expected_truth_sha256: str,
    expected_execution_sha256s: Mapping[TrialKey, str],
    expected_report_sha256s: Mapping[TrialKey, str],
    expected_execution_file_sha256s: Mapping[TrialKey, str],
    expected_report_file_sha256s: Mapping[TrialKey, str],
    expected_usage_sidecar_sha256s: Mapping[TrialKey, str],
    cold_trials_attested: bool,
    line_tolerance: int = 8,
) -> Dict[str, Any]:
    """Freeze 25 answer-free execution/report/usage triples, then score truth."""

    if cold_trials_attested is not True:
        raise DiscoveryAblationExperimentError(
            "D0-D4 scoring requires explicit isolated-cold trial attestation"
        )
    if (
        isinstance(line_tolerance, bool)
        or not isinstance(line_tolerance, int)
        or line_tolerance < 0
    ):
        raise DiscoveryAblationExperimentError("line_tolerance must be a non-negative integer")
    expected_plan = _require_external_hash(
        expected_plan_sha256, label="expected ablation plan SHA-256"
    )
    expected_truth = _require_external_hash(
        expected_truth_sha256, label="expected truth file SHA-256"
    )
    expected_keys = _expected_trial_keys()
    for label, values in (
        ("execution paths", execution_paths),
        ("report paths", report_paths),
        ("expected execution hashes", expected_execution_sha256s),
        ("expected report hashes", expected_report_sha256s),
        ("expected execution file hashes", expected_execution_file_sha256s),
        ("expected report file hashes", expected_report_file_sha256s),
        ("usage sidecar paths", usage_sidecar_paths),
        ("expected usage sidecar hashes", expected_usage_sidecar_sha256s),
    ):
        if set(values) != expected_keys:
            raise DiscoveryAblationExperimentError(f"{label} must bind D0-D4 trials 1-5 exactly")
    resolved_groups = {
        "execution": [Path(value).resolve() for value in execution_paths.values()],
        "report": [Path(value).resolve() for value in report_paths.values()],
        "usage sidecar": [Path(value).resolve() for value in usage_sidecar_paths.values()],
    }
    for label, paths in resolved_groups.items():
        if len(set(paths)) != len(expected_keys):
            raise DiscoveryAblationExperimentError(
                f"isolated-cold trials require 25 distinct {label} paths"
            )
    all_artifact_paths = [path for paths in resolved_groups.values() for path in paths]
    if len(set(all_artifact_paths)) != len(all_artifact_paths):
        raise DiscoveryAblationExperimentError(
            "execution, report, and usage sidecar paths must be mutually distinct"
        )
    protected_paths = {Path(plan_path).resolve(), Path(truth_path).resolve()}
    if len(protected_paths) != 2 or protected_paths.intersection(all_artifact_paths):
        raise DiscoveryAblationExperimentError(
            "plan and truth paths must not alias any frozen run artifact"
        )
    normalized_execution_hashes = {
        key: _require_external_hash(
            value,
            label=f"expected {key[0]} trial {key[1]} execution SHA-256",
        )
        for key, value in expected_execution_sha256s.items()
    }
    normalized_report_hashes = {
        key: _require_external_hash(
            value,
            label=f"expected {key[0]} trial {key[1]} report SHA-256",
        )
        for key, value in expected_report_sha256s.items()
    }
    normalized_execution_file_hashes = {
        key: _require_external_hash(
            value,
            label=f"expected {key[0]} trial {key[1]} execution file SHA-256",
        )
        for key, value in expected_execution_file_sha256s.items()
    }
    normalized_report_file_hashes = {
        key: _require_external_hash(
            value,
            label=f"expected {key[0]} trial {key[1]} report file SHA-256",
        )
        for key, value in expected_report_file_sha256s.items()
    }
    normalized_usage_hashes = {
        key: _require_external_hash(
            value,
            label=f"expected {key[0]} trial {key[1]} usage sidecar SHA-256",
        )
        for key, value in expected_usage_sidecar_sha256s.items()
    }

    # Phase 1: freeze every answer-free input and validate all cross-bindings.
    # Ground truth is deliberately not opened anywhere in this phase.
    plan, plan_file_sha = _stable_plan_load(Path(plan_path), expected_plan_sha256=expected_plan)
    frozen: Dict[TrialKey, Dict[str, Any]] = {}
    run_inputs: list[Dict[str, Any]] = []
    for key in sorted(expected_keys):
        arm_id, trial_index = key
        request = build_discovery_ablation_run_request(
            plan,
            arm_id=arm_id,
            trial_index=trial_index,
            expected_plan_sha256=expected_plan,
        )
        execution, execution_file_sha = _stable_json_load(
            Path(execution_paths[key]), label=f"{arm_id} trial {trial_index} execution"
        )
        try:
            validate_discovery_ablation_execution(execution, request=request)
        except DiscoveryAblationError as exc:
            raise DiscoveryAblationExperimentError(str(exc)) from exc
        if execution.get("execution_sha256") != normalized_execution_hashes[key]:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} execution does not match its external SHA-256"
            )
        if execution_file_sha != normalized_execution_file_hashes[key]:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} execution file does not match its external SHA-256"
            )
        report, report_file_sha = _stable_json_load(
            Path(report_paths[key]), label=f"{arm_id} trial {trial_index} report"
        )
        report_sha = canonical_json_sha256(report)
        if report_sha != normalized_report_hashes[key]:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} report does not match its external SHA-256"
            )
        if report_file_sha != normalized_report_file_hashes[key]:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} report file does not match its external SHA-256"
            )
        if execution.get("report_sha256") != report_sha:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} execution/report SHA-256 binding mismatch"
            )
        override = discovery_ablation_runtime_override_from_request(request)
        try:
            report_contract = validate_discovery_ablation_report(report, request, override)
        except DiscoveryAblationError as exc:
            raise DiscoveryAblationExperimentError(str(exc)) from exc
        if execution.get("report_contract") != report_contract:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} frozen report contract mismatch"
            )
        raw_usage_evidence = report_contract.get("raw_usage_evidence")
        if not isinstance(raw_usage_evidence, Mapping):
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} raw usage evidence is missing"
            )
        usage_path = Path(usage_sidecar_paths[key])
        reported_usage_name = str(raw_usage_evidence.get("path") or "")
        expected_usage_path = (Path(report_paths[key]).parent / reported_usage_name).resolve()
        if usage_path.name != reported_usage_name or usage_path.resolve() != expected_usage_path:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} usage sidecar path binding mismatch"
            )
        frozen_usage_evidence = _stable_usage_load(
            usage_path,
            expected_sha256=normalized_usage_hashes[key],
        )
        if (
            dict(frozen_usage_evidence) != dict(raw_usage_evidence)
            or execution.get("usage_sidecar_sha256") != frozen_usage_evidence["sha256"]
        ):
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} usage sidecar/report/execution binding mismatch"
            )
        if report_contract.get("completeness") != "complete":
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} report is not complete"
            )
        if report_contract.get("reserved_tokens") != 0:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} has unsettled token reservations"
            )
        if (
            execution.get("release_eligible") is not False
            or override.report_metadata().get("release_eligible") is not False
        ):
            raise DiscoveryAblationExperimentError(
                "all discovery ablation artifacts must be release-ineligible"
            )
        if report.get("release_eligible") is not False:
            raise DiscoveryAblationExperimentError(
                f"{arm_id} trial {trial_index} scanner report must explicitly set "
                "release_eligible=false"
            )
        _validate_report_scoring_shape(report, label=f"{arm_id} trial {trial_index} report")
        total_tokens = int(report_contract["consumed_tokens"])
        usage = _validate_usage(report, expected_total_tokens=total_tokens)
        _validate_stage_budget(
            usage,
            expected_stage_tokens=request["fixed_contract"]["expected_stage_tokens"],
        )
        frozen[key] = {
            "execution": copy.deepcopy(execution),
            "report": copy.deepcopy(report),
            "usage": usage,
            "report_contract": copy.deepcopy(report_contract),
        }
        run_inputs.append(
            {
                "arm_id": arm_id,
                "trial_index": trial_index,
                "run_id": str(execution["run_id"]),
                "request_sha256": str(execution["request_sha256"]),
                "execution_schema_version": str(execution["schema_version"]),
                "execution_sha256": str(execution["execution_sha256"]),
                "execution_file_sha256": execution_file_sha,
                "report_sha256": report_sha,
                "report_file_sha256": report_file_sha,
                "usage_sidecar_name": usage_path.name,
                "usage_sidecar_sha256": str(frozen_usage_evidence["sha256"]),
                "executor_sha256": str(execution["executor_sha256"]),
                "release_eligible": False,
            }
        )

    if any(
        len({row[field] for row in run_inputs}) != len(expected_keys)
        for field in ("execution_sha256", "report_sha256", "usage_sidecar_sha256")
    ):
        raise DiscoveryAblationExperimentError(
            "all cold trials must have distinct execution, report, and usage artifacts"
        )

    # Phase 2: only after all 75 answer-free artifacts are frozen may truth be
    # opened by this independent scorer.
    truth, truth_file_sha = _stable_json_load(Path(truth_path), label="ground truth")
    if truth_file_sha != expected_truth:
        raise DiscoveryAblationExperimentError(
            "ground truth does not match the externally expected file SHA-256"
        )
    _validate_truth(truth)
    plan_dataset_id = str(plan["answer_free_input"]["dataset_id"])
    truth_dataset_id = truth.get("dataset_id")
    if truth_dataset_id is not None and str(truth_dataset_id) != plan_dataset_id:
        raise DiscoveryAblationExperimentError(
            "ground truth dataset_id does not match the frozen answer-free dataset"
        )

    arms: Dict[str, Any] = {}
    for arm_id in ABLATION_ARM_IDS:
        spec = _arm_spec(plan, arm_id)
        trials: list[Dict[str, Any]] = []
        for trial_index in range(1, ABLATION_COLD_TRIALS + 1):
            row = frozen[(arm_id, trial_index)]
            raw_scores = score_report_views(
                dict(row["report"]),
                dict(truth),
                line_tolerance=line_tolerance,
            )
            total_tokens = int(row["report_contract"]["consumed_tokens"])
            trials.append(
                {
                    "trial_index": trial_index,
                    "run_id": str(row["execution"]["run_id"]),
                    "execution_sha256": str(row["execution"]["execution_sha256"]),
                    "report_sha256": str(row["execution"]["report_sha256"]),
                    "usage_sidecar_sha256": str(row["execution"]["usage_sidecar_sha256"]),
                    "completeness": str(row["report_contract"]["completeness"]),
                    "total_tokens": total_tokens,
                    "usage": copy.deepcopy(row["usage"]),
                    "views": {
                        "confirmed": _score_view(raw_scores["default"], total_tokens=total_tokens),
                        "with_review": _score_view(
                            raw_scores["with_needs_review"], total_tokens=total_tokens
                        ),
                    },
                    "warm_cache_benefit": _warm_cache_unavailable(),
                    "release_eligible": False,
                }
            )
        cost_upper_bound = bool(spec["cost_upper_bound"])
        arms[arm_id] = {
            "arm_id": arm_id,
            "arm_revision": int(spec["revision"]),
            "arm_spec_sha256": str(spec["arm_spec_sha256"]),
            "baseline": bool(spec["baseline"]),
            "cost_upper_bound": cost_upper_bound,
            "role": "cost_upper_bound_only" if cost_upper_bound else "quality_and_cost_ablation",
            "trial_count": len(trials),
            "configured_cost_expectation_tokens": ABLATION_EXPECTED_MAX_TOKENS,
            "trials": trials,
            "aggregates": _aggregate_arm_trials(trials),
            "warm_cache_benefit": _warm_cache_unavailable(),
            "release_eligible": False,
        }

    result: Dict[str, Any] = {
        "schema_version": DISCOVERY_ABLATION_EXPERIMENT_SCHEMA_VERSION,
        "scorer": {
            "component": "zscope.benchmarking.discovery_ablation_experiment",
            "revision": 1,
            "source_sha256": _sha256_file(Path(__file__)),
            "line_tolerance": line_tolerance,
        },
        "inputs": {
            "plan": {
                "schema_version": str(plan["schema_version"]),
                "plan_sha256": str(plan["plan_sha256"]),
                "file_sha256": plan_file_sha,
                "dataset_id": plan_dataset_id,
                "answer_free_input_payload_sha256": str(
                    plan["answer_free_input"]["payload_sha256"]
                ),
                "config_identity_sha256": str(plan["config_identity"]["combined_sha256"]),
                "validator_config_sha256": str(plan["config_identity"]["validator_config_sha256"]),
                "validator_arm_spec_sha256": str(
                    plan["fixed_contract"]["validator_config"]["validator_arm_spec_sha256"]
                ),
                "catalog_sha256": str(plan["catalog"]["catalog_sha256"]),
            },
            "truth": {
                "benchmark": str(truth.get("benchmark") or "unknown"),
                "suite": str(truth.get("suite") or "unknown"),
                "version": str(truth.get("version") or ""),
                "ground_truth_count": len(truth["vulnerabilities"]),
                "safe_entry_count": len(truth.get("safe_entries") or []),
                "file_sha256": truth_file_sha,
                "payload_sha256": canonical_json_sha256(truth),
            },
            "runs": run_inputs,
        },
        "contract": {
            "scoring_order": "all_executions_and_reports_frozen_before_truth_open",
            "required_arms": list(ABLATION_ARM_IDS),
            "trials_per_arm": ABLATION_COLD_TRIALS,
            "scan_depth": "balanced",
            "per_run_cost_expectation_tokens": ABLATION_EXPECTED_MAX_TOKENS,
            "cache_mode": "isolated_cold",
            "cold_trials_attested": True,
            "fixed_plan_identity": True,
            "fixed_config_identity": True,
            "fixed_validator_identity": True,
            "truth_loaded_by": "independent_post_scorer_only",
            "model_execution": "forbidden",
            "release_policy": "all_inputs_and_outputs_are_release_ineligible",
            "warm_cache_benefit_policy": "N/A_without_paired_warm_runs",
        },
        "arms": arms,
        "interpretation": {
            "quality_comparable_arms": ["D0", "D1", "D2", "D3"],
            "cost_upper_bound_arms": ["D4"],
            "selection_performed": False,
            "release_use": "forbidden",
        },
        "release_eligible": False,
    }
    result["experiment_sha256"] = canonical_json_sha256(result)
    validate_discovery_ablation_experiment(result)
    return result


def _require_exact(value: Any, fields: frozenset[str], *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise DiscoveryAblationExperimentError(f"{label} has missing or unknown fields")
    return value


def _validate_distribution(value: Any, *, label: str) -> None:
    row = _require_exact(value, _DISTRIBUTION_FIELDS, label=label)
    count = row.get("count")
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise DiscoveryAblationExperimentError(f"{label}.count is invalid")
    for field in _DISTRIBUTION_FIELDS - {"count"}:
        number = row.get(field)
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            raise DiscoveryAblationExperimentError(f"{label}.{field} is invalid")
    if row["median"] != row["p50"] or row["range"] != row["maximum"] - row["minimum"]:
        raise DiscoveryAblationExperimentError(f"{label} does not conserve")


def _validate_warm_cache(value: Any, *, label: str) -> None:
    row = _require_exact(value, _WARM_CACHE_FIELDS, label=label)
    if (
        row.get("available") is not False
        or row.get("value") is not None
        or row.get("unit") != "fractional_token_reduction"
        or not str(row.get("reason") or "").startswith("N/A:")
    ):
        raise DiscoveryAblationExperimentError(
            f"{label} must explicitly mark cold-only warm-cache benefit N/A"
        )


def _validate_view(value: Any, *, truth_count: int, total_tokens: int, label: str) -> None:
    row = _require_exact(value, _VIEW_FIELDS, label=label)
    for field in ("report_issue_count", "true_positives", "false_positives_raw"):
        number = row.get(field)
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise DiscoveryAblationExperimentError(f"{label}.{field} is invalid")
    for field in ("recall", "actionable_precision", "actionable_false_discovery_rate"):
        number = row.get(field)
        if isinstance(number, bool) or not isinstance(number, (int, float)) or not 0 <= number <= 1:
            raise DiscoveryAblationExperimentError(f"{label}.{field} is invalid")
    if abs(float(row["recall"]) - round(int(row["true_positives"]) / truth_count, 4)) > 1e-12:
        raise DiscoveryAblationExperimentError(f"{label}.recall does not conserve")
    denominator = int(row["true_positives"]) + int(row["false_positives_raw"])
    expected_precision = round(int(row["true_positives"]) / denominator, 4) if denominator else 0.0
    expected_fdr = round(int(row["false_positives_raw"]) / denominator, 4) if denominator else 0.0
    if (
        row["actionable_precision"] != expected_precision
        or row["actionable_false_discovery_rate"] != expected_fdr
    ):
        raise DiscoveryAblationExperimentError(f"{label} precision/FDR does not conserve")
    ids = row.get("true_positive_truth_ids")
    if (
        not isinstance(ids, list)
        or any(not isinstance(item, str) or not item for item in ids)
        or ids != sorted(set(ids))
        or len(ids) != row["true_positives"]
    ):
        raise DiscoveryAblationExperimentError(f"{label} TP identities are invalid")
    discovery = _require_exact(row.get("discovery"), _DISCOVERY_FIELDS, label=f"{label}.discovery")
    for field in (
        "by_source",
        "exclusive_by_source",
        "source_set_outcomes",
        "intersections_by_source_set",
    ):
        if not isinstance(discovery.get(field), Mapping):
            raise DiscoveryAblationExperimentError(f"{label}.discovery.{field} is invalid")
    token_rows = row.get("tokens_per_exclusive_true_positive")
    if not isinstance(token_rows, Mapping):
        raise DiscoveryAblationExperimentError(f"{label} token ratios are invalid")
    for source, raw in discovery["exclusive_by_source"].items():
        if not isinstance(raw, Mapping):
            raise DiscoveryAblationExperimentError(f"{label} exclusive source row is invalid")
        expected = total_tokens / int(raw["true_positives"]) if int(raw["true_positives"]) else None
        if token_rows.get(source) != expected:
            raise DiscoveryAblationExperimentError(f"{label} tokens/exclusive-TP does not conserve")


def validate_discovery_ablation_experiment(result: Mapping[str, Any]) -> None:
    """Fail closed on schema drift, release use, or aggregate disagreement."""

    _require_exact(result, _TOP_LEVEL_FIELDS, label="discovery ablation experiment")
    if result.get("schema_version") != DISCOVERY_ABLATION_EXPERIMENT_SCHEMA_VERSION:
        raise DiscoveryAblationExperimentError("ablation experiment schema_version is invalid")
    if result.get("release_eligible") is not False:
        raise DiscoveryAblationExperimentError("ablation experiment can never be release eligible")
    if result.get("experiment_sha256") != canonical_json_sha256(
        {key: value for key, value in result.items() if key != "experiment_sha256"}
    ):
        raise DiscoveryAblationExperimentError("ablation experiment SHA-256 mismatch")
    scorer = _require_exact(result.get("scorer"), _SCORER_FIELDS, label="scorer")
    if (
        scorer.get("component") != "zscope.benchmarking.discovery_ablation_experiment"
        or scorer.get("revision") != 1
        or not _is_sha256(scorer.get("source_sha256"))
        or isinstance(scorer.get("line_tolerance"), bool)
        or not isinstance(scorer.get("line_tolerance"), int)
        or int(scorer["line_tolerance"]) < 0
    ):
        raise DiscoveryAblationExperimentError("ablation scorer identity is invalid")

    inputs = _require_exact(result.get("inputs"), _INPUT_FIELDS, label="inputs")
    plan = _require_exact(inputs.get("plan"), _PLAN_INPUT_FIELDS, label="plan input")
    truth = _require_exact(inputs.get("truth"), _TRUTH_INPUT_FIELDS, label="truth input")
    for field in _PLAN_INPUT_FIELDS:
        if field.endswith("sha256") and not _is_sha256(plan.get(field)):
            raise DiscoveryAblationExperimentError(f"plan input {field} is invalid")
    for field in ("file_sha256", "payload_sha256"):
        if not _is_sha256(truth.get(field)):
            raise DiscoveryAblationExperimentError(f"truth input {field} is invalid")
    truth_count = truth.get("ground_truth_count")
    if isinstance(truth_count, bool) or not isinstance(truth_count, int) or truth_count <= 0:
        raise DiscoveryAblationExperimentError("truth ground_truth_count is invalid")
    contract = _require_exact(result.get("contract"), _CONTRACT_FIELDS, label="contract")
    expected_contract = {
        "scoring_order": "all_executions_and_reports_frozen_before_truth_open",
        "required_arms": list(ABLATION_ARM_IDS),
        "trials_per_arm": ABLATION_COLD_TRIALS,
        "scan_depth": "balanced",
        "per_run_cost_expectation_tokens": ABLATION_EXPECTED_MAX_TOKENS,
        "cache_mode": "isolated_cold",
        "cold_trials_attested": True,
        "fixed_plan_identity": True,
        "fixed_config_identity": True,
        "fixed_validator_identity": True,
        "truth_loaded_by": "independent_post_scorer_only",
        "model_execution": "forbidden",
        "release_policy": "all_inputs_and_outputs_are_release_ineligible",
        "warm_cache_benefit_policy": "N/A_without_paired_warm_runs",
    }
    if dict(contract) != expected_contract:
        raise DiscoveryAblationExperimentError("ablation experiment contract is invalid")
    interpretation = _require_exact(
        result.get("interpretation"), _INTERPRETATION_FIELDS, label="interpretation"
    )
    if dict(interpretation) != {
        "quality_comparable_arms": ["D0", "D1", "D2", "D3"],
        "cost_upper_bound_arms": ["D4"],
        "selection_performed": False,
        "release_use": "forbidden",
    }:
        raise DiscoveryAblationExperimentError("ablation interpretation is invalid")

    runs = inputs.get("runs")
    if not isinstance(runs, list) or len(runs) != len(_expected_trial_keys()):
        raise DiscoveryAblationExperimentError("ablation run input matrix is incomplete")
    observed_keys: list[TrialKey] = []
    uniqueness_fields = (
        "run_id",
        "request_sha256",
        "execution_sha256",
        "execution_file_sha256",
        "report_sha256",
        "report_file_sha256",
        "usage_sidecar_name",
        "usage_sidecar_sha256",
    )
    unique_values: Dict[str, list[str]] = {field: [] for field in uniqueness_fields}
    input_by_key: Dict[TrialKey, Mapping[str, Any]] = {}
    for raw in runs:
        row = _require_exact(raw, _RUN_INPUT_FIELDS, label="run input")
        arm_id = row.get("arm_id")
        trial_index = row.get("trial_index")
        if (
            arm_id not in ABLATION_ARM_IDS
            or isinstance(trial_index, bool)
            or not isinstance(trial_index, int)
        ):
            raise DiscoveryAblationExperimentError("run input arm/trial identity is invalid")
        key = (str(arm_id), trial_index)
        observed_keys.append(key)
        input_by_key[key] = row
        if (
            row.get("execution_schema_version") != ABLATION_EXECUTION_SCHEMA_VERSION
            or row.get("release_eligible") is not False
            or not isinstance(row.get("usage_sidecar_name"), str)
            or not str(row.get("usage_sidecar_name") or "")
            or Path(str(row["usage_sidecar_name"])).name != row["usage_sidecar_name"]
        ):
            raise DiscoveryAblationExperimentError(
                "run input is not a release-ineligible execution"
            )
        for field in (
            "request_sha256",
            "execution_sha256",
            "execution_file_sha256",
            "report_sha256",
            "report_file_sha256",
            "usage_sidecar_sha256",
            "executor_sha256",
        ):
            if not _is_sha256(row.get(field)):
                raise DiscoveryAblationExperimentError(f"run input {field} is invalid")
        for field in uniqueness_fields:
            unique_values[field].append(str(row.get(field) or ""))
    if observed_keys != sorted(_expected_trial_keys()) or any(
        len(set(values)) != len(values) or any(not value for value in values)
        for values in unique_values.values()
    ):
        raise DiscoveryAblationExperimentError("ablation run inputs are not unique and ordered")

    arms = result.get("arms")
    if not isinstance(arms, Mapping) or set(arms) != set(ABLATION_ARM_IDS):
        raise DiscoveryAblationExperimentError("ablation experiment must contain D0-D4")
    for arm_id in ABLATION_ARM_IDS:
        arm = _require_exact(arms[arm_id], _ARM_FIELDS, label=f"Arm {arm_id}")
        expected_cost_upper = arm_id == "D4"
        if (
            arm.get("arm_id") != arm_id
            or arm.get("cost_upper_bound") is not expected_cost_upper
            or arm.get("role")
            != ("cost_upper_bound_only" if expected_cost_upper else "quality_and_cost_ablation")
            or arm.get("trial_count") != ABLATION_COLD_TRIALS
            or arm.get("configured_cost_expectation_tokens") != ABLATION_EXPECTED_MAX_TOKENS
            or arm.get("release_eligible") is not False
            or not _is_sha256(arm.get("arm_spec_sha256"))
        ):
            raise DiscoveryAblationExperimentError(f"Arm {arm_id} identity is invalid")
        _validate_warm_cache(arm.get("warm_cache_benefit"), label=f"Arm {arm_id} warm cache")
        trials = arm.get("trials")
        if not isinstance(trials, list) or len(trials) != ABLATION_COLD_TRIALS:
            raise DiscoveryAblationExperimentError(f"Arm {arm_id} requires five trials")
        indexes: list[int] = []
        for raw_trial in trials:
            trial = _require_exact(raw_trial, _TRIAL_FIELDS, label=f"Arm {arm_id} trial")
            trial_index = trial.get("trial_index")
            if isinstance(trial_index, bool) or not isinstance(trial_index, int):
                raise DiscoveryAblationExperimentError(f"Arm {arm_id} trial index is invalid")
            indexes.append(trial_index)
            run_input = input_by_key.get((arm_id, trial_index))
            if (
                run_input is None
                or trial.get("run_id") != run_input.get("run_id")
                or trial.get("execution_sha256") != run_input.get("execution_sha256")
                or trial.get("report_sha256") != run_input.get("report_sha256")
                or trial.get("usage_sidecar_sha256") != run_input.get("usage_sidecar_sha256")
            ):
                raise DiscoveryAblationExperimentError(f"Arm {arm_id} trial input binding mismatch")
            total_tokens = trial.get("total_tokens")
            if (
                isinstance(total_tokens, bool)
                or not isinstance(total_tokens, int)
                or total_tokens < 0
                or total_tokens > ABLATION_EXPECTED_MAX_TOKENS
                or trial.get("release_eligible") is not False
            ):
                raise DiscoveryAblationExperimentError(f"Arm {arm_id} trial cost is invalid")
            usage = _require_exact(
                trial.get("usage"), _USAGE_FIELDS, label=f"Arm {arm_id} trial usage"
            )
            if (
                usage.get("complete") is not True
                or usage.get("conservation_passed") is not True
                or usage.get("telemetry_complete") is not True
                or usage.get("provider_usage_coverage") != 1.0
                or usage.get("call_count") != usage.get("provider_reported_call_count")
                or usage.get("total_tokens") != total_tokens
                or int(usage.get("prompt_tokens") or 0) + int(usage.get("completion_tokens") or 0)
                != total_tokens
            ):
                raise DiscoveryAblationExperimentError(f"Arm {arm_id} trial usage is invalid")
            _validate_stage_budget(
                usage,
                expected_stage_tokens={
                    "semantic_completion": 1_000_000,
                    "active_discovery": 2_500_000,
                    "validator": 8_000_000,
                    "investigation_remediation_reserve": 500_000,
                },
            )
            views = trial.get("views")
            if not isinstance(views, Mapping) or set(views) != {"confirmed", "with_review"}:
                raise DiscoveryAblationExperimentError(f"Arm {arm_id} trial views are invalid")
            for view_name in ("confirmed", "with_review"):
                _validate_view(
                    views[view_name],
                    truth_count=truth_count,
                    total_tokens=total_tokens,
                    label=f"Arm {arm_id} trial {trial_index} {view_name}",
                )
            _validate_warm_cache(
                trial.get("warm_cache_benefit"),
                label=f"Arm {arm_id} trial {trial_index} warm cache",
            )
        if indexes != list(range(1, ABLATION_COLD_TRIALS + 1)):
            raise DiscoveryAblationExperimentError(f"Arm {arm_id} trials are not ordered 1-5")
        aggregates = _require_exact(
            arm.get("aggregates"), _AGGREGATE_FIELDS, label=f"Arm {arm_id} aggregates"
        )
        if dict(aggregates) != _aggregate_arm_trials(trials):
            raise DiscoveryAblationExperimentError(f"Arm {arm_id} aggregates do not conserve")
        for field, distribution in aggregates["cost"].items():
            _validate_distribution(distribution, label=f"Arm {arm_id} cost {field}")
        for view_name, raw_view in aggregates["views"].items():
            view = _require_exact(
                raw_view,
                _VIEW_AGGREGATE_FIELDS,
                label=f"Arm {arm_id} aggregate {view_name}",
            )
            for metric, distribution in view["metric_distributions"].items():
                _validate_distribution(distribution, label=f"Arm {arm_id} {view_name} {metric}")


def write_discovery_ablation_experiment(path: Path, result: Mapping[str, Any]) -> None:
    validate_discovery_ablation_experiment(result)
    Path(path).write_text(
        json.dumps(dict(result), ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def load_discovery_ablation_experiment(path: Path) -> Dict[str, Any]:
    value, _file_sha = _stable_json_load(Path(path), label="discovery ablation experiment")
    validate_discovery_ablation_experiment(value)
    return value


__all__ = [
    "DISCOVERY_ABLATION_EXPERIMENT_SCHEMA_VERSION",
    "DiscoveryAblationExperimentError",
    "load_discovery_ablation_experiment",
    "score_discovery_ablation_experiment",
    "validate_discovery_ablation_experiment",
    "write_discovery_ablation_experiment",
]
