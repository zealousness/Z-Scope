"""Benchmark v5 scorer built on the frozen matcher-v2 product matching contract."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

from .protocol import (
    MATCHER_VERSION,
    _STRUCTURED_CATEGORY_FAMILIES,
    score_report,
    score_report_views,
)
from .truth_contract import (
    TRUTH_CONTRACT_V2_SCHEMA_VERSION,
    summarize_truth_contract,
    truth_records_for_contract,
)


BENCHMARK_V5_SCHEMA_VERSION = "zscope.benchmark.v5"
FORMAL_BENCHMARK_V4_SCHEMA_VERSION = "zscope.formal-benchmark.v4"
POLICY_V2_SCHEMA_VERSION = "zscope.benchmark-policy.v2"
TAXONOMY_SCHEMA_VERSION = "zscope.defect-taxonomy.v1"
E0_ATTESTATION_SCHEMA_VERSION = "zscope.e0-attestation.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_POLICY_PATH = Path(__file__).with_name("benchmark_policy.v2.json")
_TAXONOMY_PATH = Path(__file__).with_name("defect-taxonomy.v1.json")
_COMPONENT_METRICS = {
    "security_spec_mining": {
        "atomic_clause_precision",
        "atomic_clause_recall",
        "scope_accuracy",
        "overgeneralization_rate",
        "evidence_parse_rate",
        "compiler_acceptance_rate",
    },
    "hypothesis_hunting": {
        "attack_surface_coverage",
        "valid_hypothesis_rate",
        "exclusive_confirmed_tp",
        "wrong_family_rate",
        "wrong_subject_rate",
        "wrong_sink_rate",
        "wrong_region_rate",
        "tokens_per_exclusive_tp",
    },
    "proof_engine": {
        "certificate_replay_rate",
        "tamper_rejection_rate",
        "false_acceptance_count",
        "clause_closure_rate",
        "unknown_conflict_rate",
        "confirmed_certificate_coverage",
        "post_proof_extra_calls",
        "trace_completeness",
    },
}
_COUNT_METRICS = frozenset(
    {"exclusive_confirmed_tp", "false_acceptance_count", "post_proof_extra_calls"}
)
_NULLABLE_COST_METRICS = frozenset({"tokens_per_exclusive_tp"})


class BenchmarkV5Error(ValueError):
    """Raised when a Benchmark v5 input cannot support a trustworthy score."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_value(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _load_object(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkV5Error(f"cannot load Benchmark v5 contract: {path}") from exc
    if not isinstance(value, dict):
        raise BenchmarkV5Error(f"Benchmark v5 contract must be an object: {path}")
    return value


def load_benchmark_v5_policy(path: Optional[Path] = None) -> Dict[str, Any]:
    selected = (path or _POLICY_PATH).resolve()
    value = _load_object(selected)
    expected = {
        "schema_version",
        "policy_id",
        "benchmark_schema_version",
        "formal_schema_version",
        "minimum_formal_trials",
        "quality_gates",
        "cost_contract",
        "requirements",
    }
    if set(value) != expected:
        raise BenchmarkV5Error("Benchmark policy v2 fields are invalid")
    if value.get("schema_version") != POLICY_V2_SCHEMA_VERSION:
        raise BenchmarkV5Error("Benchmark policy v2 schema is invalid")
    if value.get("benchmark_schema_version") != BENCHMARK_V5_SCHEMA_VERSION:
        raise BenchmarkV5Error("Benchmark policy does not bind Benchmark v5")
    if value.get("formal_schema_version") != FORMAL_BENCHMARK_V4_SCHEMA_VERSION:
        raise BenchmarkV5Error("Benchmark policy does not bind formal v4")
    if value.get("minimum_formal_trials") != 5:
        raise BenchmarkV5Error("Benchmark v5 requires exactly five formal trials")
    cost = value.get("cost_contract")
    if not isinstance(cost, Mapping) or cost.get("runtime_token_limit") is not False:
        raise BenchmarkV5Error("Benchmark v5 cost contract must remain observational")
    return {**value, "source_sha256": hashlib.sha256(selected.read_bytes()).hexdigest()}


def load_defect_taxonomy(path: Optional[Path] = None) -> Dict[str, Any]:
    selected = (path or _TAXONOMY_PATH).resolve()
    value = _load_object(selected)
    if set(value) != {
        "schema_version",
        "matcher_version",
        "normalization",
        "exact_category_policy",
        "families",
    }:
        raise BenchmarkV5Error("defect taxonomy v1 fields are invalid")
    if value.get("schema_version") != TAXONOMY_SCHEMA_VERSION:
        raise BenchmarkV5Error("defect taxonomy schema is invalid")
    if value.get("matcher_version") != MATCHER_VERSION:
        raise BenchmarkV5Error("defect taxonomy does not bind matcher v2")
    raw_families = value.get("families")
    if not isinstance(raw_families, Mapping):
        raise BenchmarkV5Error("defect taxonomy families are invalid")
    taxonomy_families = {
        str(name): frozenset(str(item) for item in members)
        for name, members in raw_families.items()
        if isinstance(name, str) and isinstance(members, list)
    }
    if taxonomy_families != _STRUCTURED_CATEGORY_FAMILIES:
        raise BenchmarkV5Error("defect taxonomy would change matcher-v2 family semantics")
    return {**value, "source_sha256": hashlib.sha256(selected.read_bytes()).hexdigest()}


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _component_section(report: Mapping[str, Any], name: str) -> Dict[str, Any]:
    metadata = _mapping(report.get("metadata"))
    components = _mapping(metadata.get("benchmark_v5_components"))
    value = components.get(name)
    if not isinstance(value, Mapping):
        return {
            "status": "not_available",
            "reason": f"report does not expose benchmark_v5_components.{name}",
        }
    if value.get("status") != "available":
        return {
            "status": "not_available",
            "reason": str(value.get("reason") or f"{name} metrics unavailable"),
        }
    required = _COMPONENT_METRICS[name]
    missing = sorted(required - set(value))
    if missing:
        return {
            "status": "not_available",
            "reason": f"{name} metrics are incomplete: {', '.join(missing)}",
        }
    for metric in required:
        raw = value.get(metric)
        if metric in _NULLABLE_COST_METRICS and raw is None:
            continue
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            return {"status": "not_available", "reason": f"{name}.{metric} is not numeric"}
        number = float(raw)
        if metric in _COUNT_METRICS or metric in _NULLABLE_COST_METRICS:
            if number < 0 or (metric in _COUNT_METRICS and not number.is_integer()):
                return {
                    "status": "not_available",
                    "reason": f"{name}.{metric} is outside its count domain",
                }
        elif not 0.0 <= number <= 1.0:
            return {"status": "not_available", "reason": f"{name}.{metric} is not a rate"}
    return {"status": "available", **dict(value)}


def _cost_metrics(report: Mapping[str, Any], confirmed_tp: int) -> Dict[str, Any]:
    metadata = _mapping(report.get("metadata"))
    usage = _mapping(metadata.get("llm_usage"))
    totals = _mapping(usage.get("totals"))
    total_tokens = int(
        totals.get("total_tokens")
        or usage.get("total_tokens")
        or metadata.get("total_cumulative_total_tokens")
        or 0
    )
    loc = int(
        metadata.get("source_loc") or _mapping(metadata.get("benchmark_input")).get("loc") or 0
    )
    wall = float(metadata.get("wall_time_seconds") or metadata.get("elapsed_seconds") or 0.0)
    return {
        "runtime_token_limit_applied": False,
        "total_tokens": total_tokens,
        "tokens_per_kloc": (total_tokens / (loc / 1000.0) if loc > 0 else None),
        "tokens_per_confirmed_tp": (total_tokens / confirmed_tp if confirmed_tp else None),
        "source_loc": loc or None,
        "wall_time_seconds": wall,
        "usage_by_agent": dict(_mapping(usage.get("by_agent"))),
        "usage_by_stage": dict(_mapping(usage.get("by_stage"))),
        "provider_usage_coverage": usage.get("provider_usage_coverage"),
        "token_conservation": usage.get("token_conservation"),
    }


def _safe_pair_metrics(
    confirmable_records: Sequence[Mapping[str, Any]],
    pair_results: Optional[Mapping[str, Mapping[str, Any]]],
    *,
    formal: bool,
) -> Dict[str, Any]:
    if pair_results is None:
        return {"status": "not_available", "reason": "paired scanner reports were not supplied"}
    records_by_id = {str(record.get("id") or ""): record for record in confirmable_records}
    expected = set(records_by_id)
    if set(pair_results) != expected:
        raise BenchmarkV5Error("safe-pair results must cover every confirmable truth exactly")
    consistent = 0
    vulnerable_hits = 0
    fixed_alerts = 0
    for truth_id in sorted(expected):
        row = pair_results[truth_id]
        if formal:
            expected_row = {
                "schema_version",
                "pair_uid",
                "pair_manifest_sha256",
                "answer_material_present",
                "vulnerable",
                "fixed_or_near_miss",
            }
            if (
                set(row) != expected_row
                or row.get("schema_version") != "zscope.safe-pair-result.v1"
            ):
                raise BenchmarkV5Error(f"formal safe-pair result fields are invalid: {truth_id}")
            if row.get("answer_material_present") is not False:
                raise BenchmarkV5Error(
                    f"formal safe-pair result is not answer-isolated: {truth_id}"
                )
            contract = _mapping(records_by_id[truth_id].get("verification_contract"))
            pair = _mapping(contract.get("safe_pair"))
            if row.get("pair_uid") != pair.get("pair_uid") or row.get(
                "pair_manifest_sha256"
            ) != pair.get("manifest_sha256"):
                raise BenchmarkV5Error(f"formal safe-pair identity is invalid: {truth_id}")
            sides: Dict[str, Mapping[str, Any]] = {}
            for side, expected_sha in (
                ("vulnerable", pair.get("vulnerable_sha256")),
                ("fixed_or_near_miss", pair.get("fixed_or_near_miss_sha256")),
            ):
                side_value = _mapping(row.get(side))
                if set(side_value) != {"alerted", "source_sha256", "report_sha256"}:
                    raise BenchmarkV5Error(f"formal safe-pair side fields are invalid: {truth_id}")
                if not isinstance(side_value.get("alerted"), bool):
                    raise BenchmarkV5Error(f"formal safe-pair alert is invalid: {truth_id}")
                if side_value.get("source_sha256") != expected_sha or not _SHA256_RE.fullmatch(
                    str(side_value.get("report_sha256") or "")
                ):
                    raise BenchmarkV5Error(
                        f"formal safe-pair source/report binding failed: {truth_id}"
                    )
                sides[side] = side_value
            vulnerable = bool(sides["vulnerable"]["alerted"])
            fixed = bool(sides["fixed_or_near_miss"]["alerted"])
        else:
            if set(row) != {"vulnerable_alerted", "fixed_alerted"} or any(
                not isinstance(row.get(field), bool)
                for field in ("vulnerable_alerted", "fixed_alerted")
            ):
                raise BenchmarkV5Error(f"safe-pair result is invalid: {truth_id}")
            vulnerable = bool(row["vulnerable_alerted"])
            fixed = bool(row["fixed_alerted"])
        vulnerable_hits += int(vulnerable)
        fixed_alerts += int(fixed)
        consistent += int(vulnerable and not fixed)
    return {
        "status": "available",
        "pair_count": len(expected),
        "vulnerable_detected_count": vulnerable_hits,
        "fixed_alert_count": fixed_alerts,
        "consistent_pair_count": consistent,
        "consistency_rate": consistent / len(expected) if expected else 1.0,
        "safe_entry_alert_rate": fixed_alerts / len(expected) if expected else 0.0,
        "pair_results_sha256": _sha256_value(pair_results),
        "formal_bindings_verified": formal,
    }


def _macro_metrics(report: Dict[str, Any], truth: Dict[str, Any], view: str) -> Dict[str, Any]:
    records = truth_records_for_contract(truth, kinds=("concrete_trigger", "public_api_contract"))
    dimensions: Dict[str, Dict[str, list[Dict[str, Any]]]] = {
        "project": {},
        "cwe": {},
        "contract": {},
        "defect_taxonomy": {},
    }
    for record in records:
        contract = _mapping(record.get("verification_contract"))
        dimensions["project"].setdefault(
            str(record.get("project") or truth.get("benchmark") or "unknown"), []
        ).append(record)
        dimensions["contract"].setdefault(str(contract.get("kind") or "unknown"), []).append(record)
        dimensions["defect_taxonomy"].setdefault(
            str(contract.get("defect_taxonomy_id") or "unknown"), []
        ).append(record)
        cwes = record.get("cwe_ids")
        if not isinstance(cwes, list):
            cwes = [value for value in re.split(r"[/, ]+", str(record.get("cwe") or "")) if value]
        for cwe in sorted(set(str(value) for value in cwes if str(value))):
            dimensions["cwe"].setdefault(cwe, []).append(record)
    output: Dict[str, Any] = {}
    for dimension, groups in dimensions.items():
        rows: Dict[str, Any] = {}
        recalls: list[float] = []
        precisions: list[float] = []
        for key, values in sorted(groups.items()):
            result = score_report(
                report,
                {
                    "benchmark": truth.get("benchmark"),
                    "suite": truth.get("suite"),
                    "vulnerabilities": values,
                    "safe_entries": [],
                },
                view=view,
            )
            recall = float(result["recall"])
            precision = float(result["actionable_precision"])
            recalls.append(recall)
            precisions.append(precision)
            rows[key] = {
                "truth_count": int(result["ground_truth_count"]),
                "true_positives": int(result["true_positives"]),
                "recall": recall,
                "actionable_precision": precision,
            }
        output[dimension] = {
            "groups": rows,
            "macro_recall": statistics.fmean(recalls) if recalls else None,
            "macro_actionable_precision": statistics.fmean(precisions) if precisions else None,
        }
    return output


def score_benchmark_v5(
    report: Dict[str, Any],
    truth: Dict[str, Any],
    *,
    pair_results: Optional[Mapping[str, Mapping[str, Any]]] = None,
    formal: bool = False,
) -> Dict[str, Any]:
    policy = load_benchmark_v5_policy()
    taxonomy = load_defect_taxonomy()
    contract = summarize_truth_contract(truth)
    if contract.get("schema_version") != TRUTH_CONTRACT_V2_SCHEMA_VERSION:
        raise BenchmarkV5Error("Benchmark v5 requires truth contract v2")
    if contract.get("formal_eligible") is not True:
        raise BenchmarkV5Error("Truth v16 is not contract-complete")
    views = score_report_views(report, truth)
    for result in views.values():
        if _mapping(result.get("scoring_contract")).get("matcher_version") != MATCHER_VERSION:
            raise BenchmarkV5Error("Benchmark v5 requires matcher v2")
    confirmable = truth_records_for_contract(
        truth, kinds=("concrete_trigger", "public_api_contract")
    )
    product_views: Dict[str, Any] = {}
    for name in ("default", "with_needs_review"):
        raw = views[name]
        product_views[name] = {
            "ground_truth_count": raw["ground_truth_count"],
            "true_positives": raw["true_positives"],
            "false_negatives": raw["false_negatives"],
            "false_positives_raw": raw["false_positives_raw"],
            "false_positives_effective": raw["false_positives_effective"],
            "actionable_precision": raw["actionable_precision"],
            "root_cause_precision": raw["root_cause_precision"],
            "recall": raw["recall"],
            "actionable_f1": raw["actionable_f1"],
            "actionable_false_discovery_rate": raw["actionable_false_discovery_rate"],
            "safe_entry_alert_rate": raw.get("safe_entry_alert_rate"),
            "matched": raw["matched"],
            "missed": raw["missed"],
            "macro": _macro_metrics(report, truth, name),
            "matcher_audit": {
                "same_product_root_count": raw["same_product_root_count"],
                "truth_covered_additional_count": raw["truth_covered_additional_count"],
                "cross_anchor_overlap_count": raw["cross_anchor_overlap_count"],
                "weak_legacy_overlap_count": raw["weak_legacy_overlap_count"],
            },
        }
    components = {
        "security_spec_mining": _component_section(report, "security_spec_mining"),
        "hypothesis_hunting": _component_section(report, "hypothesis_hunting"),
        "proof_engine": _component_section(report, "proof_engine"),
    }
    pairs = _safe_pair_metrics(confirmable, pair_results, formal=formal)
    if formal:
        missing = [name for name, section in components.items() if section["status"] != "available"]
        if missing:
            raise BenchmarkV5Error(
                "formal Benchmark v5 requires component metrics: " + ", ".join(missing)
            )
        if pairs.get("status") != "available":
            raise BenchmarkV5Error("formal Benchmark v5 requires safe-pair results")
        if report.get("answer_material_present") is not False:
            raise BenchmarkV5Error("formal Benchmark v5 requires answer-isolated scanner output")
        cost = _cost_metrics(report, int(product_views["default"]["true_positives"]))
        if cost.get("provider_usage_coverage") != 1.0 or cost.get("token_conservation") is not True:
            raise BenchmarkV5Error("formal Benchmark v5 requires complete provider/token telemetry")
    else:
        cost = _cost_metrics(report, int(product_views["default"]["true_positives"]))
    result = {
        "schema_version": BENCHMARK_V5_SCHEMA_VERSION,
        "benchmark": truth.get("benchmark", "unknown"),
        "suite": truth.get("suite", "unknown"),
        "truth_contract": contract,
        "scoring_contract": {
            "matcher_version": MATCHER_VERSION,
            "taxonomy_schema_version": TAXONOMY_SCHEMA_VERSION,
            "taxonomy_sha256": taxonomy["source_sha256"],
            "policy_schema_version": POLICY_V2_SCHEMA_VERSION,
            "policy_sha256": policy["source_sha256"],
            "v4_comparison_policy": "incomparable",
        },
        "artifact_bindings": {
            "truth_v16_content": _sha256_value(truth),
            "truth_contract_manifest": str(contract["manifest_sha256"]),
            "review_bundle_content": str(contract["review_bundle_sha256"]),
            "defect_taxonomy": taxonomy["source_sha256"],
            "benchmark_policy": policy["source_sha256"],
        },
        "product": product_views,
        "design_risk": {
            name: views[name].get("design_risk_view", {"status": "not_available"})
            for name in ("default", "with_needs_review")
        },
        "security_spec_mining": components["security_spec_mining"],
        "hypothesis_hunting": components["hypothesis_hunting"],
        "proof_engine": components["proof_engine"],
        "safe_pairs": pairs,
        "cost": cost,
        "formal_ready": formal,
    }
    result["score_sha256"] = _sha256_value(result)
    return result


def _jaccard(sets: Sequence[set[str]]) -> float:
    if not sets:
        return 0.0
    union = set.union(*sets)
    intersection = set.intersection(*sets)
    return len(intersection) / len(union) if union else 1.0


def _required_number(value: Any, *, field: str, integer: bool = False) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BenchmarkV5Error(f"formal Benchmark v5 metric is missing or invalid: {field}")
    if integer:
        if not float(value).is_integer():
            raise BenchmarkV5Error(f"formal Benchmark v5 metric must be an integer: {field}")
        return int(value)
    return float(value)


def aggregate_benchmark_v5(
    trials: Sequence[Mapping[str, Any]],
    *,
    e0_attestation: Mapping[str, Any],
    trusted_workflow_run_id: str,
    trusted_head_sha: str,
    baseline_actionable_precision: float,
) -> Dict[str, Any]:
    if len(trials) != 5:
        raise BenchmarkV5Error("formal Benchmark v5 requires exactly five trials")
    if any(trial.get("schema_version") != BENCHMARK_V5_SCHEMA_VERSION for trial in trials):
        raise BenchmarkV5Error("formal Benchmark v5 cannot consume historical scores")
    for trial in trials:
        unsigned_trial = dict(trial)
        supplied_score_sha = str(unsigned_trial.pop("score_sha256", ""))
        if supplied_score_sha != _sha256_value(unsigned_trial):
            raise BenchmarkV5Error("formal Benchmark v5 trial score hash is invalid")
    if any(trial.get("formal_ready") is not True for trial in trials):
        raise BenchmarkV5Error("formal Benchmark v5 trial is not component-complete")
    contracts = [_mapping(trial.get("truth_contract")) for trial in trials]
    manifests = {str(item.get("manifest_sha256") or "") for item in contracts}
    if len(manifests) != 1 or "" in manifests:
        raise BenchmarkV5Error("formal trials do not bind one Truth v16 manifest")
    bindings = [_mapping(trial.get("artifact_bindings")) for trial in trials]
    if not bindings or any(binding != bindings[0] for binding in bindings[1:]):
        raise BenchmarkV5Error("formal trials do not bind one E0 artifact set")
    _validate_e0_attestation_binding(
        e0_attestation,
        trusted_workflow_run_id=trusted_workflow_run_id,
        trusted_head_sha=trusted_head_sha,
        expected_artifacts=bindings[0],
    )
    defaults = [_mapping(_mapping(trial.get("product")).get("default")) for trial in trials]
    recalls = [float(item.get("recall") or 0.0) for item in defaults]
    precisions = [float(item.get("actionable_precision") or 0.0) for item in defaults]
    tokens = [int(_mapping(trial.get("cost")).get("total_tokens") or 0) for trial in trials]
    tp_sets = [set(str(value) for value in item.get("matched", [])) for item in defaults]
    if not 0.0 <= baseline_actionable_precision <= 1.0:
        raise BenchmarkV5Error("formal Benchmark v5 baseline precision is invalid")
    median_recall = statistics.median(recalls)
    median_precision = statistics.median(precisions)
    recall_range_pp = (max(recalls) - min(recalls)) * 100.0
    jaccard = _jaccard(tp_sets)
    pair_alert_rates = [
        float(
            _required_number(
                _mapping(trial.get("safe_pairs")).get("safe_entry_alert_rate"),
                field="safe_pairs.safe_entry_alert_rate",
            )
        )
        for trial in trials
    ]
    proof_false_acceptance = [
        int(
            _required_number(
                _mapping(trial.get("proof_engine")).get("false_acceptance_count"),
                field="proof_engine.false_acceptance_count",
                integer=True,
            )
        )
        for trial in trials
    ]
    trace_completeness = [
        float(
            _required_number(
                _mapping(trial.get("proof_engine")).get("trace_completeness"),
                field="proof_engine.trace_completeness",
            )
        )
        for trial in trials
    ]
    provider_coverage = [
        float(
            _required_number(
                _mapping(trial.get("cost")).get("provider_usage_coverage"),
                field="cost.provider_usage_coverage",
            )
        )
        for trial in trials
    ]
    conservation = [
        _mapping(trial.get("cost")).get("token_conservation") is True for trial in trials
    ]
    policy = load_benchmark_v5_policy()
    observed = {
        "confirmed_recall": median_recall,
        "actionable_precision_delta_pp": (median_precision - baseline_actionable_precision) * 100.0,
        "true_positive_jaccard": jaccard,
        "recall_range_pp": recall_range_pp,
        "safe_entry_alert_rate": statistics.median(pair_alert_rates),
        "proof_false_acceptance_count": max(proof_false_acceptance),
        "provider_usage_coverage": min(provider_coverage),
        "trace_completeness": min(trace_completeness),
        "token_conservation_rate": sum(conservation) / len(conservation),
    }
    gate_rows: Dict[str, Any] = {}
    for name, specification in _mapping(policy.get("quality_gates")).items():
        operator = str(_mapping(specification).get("operator") or "")
        threshold = float(
            _required_number(
                _mapping(specification).get("threshold"), field=f"policy.{name}.threshold"
            )
        )
        value = float(observed[name])
        passed = (
            value >= threshold
            if operator == ">="
            else value <= threshold if operator == "<=" else False
        )
        gate_rows[name] = {
            "value": value,
            "operator": operator,
            "threshold": threshold,
            "passed": passed,
        }
    result = {
        "schema_version": FORMAL_BENCHMARK_V4_SCHEMA_VERSION,
        "trial_count": 5,
        "truth_manifest_sha256": next(iter(manifests)),
        "e0_attestation_sha256": str(e0_attestation.get("content_sha256") or ""),
        "quality": {
            "median_recall": median_recall,
            "min_recall": min(recalls),
            "max_recall": max(recalls),
            "recall_range_pp": recall_range_pp,
            "median_actionable_precision": median_precision,
            "baseline_actionable_precision": baseline_actionable_precision,
            "actionable_precision_delta_pp": observed["actionable_precision_delta_pp"],
            "true_positive_jaccard": jaccard,
        },
        "cost": {
            "runtime_token_limit_applied": False,
            "median_total_tokens": statistics.median(tokens),
            "min_total_tokens": min(tokens),
            "max_total_tokens": max(tokens),
        },
        "policy_evaluation": {
            "policy_schema_version": POLICY_V2_SCHEMA_VERSION,
            "policy_sha256": policy["source_sha256"],
            "status": "passed" if all(row["passed"] for row in gate_rows.values()) else "failed",
            "gates": gate_rows,
        },
    }
    result["aggregate_sha256"] = _sha256_value(result)
    return result


def _validate_e0_attestation_binding(
    value: Mapping[str, Any],
    *,
    trusted_workflow_run_id: str,
    trusted_head_sha: str,
    expected_artifacts: Mapping[str, Any],
) -> None:
    expected_top = {
        "schema_version",
        "issued_at",
        "workflow",
        "component_commits",
        "artifacts",
        "review_summary",
        "invariants",
        "content_sha256",
    }
    if set(value) != expected_top or value.get("schema_version") != E0_ATTESTATION_SCHEMA_VERSION:
        raise BenchmarkV5Error("formal Benchmark v5 requires an E0 attestation")
    workflow = _mapping(value.get("workflow"))
    if set(workflow) != {"path", "run_id", "head_sha", "environment"}:
        raise BenchmarkV5Error("E0 attestation workflow identity is incomplete")
    if workflow.get("path") != ".github/workflows/range-v16-benchmark-v5-attestation.yml":
        raise BenchmarkV5Error("E0 attestation workflow path is untrusted")
    if str(workflow.get("run_id") or "") != str(trusted_workflow_run_id):
        raise BenchmarkV5Error("E0 attestation run identity is untrusted")
    if workflow.get("head_sha") != trusted_head_sha:
        raise BenchmarkV5Error("E0 attestation head identity is untrusted")
    if workflow.get("environment") != "sealed-benchmark":
        raise BenchmarkV5Error("E0 attestation environment is untrusted")
    commits = _mapping(value.get("component_commits"))
    if set(commits) != {"governance", "scorer", "truth"} or not all(
        _GIT_SHA_RE.fullmatch(str(item or "")) for item in commits.values()
    ):
        raise BenchmarkV5Error("E0 attestation component commits are invalid")
    artifacts = _mapping(value.get("artifacts"))
    required_artifacts = {
        "truth_v16",
        "truth_v16_content",
        "truth_contract_manifest",
        "truth_manifest",
        "review_bundle",
        "review_bundle_content",
        "review_provenance",
        "safe_pair_manifest",
        "defect_taxonomy",
        "benchmark_policy",
        "scorer_bundle",
    }
    if set(artifacts) != required_artifacts or not all(
        _SHA256_RE.fullmatch(str(item or "")) for item in artifacts.values()
    ):
        raise BenchmarkV5Error("E0 attestation artifact bindings are invalid")
    for name in (
        "truth_v16_content",
        "truth_contract_manifest",
        "review_bundle_content",
        "defect_taxonomy",
        "benchmark_policy",
    ):
        if artifacts.get(name) != expected_artifacts.get(name):
            raise BenchmarkV5Error(f"E0 attestation does not bind trial artifact: {name}")
    review = _mapping(value.get("review_summary"))
    if (
        set(review)
        != {"record_count", "dual_review_count", "opus_review_count", "disputed_opus_count"}
        or review.get("record_count") != 136
        or review.get("dual_review_count") != 136
        or int(review.get("opus_review_count") or 0) < 9
        or review.get("disputed_opus_count") != 9
    ):
        raise BenchmarkV5Error("E0 attestation review coverage is incomplete")
    unsigned = dict(value)
    supplied = str(unsigned.pop("content_sha256", ""))
    if supplied != _sha256_value(unsigned):
        raise BenchmarkV5Error("E0 attestation content hash is invalid")
    invariants = _mapping(value.get("invariants"))
    required_invariants = {
        "matcher_v2_unchanged",
        "v15_read_only",
        "safe_units_cover_confirmable_truth",
        "scanner_answer_isolated",
        "raw_reviews_artifact_only",
        "product_runtime_unchanged",
    }
    if set(invariants) != required_invariants or any(
        invariants.get(name) is not True for name in required_invariants
    ):
        raise BenchmarkV5Error("E0 attestation hard invariant is not satisfied")


__all__ = [
    "BENCHMARK_V5_SCHEMA_VERSION",
    "BenchmarkV5Error",
    "FORMAL_BENCHMARK_V4_SCHEMA_VERSION",
    "POLICY_V2_SCHEMA_VERSION",
    "TAXONOMY_SCHEMA_VERSION",
    "aggregate_benchmark_v5",
    "load_benchmark_v5_policy",
    "load_defect_taxonomy",
    "score_benchmark_v5",
]
