"""Benchmark v5 scorer built on the frozen matcher-v2 product matching contract."""

from __future__ import annotations

import hashlib
import json
import math
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
_POLICY_PATH = Path(__file__).with_name("benchmark_policy.v2.json")
_TAXONOMY_PATH = Path(__file__).with_name("defect-taxonomy.v1.json")


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
    loc = int(metadata.get("source_loc") or _mapping(metadata.get("benchmark_input")).get("loc") or 0)
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
    confirmable_ids: Sequence[str], pair_results: Optional[Mapping[str, Mapping[str, Any]]]
) -> Dict[str, Any]:
    if pair_results is None:
        return {"status": "not_available", "reason": "paired scanner reports were not supplied"}
    expected = set(confirmable_ids)
    if set(pair_results) != expected:
        raise BenchmarkV5Error("safe-pair results must cover every confirmable truth exactly")
    consistent = 0
    vulnerable_hits = 0
    fixed_alerts = 0
    for truth_id in confirmable_ids:
        row = pair_results[truth_id]
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
    }


def _macro_metrics(report: Dict[str, Any], truth: Dict[str, Any], view: str) -> Dict[str, Any]:
    records = truth_records_for_contract(
        truth, kinds=("concrete_trigger", "public_api_contract")
    )
    groups: Dict[str, list[Dict[str, Any]]] = {}
    for record in records:
        contract = _mapping(record.get("verification_contract"))
        key = str(contract.get("defect_taxonomy_id") or record.get("category") or "unknown")
        groups.setdefault(key, []).append(record)
    per_group: Dict[str, Any] = {}
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
        per_group[key] = {
            "truth_count": int(result["ground_truth_count"]),
            "true_positives": int(result["true_positives"]),
            "recall": recall,
            "actionable_precision": precision,
        }
    return {
        "per_contract_family": per_group,
        "contract_macro_recall": statistics.fmean(recalls) if recalls else None,
        "contract_macro_actionable_precision": (
            statistics.fmean(precisions) if precisions else None
        ),
    }


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
    confirmable_ids = [str(item.get("id") or "") for item in confirmable]
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
            "actionable_false_discovery_rate": raw[
                "actionable_false_discovery_rate"
            ],
            "safe_entry_alert_rate": raw.get("safe_entry_alert_rate"),
            "matched": raw["matched"],
            "missed": raw["missed"],
            "macro": _macro_metrics(report, truth, name),
            "matcher_audit": {
                "same_product_root_count": raw["same_product_root_count"],
                "truth_covered_additional_count": raw[
                    "truth_covered_additional_count"
                ],
                "cross_anchor_overlap_count": raw["cross_anchor_overlap_count"],
                "weak_legacy_overlap_count": raw["weak_legacy_overlap_count"],
            },
        }
    components = {
        "security_spec_mining": _component_section(report, "security_spec_mining"),
        "hypothesis_hunting": _component_section(report, "hypothesis_hunting"),
        "proof_engine": _component_section(report, "proof_engine"),
    }
    pairs = _safe_pair_metrics(confirmable_ids, pair_results)
    if formal:
        missing = [name for name, section in components.items() if section["status"] != "available"]
        if missing:
            raise BenchmarkV5Error(
                "formal Benchmark v5 requires component metrics: " + ", ".join(missing)
            )
        if pairs.get("status") != "available":
            raise BenchmarkV5Error("formal Benchmark v5 requires safe-pair results")
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
        "product": product_views,
        "security_spec_mining": components["security_spec_mining"],
        "hypothesis_hunting": components["hypothesis_hunting"],
        "proof_engine": components["proof_engine"],
        "safe_pairs": pairs,
        "cost": _cost_metrics(report, int(product_views["default"]["true_positives"])),
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


def aggregate_benchmark_v5(
    trials: Sequence[Mapping[str, Any]],
    *,
    e0_attestation: Mapping[str, Any],
    trusted_workflow_run_id: str,
    trusted_head_sha: str,
) -> Dict[str, Any]:
    if len(trials) != 5:
        raise BenchmarkV5Error("formal Benchmark v5 requires exactly five trials")
    if any(trial.get("schema_version") != BENCHMARK_V5_SCHEMA_VERSION for trial in trials):
        raise BenchmarkV5Error("formal Benchmark v5 cannot consume historical scores")
    if any(trial.get("formal_ready") is not True for trial in trials):
        raise BenchmarkV5Error("formal Benchmark v5 trial is not component-complete")
    contracts = [_mapping(trial.get("truth_contract")) for trial in trials]
    manifests = {str(item.get("manifest_sha256") or "") for item in contracts}
    if len(manifests) != 1 or "" in manifests:
        raise BenchmarkV5Error("formal trials do not bind one Truth v16 manifest")
    _validate_e0_attestation_binding(
        e0_attestation,
        trusted_workflow_run_id=trusted_workflow_run_id,
        trusted_head_sha=trusted_head_sha,
    )
    defaults = [_mapping(_mapping(trial.get("product")).get("default")) for trial in trials]
    recalls = [float(item.get("recall") or 0.0) for item in defaults]
    precisions = [float(item.get("actionable_precision") or 0.0) for item in defaults]
    tokens = [int(_mapping(trial.get("cost")).get("total_tokens") or 0) for trial in trials]
    tp_sets = [set(str(value) for value in item.get("matched", [])) for item in defaults]
    result = {
        "schema_version": FORMAL_BENCHMARK_V4_SCHEMA_VERSION,
        "trial_count": 5,
        "truth_manifest_sha256": next(iter(manifests)),
        "e0_attestation_sha256": str(e0_attestation.get("content_sha256") or ""),
        "quality": {
            "median_recall": statistics.median(recalls),
            "min_recall": min(recalls),
            "max_recall": max(recalls),
            "recall_range_pp": (max(recalls) - min(recalls)) * 100.0,
            "median_actionable_precision": statistics.median(precisions),
            "true_positive_jaccard": _jaccard(tp_sets),
        },
        "cost": {
            "runtime_token_limit_applied": False,
            "median_total_tokens": statistics.median(tokens),
            "min_total_tokens": min(tokens),
            "max_total_tokens": max(tokens),
        },
    }
    result["aggregate_sha256"] = _sha256_value(result)
    return result


def _validate_e0_attestation_binding(
    value: Mapping[str, Any], *, trusted_workflow_run_id: str, trusted_head_sha: str
) -> None:
    if value.get("schema_version") != E0_ATTESTATION_SCHEMA_VERSION:
        raise BenchmarkV5Error("formal Benchmark v5 requires an E0 attestation")
    workflow = _mapping(value.get("workflow"))
    if workflow.get("path") != ".github/workflows/range-v16-benchmark-v5-attestation.yml":
        raise BenchmarkV5Error("E0 attestation workflow path is untrusted")
    if str(workflow.get("run_id") or "") != str(trusted_workflow_run_id):
        raise BenchmarkV5Error("E0 attestation run identity is untrusted")
    if workflow.get("head_sha") != trusted_head_sha:
        raise BenchmarkV5Error("E0 attestation head identity is untrusted")
    unsigned = dict(value)
    supplied = str(unsigned.pop("content_sha256", ""))
    if supplied != _sha256_value(unsigned):
        raise BenchmarkV5Error("E0 attestation content hash is invalid")
    invariants = _mapping(value.get("invariants"))
    if not invariants or any(item is not True for item in invariants.values()):
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
