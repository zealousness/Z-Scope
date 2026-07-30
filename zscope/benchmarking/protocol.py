"""Machine-readable benchmark protocol and metrics for Z-SCOPE."""

from __future__ import annotations

import json
import hashlib
import heapq
import math
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from zscope._version import __version__
from zscope.common.issue_identity import issues_may_share_root_cause, stable_issue_fingerprint


SCHEMA_VERSION = "zscope.benchmark.v3"
INTEGRITY_SCHEMA_VERSION = "zscope.benchmark.integrity.v1"
SOURCE_FILE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".i",
}

MIN_RELEASE_TRIALS = 5
DEFAULT_BOOTSTRAP_SAMPLES = 2000
RELEASE_THRESHOLDS = {
    "actionable_precision": 0.70,
    "distinct_root_recall": 0.80,
    "high_critical_recall": 0.90,
    "safe_entry_alert_rate": 0.10,
    "per_cwe_recall": 0.65,
    "per_cwe_min_samples": 20,
    "actionable_f1_stdev": 0.02,
    "true_positive_jaccard": 0.90,
    "alert_jaccard": 0.80,
    "median_wall_time_seconds": 3600.0,
    "median_billable_tokens": 30_000_000.0,
    "median_report_tail_seconds": 120.0,
    "tokens_per_true_positive_reduction": 0.30,
}

FP_AUDIT_DUPLICATE_OF_GT = "duplicate_of_gt"
FP_AUDIT_TRUE_EXTRA_ADD_GT = "true_extra_add_gt"
FP_AUDIT_NEEDS_REVIEW_ONLY = "needs_review_only"
FP_AUDIT_FALSE_POSITIVE_SUPPRESS = "false_positive_suppress"

CONDITION_PURE_LLM_ENTRY = "pure_llm_entry_source"
CONDITION_PURE_LLM_REPO = "pure_llm_repo_context"
CONDITION_FULL_ZSCOPE = "full_zscope_pipeline"
CONDITION_CANDIDATES = "candidate_layer"

BENCHMARK_CONDITIONS = (
    CONDITION_PURE_LLM_ENTRY,
    CONDITION_PURE_LLM_REPO,
    CONDITION_FULL_ZSCOPE,
    CONDITION_CANDIDATES,
)

RUN_KINDS = ("smoke", "sample", "formal")

FalsePositiveClassifier = Callable[[Dict[str, Any]], Dict[str, Any]]


@dataclass(frozen=True)
class BenchmarkTrialKey:
    suite: str
    condition: str
    trial_index: int
    run_kind: str


def json_dump(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest for a file, or an empty string when unavailable."""

    path = Path(path)
    if not path.is_file():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_payload(payload: Any) -> str:
    """Return a deterministic SHA-256 digest for a JSON-compatible payload."""

    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def source_tree_manifest(project_root: Path) -> Dict[str, Any]:
    """Hash source inputs without including generated reports, caches, or build output."""

    project_root = Path(project_root)
    digest = hashlib.sha256()
    file_count = 0
    if not project_root.is_dir():
        return {"sha256": "", "file_count": 0}

    ignored_parts = {
        ".git",
        "build",
        "benchmark",
        "benchmark_runs",
        "runs",
    }
    candidates: List[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(project_root)
        if any(part in ignored_parts or part.startswith(".zscope") for part in relative.parts):
            continue
        if path.suffix.lower() not in SOURCE_FILE_SUFFIXES and path.name != "compile_commands.json":
            continue
        candidates.append(path)

    for path in sorted(candidates, key=lambda item: item.relative_to(project_root).as_posix()):
        relative = path.relative_to(project_root).as_posix()
        file_digest = sha256_file(path)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        file_count += 1
    return {
        "sha256": digest.hexdigest() if file_count else "",
        "file_count": file_count,
    }


def build_benchmark_artifact_manifest(
    suite_root: Path,
    *,
    truth: Optional[Dict[str, Any]] = None,
    config_path: Optional[Path] = None,
    execution_config_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Capture immutable benchmark/scorer/config/source identities for a trial."""

    suite_root = Path(suite_root)
    project_root = suite_root / "project"
    if not project_root.is_dir():
        project_root = suite_root
    truth_path = suite_root / "benchmark" / "ground_truth.json"
    entries_path = suite_root / "benchmark" / "entries.json"
    benchmark_manifest_path = suite_root / "benchmark" / "manifest.json"
    selected_config = Path(config_path) if config_path else suite_root / "zscope.benchmark.yaml"
    selected_execution_config = (
        Path(execution_config_path) if execution_config_path else selected_config
    )
    source_manifest = source_tree_manifest(project_root)
    truth_digest = sha256_file(truth_path)
    if not truth_digest and truth is not None:
        truth_digest = sha256_payload(truth)
    return {
        "schema_version": INTEGRITY_SCHEMA_VERSION,
        "hash_algorithm": "sha256",
        "truth_sha256": truth_digest,
        "scorer_sha256": sha256_file(Path(__file__)),
        "config_sha256": sha256_file(selected_config),
        "execution_config_sha256": sha256_file(selected_execution_config),
        "benchmark_manifest_sha256": sha256_file(benchmark_manifest_path),
        "entries_sha256": sha256_file(entries_path),
        "source_manifest_sha256": source_manifest["sha256"],
        "source_file_count": source_manifest["file_count"],
    }


def issue_identity(issue: Dict[str, Any]) -> str:
    """Return a stable issue identity for run-to-run overlap metrics."""

    stable = stable_issue_fingerprint(issue)
    if stable:
        return stable

    parts = [
        str(issue.get("dedup_key") or issue.get("id") or ""),
        str(issue.get("category") or issue.get("type") or issue.get("cwe") or ""),
        str(issue.get("function") or issue.get("func_name") or ""),
        _location_file(issue),
        str(_location_line(issue) or ""),
        _short_text(issue),
    ]
    raw = "|".join(part.lower().replace("\\", "/") for part in parts if part)
    return raw or json.dumps(issue, ensure_ascii=False, sort_keys=True)[:240]


def issue_identity_record(issue: Dict[str, Any]) -> Dict[str, Any]:
    """Return auditable identity metadata for benchmark reports."""

    pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
    stable = stable_issue_fingerprint(issue)
    return {
        "identity": issue_identity(issue),
        "stable_fingerprint": stable,
        "dedup_key": issue.get("dedup_key"),
        "candidate_id": issue.get("candidate_id") or issue.get("id"),
        "candidate_source": issue.get("candidate_source")
        or pack.get("candidate_source")
        or issue.get("finding_kind"),
        "baseline_match_strategy": issue.get("baseline_match_strategy"),
        "suppression_source": issue.get("suppression_source"),
    }


def classify_false_positive_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Classify an unmatched finding when no suite-specific audit rules are provided."""

    audited = dict(record)
    audited["fp_audit_classification"] = FP_AUDIT_NEEDS_REVIEW_ONLY
    audited["fp_audit_reason"] = (
        "unmatched finding should remain review-only until a benchmark-specific "
        "audit classifies it"
    )
    return audited


def false_positive_audit_summary(
    effective_records: Sequence[Dict[str, Any]],
    duplicate_records: Sequence[Dict[str, Any]],
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
) -> Dict[str, Any]:
    """Return an auditable split between duplicates, true extras, review-only, and suppressions."""

    classifier = fp_audit_classifier or classify_false_positive_record
    audited_duplicates = [
        {
            **dict(record),
            "fp_audit_classification": FP_AUDIT_DUPLICATE_OF_GT,
            "fp_audit_reason": "scorer classified this unmatched issue as duplicate_of_matched",
        }
        for record in duplicate_records
    ]
    audited_effective = [classifier(record) for record in effective_records]
    all_records = audited_duplicates + audited_effective
    counts: Dict[str, int] = {}
    for record in all_records:
        key = str(record.get("fp_audit_classification") or FP_AUDIT_NEEDS_REVIEW_ONLY)
        counts[key] = counts.get(key, 0) + 1
    return {
        "schema_version": "zscope.fp_audit.v1",
        "counts": counts,
        "effective_records": audited_effective,
        "duplicate_of_matched_records": audited_duplicates,
    }


def report_issues(report: Dict[str, Any], view: str = "default") -> List[Dict[str, Any]]:
    views = report.get("report_views")
    if isinstance(views, dict):
        selected = views.get(view)
        if isinstance(selected, dict) and isinstance(selected.get("issues"), list):
            return [item for item in selected["issues"] if isinstance(item, dict)]
    if isinstance(report.get("issues"), list):
        return [item for item in report["issues"] if isinstance(item, dict)]
    issues: List[Dict[str, Any]] = []
    results = report.get("results")
    if isinstance(results, dict):
        for result in results.values():
            if isinstance(result, dict) and isinstance(result.get("issues"), list):
                issues.extend(item for item in result["issues"] if isinstance(item, dict))
    return issues


def _alerted_safe_entry_identities(
    issues: Sequence[Dict[str, Any]],
    safe_entries: Sequence[Dict[str, Any]],
) -> List[str]:
    """Return known-safe entry identities that have an attributed alert."""

    alerted: Set[str] = set()
    for safe_index, safe_entry in enumerate(safe_entries):
        name = str(
            safe_entry.get("function")
            or safe_entry.get("function_name")
            or safe_entry.get("name")
            or ""
        ).strip()
        if not name:
            continue
        signature = str(
            safe_entry.get("signature")
            or safe_entry.get("full_signature")
            or ""
        ).strip()
        file_path = str(
            safe_entry.get("file")
            or safe_entry.get("file_path")
            or ""
        ).strip().replace("\\", "/")
        identity = "|".join(
            part
            for part in (
                file_path.lower(),
                signature.lower() or name.lower(),
            )
            if part
        ) or f"safe-entry-{safe_index}"
        expected_names = {name.lower()}
        if signature:
            expected_names.add(signature.lower())
        for issue in issues:
            if _issue_function_anchors(issue).intersection(expected_names):
                alerted.add(identity)
                break
    return sorted(alerted)


def _normalize_cwe(value: Any) -> str:
    text = str(value or "").strip().upper().replace("_", "-")
    if not text:
        return ""
    if text.isdigit():
        return f"CWE-{text}"
    match = re.search(r"CWE-?(\d+)", text)
    return f"CWE-{match.group(1)}" if match else text


def score_report(
    report: Dict[str, Any],
    truth: Dict[str, Any],
    *,
    view: str = "default",
    line_tolerance: int = 8,
    count_duplicate_of_matched_as_fp: bool = False,
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
) -> Dict[str, Any]:
    issues = report_issues(report, view)
    issue_texts = [
        _flatten(issue).lower().replace("\\", "/")
        for issue in issues
    ]
    vulns = [item for item in truth.get("vulnerabilities", []) if isinstance(item, dict)]
    matched_truth: Dict[str, int] = {}
    matched_pairs: List[Dict[str, Any]] = []
    matched_issues: Set[int] = set()
    potential_pairs: List[Dict[str, Any]] = []
    for truth_index, vuln in enumerate(vulns):
        truth_id = str(vuln.get("id") or truth_index)
        for issue_index, issue in enumerate(issues):
            issue_text = issue_texts[issue_index]
            match_detail = issue_match_detail(
                issue,
                vuln,
                line_tolerance,
                preflattened_text=issue_text,
            )
            if match_detail is not None:
                potential_pairs.append(
                    {
                        "truth_index": truth_index,
                        "truth_id": truth_id,
                        "issue_index": issue_index,
                        "issue": issue,
                        "match": match_detail,
                        "score": _issue_match_score(
                            issue,
                            vuln,
                            match_detail,
                            preflattened_text=issue_text,
                        ),
                    }
                )

    potential_pairs.sort(
        key=lambda pair: (
            -int(pair.get("score") or 0),
            int(pair.get("truth_index") or 0),
            int(pair.get("issue_index") or 0),
        )
    )
    matched_truth_indices: Set[int] = set()
    matched_issue_by_truth_index: Dict[int, int] = {}
    selected_pairs = _select_max_weight_pairs(potential_pairs, len(vulns), len(issues))
    for pair in selected_pairs:
        truth_index = int(pair.get("truth_index") or 0)
        issue_index = int(pair.get("issue_index") or 0)
        truth_id = str(pair.get("truth_id") or truth_index)
        if truth_index in matched_truth_indices or issue_index in matched_issues:
            continue
        matched_truth_indices.add(truth_index)
        matched_truth[truth_id] = issue_index
        matched_issues.add(issue_index)
        matched_issue_by_truth_index[truth_index] = issue_index
        issue = pair.get("issue") if isinstance(pair.get("issue"), dict) else issues[issue_index]
        matched_pairs.append(
            {
                "truth_id": truth_id,
                "issue_index": issue_index,
                "issue_identity": issue_identity(issue),
                "match": pair.get("match") or {},
                "score": pair.get("score") or 0,
            }
        )

    matched_pairs.sort(
        key=lambda pair: next(
            (
                idx
                for idx, vuln in enumerate(vulns)
                if str(vuln.get("id") or idx) == str(pair.get("truth_id"))
            ),
            0,
        )
    )

    duplicate_of_matched_indices = _duplicate_of_matched_indices(
        issues,
        potential_pairs,
        matched_issues,
        matched_truth_indices,
        matched_issue_by_truth_index,
    )
    raw_fp = max(0, len(issues) - len(matched_issues))
    effective_fp = raw_fp if count_duplicate_of_matched_as_fp else max(0, raw_fp - len(duplicate_of_matched_indices))

    tp = len(matched_truth)
    fp = effective_fp
    fn = max(0, len(vulns) - tp)
    precision = tp / (tp + fp) if tp + fp else 0.0
    actionable_precision = tp / (tp + raw_fp) if tp + raw_fp else 0.0
    recall = tp / len(vulns) if vulns else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    actionable_f1 = (
        2 * actionable_precision * recall / (actionable_precision + recall)
        if actionable_precision + recall
        else 0.0
    )
    false_discovery_rate = fp / (tp + fp) if tp + fp else 0.0
    actionable_false_discovery_rate = raw_fp / (tp + raw_fp) if tp + raw_fp else 0.0
    safe_entries = [
        item for item in truth.get("safe_entries", []) if isinstance(item, dict)
    ]
    alerted_safe_entries = _alerted_safe_entry_identities(issues, safe_entries)
    standard_false_positive_rate = (
        len(alerted_safe_entries) / len(safe_entries) if safe_entries else None
    )
    issue_ids = [issue_identity(issue) for issue in issues]
    issue_records = [issue_identity_record(issue) for issue in issues]
    raw_fp_indices = [
        index for index, _identity in enumerate(issue_ids) if index not in matched_issues
    ]
    effective_fp_indices = [
        index for index in raw_fp_indices if index not in duplicate_of_matched_indices
    ]
    fp_issue_ids = [issue_ids[index] for index in effective_fp_indices]
    fp_issue_records = [issue_records[index] for index in effective_fp_indices]
    raw_fp_issue_ids = [issue_ids[index] for index in raw_fp_indices]
    raw_fp_issue_records = [issue_records[index] for index in raw_fp_indices]
    duplicate_records = [
        {
            **issue_records[index],
            "issue_index": index,
            "duplicate_of_matched": True,
        }
        for index in sorted(duplicate_of_matched_indices)
    ]
    fp_audit = false_positive_audit_summary(
        fp_issue_records,
        duplicate_records,
        fp_audit_classifier=fp_audit_classifier,
    )
    high_critical_truth = [
        (index, vuln)
        for index, vuln in enumerate(vulns)
        if str(
            vuln.get("severity")
            or vuln.get("impact_level")
            or vuln.get("priority")
            or ""
        ).strip().lower()
        in {"high", "critical"}
    ]
    high_critical_tp = sum(
        1
        for index, vuln in high_critical_truth
        if str(vuln.get("id") or index) in matched_truth
    )
    high_critical_recall = (
        high_critical_tp / len(high_critical_truth)
        if high_critical_truth
        else None
    )
    cwe_groups: Dict[str, List[tuple[int, Dict[str, Any]]]] = {}
    for index, vuln in enumerate(vulns):
        cwe = _normalize_cwe(vuln.get("cwe"))
        if cwe:
            cwe_groups.setdefault(cwe, []).append((index, vuln))
    per_cwe_recall: Dict[str, Dict[str, Any]] = {}
    for cwe, group in sorted(cwe_groups.items()):
        matched_count = sum(
            1
            for index, vuln in group
            if str(vuln.get("id") or index) in matched_truth
        )
        per_cwe_recall[cwe] = {
            "sample_count": len(group),
            "true_positives": matched_count,
            "recall": round(matched_count / len(group), 4),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": truth.get("benchmark", "unknown"),
        "suite": truth.get("suite", "unknown"),
        "view": view,
        "report_issue_count": len(issues),
        "ground_truth_count": len(vulns),
        "safe_entry_count": len(safe_entries),
        "alerted_safe_entry_count": len(alerted_safe_entries),
        "alerted_safe_entries": alerted_safe_entries,
        "safe_entry_alert_rate": (
            round(standard_false_positive_rate, 4)
            if standard_false_positive_rate is not None
            else None
        ),
        "standard_false_positive_rate": (
            round(standard_false_positive_rate, 4)
            if standard_false_positive_rate is not None
            else None
        ),
        "true_positives": tp,
        "false_positives": fp,
        "false_positives_raw": raw_fp,
        "false_positives_effective": effective_fp,
        "duplicate_of_matched_count": len(duplicate_of_matched_indices),
        "false_negatives": fn,
        "actionable_precision": round(actionable_precision, 4),
        "actionable_f1": round(actionable_f1, 4),
        "actionable_false_discovery_rate": round(actionable_false_discovery_rate, 4),
        "root_cause_precision": round(precision, 4),
        "root_cause_f1": round(f1, 4),
        "root_cause_false_discovery_rate": round(false_discovery_rate, 4),
        "effective_precision": round(precision, 4),
        "effective_f1": round(f1, 4),
        "precision": round(precision, 4),
        "false_discovery_rate": round(false_discovery_rate, 4),
        # Deprecated compatibility alias. This has always been a false-discovery
        # rate because benchmark reports do not enumerate true negatives.
        "false_positive_rate": round(false_discovery_rate, 4),
        "recall": round(recall, 4),
        "distinct_root_recall": round(recall, 4),
        "high_critical_recall": (
            round(high_critical_recall, 4)
            if high_critical_recall is not None
            else None
        ),
        "high_critical_sample_count": len(high_critical_truth),
        "high_critical_true_positives": high_critical_tp,
        "per_cwe_recall": per_cwe_recall,
        "f1": round(f1, 4),
        "matched": sorted(matched_truth),
        "matched_pairs": matched_pairs,
        "missed": [
            str(vuln.get("id") or idx)
            for idx, vuln in enumerate(vulns)
            if str(vuln.get("id") or idx) not in matched_truth
        ],
        "matched_issue_indices": sorted(matched_issues),
        "issue_identities": issue_ids,
        "issue_identity_records": issue_records,
        "true_positive_truth_ids": sorted(matched_truth),
        "false_positive_issue_identities": fp_issue_ids,
        "false_positive_issue_records": fp_issue_records,
        "false_positive_issue_identities_raw": raw_fp_issue_ids,
        "false_positive_issue_records_raw": raw_fp_issue_records,
        "duplicate_of_matched_issue_records": duplicate_records,
        "false_positive_audit": fp_audit,
        "match_diagnostics": _match_diagnostics(
            potential_pairs,
            matched_truth_indices,
            matched_issues,
            matched_issue_by_truth_index,
            vulns,
            issues,
        ),
        "scoring_contract": {
            "line_tolerance": line_tolerance,
            "count_duplicate_of_matched_as_fp": count_duplicate_of_matched_as_fp,
            "function_anchors": [
                "function",
                "secondary_function",
                "sibling_function",
                "entry_function",
                "sink_function",
                "call_path",
            ],
            "line_placeholder_policy": "truth line <= 1 is treated as unknown",
            "category_policy": "category/cwe aliases or at least two ground-truth keyword hits",
            "primary_precision_metric": "actionable_precision",
            "primary_f1_metric": "actionable_f1",
            "primary_recall_metric": "distinct_root_recall",
            "standard_false_positive_rate_metric": (
                "safe_entry_alert_rate" if safe_entries else "unavailable"
            ),
            "legacy_precision_metric": "precision (root-cause/effective; duplicates excluded)",
        },
    }


def _select_max_weight_pairs(
    potential_pairs: List[Dict[str, Any]],
    truth_count: int,
    issue_count: int,
) -> List[Dict[str, Any]]:
    """Return a deterministic maximum-cardinality, maximum-score bipartite match."""
    if not potential_pairs or not truth_count or not issue_count:
        return []
    source = truth_count + issue_count
    sink = source + 1
    graph: List[List[Dict[str, Any]]] = [[] for _ in range(sink + 1)]

    def add_edge(u: int, v: int, cap: int, cost: int, payload: Optional[Dict[str, Any]] = None) -> None:
        graph[u].append({"to": v, "rev": len(graph[v]), "cap": cap, "cost": cost, "payload": payload})
        graph[v].append({"to": u, "rev": len(graph[u]) - 1, "cap": 0, "cost": -cost, "payload": None})

    for truth_index in range(truth_count):
        add_edge(source, truth_index, 1, 0)
    for issue_index in range(issue_count):
        add_edge(truth_count + issue_index, sink, 1, 0)

    # Encode the objectives lexicographically:
    #   1. maximum cardinality,
    #   2. maximum total match score,
    #   3. deterministic minimum stable tie value.
    #
    # A fixed cardinality bonus is incorrect because ``stable_tie`` grows with
    # the report size.  Once a report contains enough findings, a valid edge can
    # otherwise become non-negative and the min-cost flow stops before reaching
    # maximum cardinality.
    matching_bound = max(1, min(truth_count, issue_count))
    max_stable_tie = max(
        (
            int(pair.get("truth_index") or 0) * (issue_count + 1)
            + int(pair.get("issue_index") or 0)
            for pair in potential_pairs
        ),
        default=0,
    )
    max_score = max((max(0, int(pair.get("score") or 0)) for pair in potential_pairs), default=0)
    tie_total_bound = matching_bound * max_stable_tie
    score_scale = tie_total_bound + 1
    secondary_total_bound = matching_bound * (
        max_score * score_scale + max_stable_tie
    )
    cardinality_bonus = secondary_total_bound + 1
    for pair in potential_pairs:
        truth_index = int(pair.get("truth_index") or 0)
        issue_index = int(pair.get("issue_index") or 0)
        if not (0 <= truth_index < truth_count and 0 <= issue_index < issue_count):
            continue
        score = int(pair.get("score") or 0)
        stable_tie = truth_index * (issue_count + 1) + issue_index
        add_edge(
            truth_index,
            truth_count + issue_index,
            1,
            -cardinality_bonus - score * score_scale + stable_tie,
            pair,
        )

    # Initial Johnson potentials are the shortest distances in the initial
    # acyclic residual graph.  They make every reduced edge cost non-negative,
    # allowing Dijkstra for each augmentation instead of SPFA.  SPFA degrades
    # badly on large needs-review reports because residual rerouting introduces
    # many alternating paths.
    infinity = 10**100
    potential = [0] * len(graph)
    issue_distances = [infinity] * issue_count
    for truth_index in range(truth_count):
        for edge in graph[truth_index]:
            if edge.get("payload") is None or int(edge.get("cap") or 0) <= 0:
                continue
            issue_index = int(edge["to"]) - truth_count
            if 0 <= issue_index < issue_count:
                issue_distances[issue_index] = min(
                    issue_distances[issue_index],
                    int(edge["cost"]),
                )
    reachable_issue_distances = [
        distance for distance in issue_distances if distance < infinity
    ]
    for issue_index, distance in enumerate(issue_distances):
        if distance < infinity:
            potential[truth_count + issue_index] = distance
    potential[sink] = min(reachable_issue_distances, default=0)

    while True:
        dist = [infinity] * len(graph)
        prev_node = [-1] * len(graph)
        prev_edge = [-1] * len(graph)
        dist[source] = 0
        queue: List[tuple[int, int]] = [(0, source)]
        while queue:
            current_dist, node = heapq.heappop(queue)
            if current_dist != dist[node]:
                continue
            for edge_index, edge in enumerate(graph[node]):
                if int(edge["cap"]) <= 0:
                    continue
                nxt = int(edge["to"])
                reduced_cost = (
                    int(edge["cost"])
                    + potential[node]
                    - potential[nxt]
                )
                if reduced_cost < 0:
                    raise RuntimeError(
                        "negative reduced cost in benchmark matching graph"
                    )
                new_dist = current_dist + reduced_cost
                if new_dist < dist[nxt]:
                    dist[nxt] = new_dist
                    prev_node[nxt] = node
                    prev_edge[nxt] = edge_index
                    heapq.heappush(queue, (new_dist, nxt))
        if prev_node[sink] < 0:
            break
        for node, distance in enumerate(dist):
            if distance < infinity:
                potential[node] += distance
        node = sink
        while node != source:
            parent = prev_node[node]
            edge_index = prev_edge[node]
            edge = graph[parent][edge_index]
            edge["cap"] = int(edge["cap"]) - 1
            graph[node][int(edge["rev"])]["cap"] = int(graph[node][int(edge["rev"])]["cap"]) + 1
            node = parent

    selected: List[Dict[str, Any]] = []
    for truth_index in range(truth_count):
        for edge in graph[truth_index]:
            payload = edge.get("payload")
            if payload is not None and int(edge.get("cap") or 0) == 0:
                selected.append(payload)
    selected.sort(key=lambda pair: int(pair.get("truth_index") or 0))
    return selected


def _match_diagnostics(
    potential_pairs: List[Dict[str, Any]],
    matched_truth_indices: Set[int],
    matched_issues: Set[int],
    matched_issue_by_truth_index: Dict[int, int],
    vulns: List[Dict[str, Any]],
    issues: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Explain common non-match causes without changing the scoring contract."""
    potentials_by_truth: Dict[int, List[Dict[str, Any]]] = {}
    for pair in potential_pairs:
        potentials_by_truth.setdefault(int(pair.get("truth_index") or 0), []).append(pair)

    issue_to_truth = {issue_index: truth_index for truth_index, issue_index in matched_issue_by_truth_index.items()}
    matched_elsewhere: List[Dict[str, Any]] = []
    for truth_index, vuln in enumerate(vulns):
        if truth_index in matched_truth_indices:
            continue
        pairs = potentials_by_truth.get(truth_index, [])
        diverted = [pair for pair in pairs if int(pair.get("issue_index") or 0) in matched_issues]
        if not diverted:
            continue
        best = max(diverted, key=lambda pair: int(pair.get("score") or 0))
        issue_index = int(best.get("issue_index") or 0)
        matched_truth_index = issue_to_truth.get(issue_index)
        matched_truth = vulns[matched_truth_index] if matched_truth_index is not None and matched_truth_index < len(vulns) else {}
        matched_elsewhere.append(
            {
                "truth_id": str(vuln.get("id") or truth_index),
                "issue_index": issue_index,
                "issue_identity": issue_identity(issues[issue_index]) if issue_index < len(issues) else "",
                "matched_truth_id": str(matched_truth.get("id") or matched_truth_index or ""),
                "score": best.get("score") or 0,
                "match": best.get("match") or {},
            }
        )

    return {
        "candidate_still_present_but_matched_another_truth": matched_elsewhere,
        "unmatched_truth_with_potential_pair_count": sum(
            1 for truth_index in potentials_by_truth if truth_index not in matched_truth_indices
        ),
    }


def _duplicate_of_matched_indices(
    issues: List[Dict[str, Any]],
    potential_pairs: List[Dict[str, Any]],
    matched_issues: Set[int],
    matched_truth_indices: Set[int],
    matched_issue_by_truth_index: Dict[int, int],
) -> Set[int]:
    """Classify unmatched report issues that duplicate an already matched TP."""
    duplicates: Set[int] = set()
    potentials_by_issue: Dict[int, List[Dict[str, Any]]] = {}
    for pair in potential_pairs:
        issue_index = int(pair.get("issue_index") or 0)
        potentials_by_issue.setdefault(issue_index, []).append(pair)

    for issue_index, issue in enumerate(issues):
        if issue_index in matched_issues:
            continue
        direct_pairs = potentials_by_issue.get(issue_index, [])
        if any(int(pair.get("truth_index") or 0) in matched_truth_indices for pair in direct_pairs):
            duplicates.add(issue_index)
            continue
        for matched_index in matched_issue_by_truth_index.values():
            if matched_index >= len(issues):
                continue
            if issues_may_share_root_cause(
                issues[matched_index],
                issue,
                require_concrete_root=True,
            ):
                duplicates.add(issue_index)
                break
    return duplicates


def score_report_views(
    report: Dict[str, Any],
    truth: Dict[str, Any],
    *,
    line_tolerance: int = 8,
    count_duplicate_of_matched_as_fp: bool = False,
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
) -> Dict[str, Dict[str, Any]]:
    return {
        "default": score_report(
            report,
            truth,
            view="default",
            line_tolerance=line_tolerance,
            count_duplicate_of_matched_as_fp=count_duplicate_of_matched_as_fp,
            fp_audit_classifier=fp_audit_classifier,
        ),
        "with_needs_review": score_report(
            report,
            truth,
            view="with_needs_review",
            line_tolerance=line_tolerance,
            count_duplicate_of_matched_as_fp=count_duplicate_of_matched_as_fp,
            fp_audit_classifier=fp_audit_classifier,
        ),
    }


def issue_matches(issue: Dict[str, Any], truth: Dict[str, Any], line_tolerance: int) -> bool:
    return issue_match_detail(issue, truth, line_tolerance) is not None


def issue_match_detail(
    issue: Dict[str, Any],
    truth: Dict[str, Any],
    line_tolerance: int,
    *,
    preflattened_text: Optional[str] = None,
) -> Optional[Dict[str, str]]:
    text = (
        preflattened_text
        if preflattened_text is not None
        else _flatten(issue).lower().replace("\\", "/")
    )
    category_reason = _category_match_reason(text, truth)
    if not category_reason:
        return None
    function_reason = _function_match_reason(issue, text, truth)
    if not function_reason:
        return None
    file_reason = _file_match_reason(text, truth)
    if not file_reason:
        return None
    line_reason = _line_match_reason(issue, truth, line_tolerance)
    if not line_reason:
        return None
    return {
        "category": category_reason,
        "function": function_reason,
        "file": file_reason,
        "line": line_reason,
    }


def _issue_match_score(
    issue: Dict[str, Any],
    truth: Dict[str, Any],
    detail: Dict[str, str],
    *,
    preflattened_text: Optional[str] = None,
) -> int:
    score = 0
    issue_category = str(issue.get("category") or issue.get("type") or "").lower().replace("-", "_")
    truth_category = str(truth.get("category") or "").lower().replace("-", "_")
    issue_cwe = str(issue.get("cwe") or "").lower()
    truth_cwe = str(truth.get("cwe") or "").lower()
    if issue_category and issue_category == truth_category:
        score += 70
    elif issue_cwe and truth_cwe and issue_cwe == truth_cwe:
        score += 65
    elif str(detail.get("category") or "").startswith("category_alias"):
        score += 35
    else:
        score += 20

    issue_func = _issue_function(issue)
    anchors = _issue_function_anchors(issue)
    text = (
        preflattened_text
        if preflattened_text is not None
        else _flatten(issue).lower().replace("\\", "/")
    )
    expected_functions = _truth_function_anchors(truth)
    scored_function = False
    for kind, func in expected_functions:
        if issue_func == func:
            score += 100 if kind == "primary" else 85
            scored_function = True
            break
        if func in anchors:
            score += 90 if kind == "primary" else 75
            scored_function = True
            break
    if not scored_function:
        for kind, func in expected_functions:
            if func in text:
                score += 45 if kind == "primary" else 35
                break

    file_reason = str(detail.get("file") or "")
    if file_reason in {"path", "secondary_path"} or file_reason.startswith("additional_path"):
        score += 20
    elif file_reason:
        score += 10

    line_reason = str(detail.get("line") or "")
    if "within_tolerance" in line_reason:
        score += 20
    elif line_reason == "no_expected_line":
        score += 2

    keyword_hits = _truth_keyword_hits(text.replace("_", " ").replace("-", " "), truth)
    score += min(keyword_hits, 4)
    return score


def collect_environment_metadata(
    *,
    suite_root: Path,
    condition: str,
    run_kind: str,
    command: Sequence[str],
    started_at: float,
    finished_at: float,
    return_code: Optional[int] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    config = config or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "condition": condition,
        "run_kind": run_kind,
        "suite_root": str(suite_root),
        "command": list(command),
        "return_code": return_code,
        "wall_time_seconds": round(max(0.0, finished_at - started_at), 4),
        "started_at_unix": started_at,
        "finished_at_unix": finished_at,
        "zscope_version": __version__,
        "commit_sha": _git_commit_sha(Path.cwd()),
        "python": sys.version.split()[0],
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "backend": config.get("backend", ""),
        "model": config.get("model", ""),
        "prompt_autofill": config.get("prompt_autofill", {}),
        "env": {
            "Z_SCOPE_BASE_URL": _redact_url(str(os.environ.get("Z_SCOPE_BASE_URL", ""))),
            "Z_SCOPE_MODEL": os.environ.get("Z_SCOPE_MODEL", ""),
        },
    }


def build_cost_metrics(
    report: Dict[str, Any],
    evaluation: Dict[str, Any],
    *,
    wall_time_seconds: float = 0.0,
) -> Dict[str, Any]:
    metadata = _collect_metadata(report)
    context_tokens = _sum_numeric(metadata, ("context_tokens",))
    cumulative_tokens = _sum_numeric(metadata, ("cumulative_total_tokens",))
    tool_calls = _sum_numeric(metadata, ("tool_call_count", "tool_calls"))
    report_tail_seconds = _max_numeric(
        metadata,
        (
            "report_tail_seconds",
            "report_assembly_seconds",
            "reporting_seconds",
            "final_report_seconds",
        ),
    )
    billable_tokens = cumulative_tokens or context_tokens
    verified = max(1, int(evaluation.get("true_positives") or 0))
    return {
        "context_tokens": context_tokens,
        "cumulative_total_tokens": cumulative_tokens,
        "billable_tokens": billable_tokens,
        "tool_calls": tool_calls,
        "wall_time_seconds": round(wall_time_seconds, 4),
        "report_tail_seconds": report_tail_seconds,
        "tokens_per_verified_issue": round(billable_tokens / verified, 4) if billable_tokens else 0.0,
        "tool_calls_per_verified_issue": round(tool_calls / verified, 4) if tool_calls else 0.0,
    }


def copy_conversation_trajectory(project_root: Path, run_dir: Path) -> List[str]:
    """Copy the latest verbose conversation recorder output into the run dir."""

    source_root = project_root / ".zscope_conversations"
    if not source_root.exists():
        return []
    run_dirs = [path for path in source_root.iterdir() if path.is_dir()]
    if not run_dirs:
        return []
    latest = max(run_dirs, key=lambda path: path.stat().st_mtime)
    target = run_dir / "trajectory" / "conversations" / latest.name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(latest, target)
    return [path.relative_to(run_dir).as_posix() for path in sorted(target.rglob("*")) if path.is_file()]


def build_trajectory_summary(
    report: Dict[str, Any],
    *,
    run_dir: Path,
    conversation_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    worker_reports = metadata.get("subagent_reports") if isinstance(metadata, dict) else []
    workflow_progress = metadata.get("workflow_progress") if isinstance(metadata, dict) else []
    return {
        "schema_version": SCHEMA_VERSION,
        "run_dir": run_dir.as_posix(),
        "conversation_files": conversation_files or [],
        "workflow_progress": workflow_progress if isinstance(workflow_progress, list) else [],
        "worker_report_count": len(worker_reports) if isinstance(worker_reports, list) else 0,
        "worker_reports": worker_reports if isinstance(worker_reports, list) else [],
        "validator": {
            "present": "validator" in _flatten(metadata).lower(),
            "audit_observation_count": metadata.get("audit_observation_count", 0),
        },
    }


def grade_trial(
    evaluation: Dict[str, Any],
    cost: Dict[str, Any],
    trajectory: Dict[str, Any],
) -> Dict[str, Any]:
    final_outcome_score = float(
        evaluation.get("actionable_f1")
        if evaluation.get("actionable_f1") is not None
        else evaluation.get("f1") or 0.0
    )
    has_trajectory = bool(trajectory.get("conversation_files") or trajectory.get("workflow_progress"))
    evidence_score = 1.0 if has_trajectory or trajectory.get("worker_report_count", 0) else 0.5
    tool_behavior_score = 1.0
    if cost.get("tool_calls_per_verified_issue", 0.0) > 80:
        tool_behavior_score = 0.5
    return {
        "schema_version": SCHEMA_VERSION,
        "final_outcome": {
            "score": round(final_outcome_score, 4),
            "basis": (
                "Actionable F1 against ground truth; every surfaced duplicate "
                "counts as a false positive."
            ),
        },
        "tool_behavior": {
            "score": tool_behavior_score,
            "basis": "Deterministic check over tool-call cost and policy-visible trajectory.",
        },
        "evidence_traceability": {
            "score": evidence_score,
            "basis": "Workflow progress, conversation files, or worker reports are replayable.",
        },
        "cost_efficiency": {
            "tokens_per_verified_issue": cost.get("tokens_per_verified_issue", 0.0),
            "tool_calls_per_verified_issue": cost.get("tool_calls_per_verified_issue", 0.0),
        },
    }


def build_trial_summary(
    *,
    suite_root: Path,
    run_dir: Path,
    condition: str,
    run_kind: str,
    trial_index: int,
    report: Dict[str, Any],
    truth: Dict[str, Any],
    environment: Dict[str, Any],
    line_tolerance: int = 8,
    conversation_files: Optional[List[str]] = None,
    fp_audit_classifier: Optional[FalsePositiveClassifier] = None,
    integrity: Optional[Dict[str, Any]] = None,
    artifact_manifest: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evaluation_views = score_report_views(
        report,
        truth,
        line_tolerance=line_tolerance,
        fp_audit_classifier=fp_audit_classifier,
    )
    default_eval = evaluation_views["default"]
    cost = build_cost_metrics(
        report,
        default_eval,
        wall_time_seconds=float(environment.get("wall_time_seconds") or 0.0),
    )
    trajectory = build_trajectory_summary(
        report,
        run_dir=run_dir,
        conversation_files=conversation_files,
    )
    grader = grade_trial(default_eval, cost, trajectory)
    if artifact_manifest is None:
        artifact_manifest = build_benchmark_artifact_manifest(
            suite_root,
            truth=truth,
        )
    if integrity is None:
        integrity = {
            "schema_version": INTEGRITY_SCHEMA_VERSION,
            "status": "not_run_verified",
            "errors": [],
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": truth.get("benchmark", suite_root.name),
        "suite": truth.get("suite", "unknown"),
        "condition": condition,
        "run_kind": run_kind,
        "trial_index": trial_index,
        "run_dir": run_dir.as_posix(),
        "environment": environment,
        "evaluation_views": evaluation_views,
        "evaluation": default_eval,
        "cost": cost,
        "trajectory": trajectory,
        "grader": grader,
        "artifact_manifest": artifact_manifest,
        "integrity": integrity,
        "final_answer": {
            "report_issue_count": default_eval.get("report_issue_count", 0),
            "issue_identities": default_eval.get("issue_identities", []),
        },
        "final_outcome": {
            "true_positive_truth_ids": default_eval.get("true_positive_truth_ids", []),
            "false_positive_issue_identities": default_eval.get(
                "false_positive_issue_identities", []
            ),
            "missed_truth_ids": default_eval.get("missed", []),
        },
    }


def aggregate_trial_summaries(
    summaries: Sequence[Dict[str, Any]],
    *,
    baseline_summaries: Optional[Sequence[Dict[str, Any]]] = None,
    baseline_tokens_per_tp: Optional[float] = None,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
    require_improvement_claim: bool = False,
) -> Dict[str, Any]:
    summaries = [summary for summary in summaries if isinstance(summary, dict)]
    by_condition: Dict[str, List[Dict[str, Any]]] = {}
    for summary in summaries:
        by_condition.setdefault(str(summary.get("condition") or "unknown"), []).append(summary)

    conditions: Dict[str, Any] = {}
    for condition, items in by_condition.items():
        f1_values = [float(item.get("evaluation", {}).get("f1") or 0.0) for item in items]
        actionable_f1_values = [
            float(
                item.get("evaluation", {}).get("actionable_f1")
                if item.get("evaluation", {}).get("actionable_f1") is not None
                else item.get("evaluation", {}).get("f1")
                or 0.0
            )
            for item in items
        ]
        precision_values = [
            float(item.get("evaluation", {}).get("precision") or 0.0) for item in items
        ]
        actionable_precision_values = [
            float(
                item.get("evaluation", {}).get("actionable_precision")
                if item.get("evaluation", {}).get("actionable_precision") is not None
                else item.get("evaluation", {}).get("precision")
                or 0.0
            )
            for item in items
        ]
        recall_values = [float(item.get("evaluation", {}).get("recall") or 0.0) for item in items]
        issue_sets = [
            set(item.get("evaluation", {}).get("issue_identities") or []) for item in items
        ]
        tp_sets = [
            set(item.get("evaluation", {}).get("true_positive_truth_ids") or []) for item in items
        ]
        fp_sets = [
            set(item.get("evaluation", {}).get("false_positive_issue_identities") or [])
            for item in items
        ]
        wall_values = _summary_numeric_values(items, "cost", "wall_time_seconds")
        token_values = _summary_numeric_values(items, "cost", "billable_tokens")
        token_per_tp_values = _summary_numeric_values(
            items,
            "cost",
            "tokens_per_verified_issue",
            positive_only=True,
        )
        report_tail_values = _summary_numeric_values(
            items,
            "cost",
            "report_tail_seconds",
        )
        high_critical_values = _summary_numeric_values(
            items,
            "evaluation",
            "high_critical_recall",
        )
        safe_alert_values = _summary_numeric_values(
            items,
            "evaluation",
            "safe_entry_alert_rate",
        )
        cwe_values = _aggregate_cwe_series(
            items,
            bootstrap_samples=bootstrap_samples,
            confidence_level=confidence_level,
        )
        release_valid = [item for item in items if _is_valid_release_trial(item)]
        conditions[condition] = {
            "trial_count": len(items),
            "valid_release_trial_count": len(release_valid),
            "precision": _series_stats(
                precision_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "actionable_precision": _series_stats(
                actionable_precision_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "recall": _series_stats(
                recall_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "distinct_root_recall": _series_stats(
                recall_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "high_critical_recall": _series_stats(
                high_critical_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "safe_entry_alert_rate": _series_stats(
                safe_alert_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "per_cwe_recall": cwe_values,
            "f1": _series_stats(
                f1_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "actionable_f1": _series_stats(
                actionable_f1_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
            "wall_time_seconds": _series_stats(
                wall_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "billable_tokens": _series_stats(
                token_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "tokens_per_verified_issue": _series_stats(
                token_per_tp_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "report_tail_seconds": _series_stats(
                report_tail_values,
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
                ci_statistic="median",
            ),
            "issue_jaccard": _mean_pairwise_jaccard(issue_sets),
            "true_positive_overlap": _mean_pairwise_jaccard(tp_sets),
            "false_positive_overlap": _mean_pairwise_jaccard(fp_sets),
        }
    result = {
        "schema_version": SCHEMA_VERSION,
        "trial_count": len(summaries),
        "bootstrap": {
            "method": "nonparametric_resampling_with_replacement",
            "confidence_level": confidence_level,
            "samples": max(0, int(bootstrap_samples)),
            "seed": 0,
        },
        "conditions": conditions,
    }
    result["release_readiness"] = evaluate_release_readiness(
        summaries,
        conditions=conditions,
        baseline_summaries=baseline_summaries,
        baseline_tokens_per_tp=baseline_tokens_per_tp,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        require_improvement_claim=require_improvement_claim,
    )
    return result


def _summary_numeric_values(
    summaries: Sequence[Dict[str, Any]],
    section: str,
    key: str,
    *,
    positive_only: bool = False,
) -> List[float]:
    values: List[float] = []
    for summary in summaries:
        data = summary.get(section)
        value = data.get(key) if isinstance(data, dict) else None
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        number = float(value)
        if positive_only and number <= 0:
            continue
        values.append(number)
    return values


def _aggregate_cwe_series(
    summaries: Sequence[Dict[str, Any]],
    *,
    bootstrap_samples: int,
    confidence_level: float,
) -> Dict[str, Any]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for summary in summaries:
        evaluation = summary.get("evaluation")
        per_cwe = evaluation.get("per_cwe_recall") if isinstance(evaluation, dict) else None
        if not isinstance(per_cwe, dict):
            continue
        for raw_cwe, row in per_cwe.items():
            if not isinstance(row, dict):
                continue
            cwe = _normalize_cwe(raw_cwe)
            if not cwe:
                continue
            target = grouped.setdefault(cwe, {"sample_counts": [], "values": []})
            sample_count = row.get("sample_count")
            recall = row.get("recall")
            if isinstance(sample_count, int) and not isinstance(sample_count, bool):
                target["sample_counts"].append(sample_count)
            if isinstance(recall, (int, float)) and not isinstance(recall, bool):
                target["values"].append(float(recall))
    result: Dict[str, Any] = {}
    for cwe, row in sorted(grouped.items()):
        sample_counts = row["sample_counts"]
        result[cwe] = {
            "sample_count": max(sample_counts) if sample_counts else 0,
            **_series_stats(
                row["values"],
                bootstrap_samples=bootstrap_samples,
                confidence_level=confidence_level,
            ),
        }
    return result


def _release_trial_errors(summary: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if str(summary.get("run_kind") or "") != "formal":
        errors.append("run_kind is not formal")
    integrity = summary.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("status") != "passed":
        errors.append("integrity status is not passed")
    else:
        chain_sha = str(integrity.get("chain_sha256") or "")
        if len(chain_sha) != 64:
            errors.append("integrity chain hash is missing")
    environment = summary.get("environment")
    return_code = environment.get("return_code") if isinstance(environment, dict) else None
    if return_code not in {0, 1}:
        errors.append(f"unexpected return code: {return_code}")
    condition = str(summary.get("condition") or "")
    cache_mode = ""
    if isinstance(integrity, dict):
        cache_mode = str(integrity.get("cache_mode") or "")
    if not cache_mode and isinstance(environment, dict):
        cache_mode = str(environment.get("cache_mode") or "")
    expected_cache_modes = (
        {"isolated_cold"}
        if condition == CONDITION_FULL_ZSCOPE
        else {"isolated_cold", "not_applicable"}
    )
    if cache_mode not in expected_cache_modes:
        errors.append(f"invalid cache mode for release trial: {cache_mode or 'missing'}")
    manifest = summary.get("artifact_manifest")
    required_hashes = (
        "truth_sha256",
        "scorer_sha256",
        "config_sha256",
        "entries_sha256",
        "source_manifest_sha256",
    )
    if not isinstance(manifest, dict):
        errors.append("artifact manifest is missing")
    else:
        missing = [key for key in required_hashes if len(str(manifest.get(key) or "")) != 64]
        if missing:
            errors.append(f"artifact hashes missing: {', '.join(missing)}")
    return errors


def _is_valid_release_trial(summary: Dict[str, Any]) -> bool:
    return not _release_trial_errors(summary)


def _artifact_protocol_signature(summary: Dict[str, Any]) -> tuple[str, ...]:
    manifest = summary.get("artifact_manifest")
    if not isinstance(manifest, dict):
        return ()
    environment = summary.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    return tuple(
        str(manifest.get(key) or "")
        for key in (
            "truth_sha256",
            "scorer_sha256",
            "config_sha256",
            "entries_sha256",
            "source_manifest_sha256",
        )
    ) + (
        str(environment.get("backend") or ""),
        str(environment.get("model") or ""),
    )


def _artifact_dataset_signature(summary: Dict[str, Any]) -> tuple[str, ...]:
    manifest = summary.get("artifact_manifest")
    if not isinstance(manifest, dict):
        return ()
    return tuple(
        str(manifest.get(key) or "")
        for key in (
            "truth_sha256",
            "scorer_sha256",
            "entries_sha256",
            "source_manifest_sha256",
        )
    )


def _trial_protocol_status(
    summaries: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    by_condition: Dict[str, List[Dict[str, Any]]] = {}
    for summary in summaries:
        by_condition.setdefault(str(summary.get("condition") or "unknown"), []).append(summary)
    condition_rows: Dict[str, Any] = {}
    valid_index_sets: List[Set[int]] = []
    protocol_passed = bool(by_condition)
    all_signatures: Set[tuple[str, ...]] = set()
    for condition, items in sorted(by_condition.items()):
        valid_items = [item for item in items if _is_valid_release_trial(item)]
        valid_indices = {
            int(item.get("trial_index"))
            for item in valid_items
            if isinstance(item.get("trial_index"), int)
            and not isinstance(item.get("trial_index"), bool)
        }
        valid_index_sets.append(valid_indices)
        signatures = {
            signature
            for signature in (_artifact_protocol_signature(item) for item in valid_items)
            if signature
        }
        all_signatures.update(
            signature
            for signature in (_artifact_dataset_signature(item) for item in valid_items)
            if signature
        )
        duplicate_indices = len(valid_indices) != len(valid_items)
        passed = (
            len(items) >= MIN_RELEASE_TRIALS
            and len(valid_items) == len(items)
            and len(valid_indices) >= MIN_RELEASE_TRIALS
            and not duplicate_indices
            and len(signatures) == 1
        )
        protocol_passed = protocol_passed and passed
        condition_rows[condition] = {
            "trial_count": len(items),
            "valid_cold_trial_count": len(valid_items),
            "valid_trial_indices": sorted(valid_indices),
            "minimum_required": MIN_RELEASE_TRIALS,
            "duplicate_trial_indices": duplicate_indices,
            "artifact_signature_count": len(signatures),
            "passed": passed,
            "invalid_trials": [
                {
                    "trial_index": item.get("trial_index"),
                    "errors": _release_trial_errors(item),
                }
                for item in items
                if not _is_valid_release_trial(item)
            ],
        }
    paired_indices = (
        set.intersection(*valid_index_sets)
        if valid_index_sets
        else set()
    )
    paired_passed = len(paired_indices) >= MIN_RELEASE_TRIALS
    protocol_passed = (
        protocol_passed
        and paired_passed
        and len(all_signatures) == 1
    )
    return {
        "minimum_trials_per_condition": MIN_RELEASE_TRIALS,
        "conditions": condition_rows,
        "paired_trial_indices": sorted(paired_indices),
        "paired_trial_count": len(paired_indices),
        "paired_trials_passed": paired_passed,
        "cross_condition_artifact_signature_count": len(all_signatures),
        "passed": protocol_passed,
    }


def _metric_gate(
    *,
    actual: Optional[float],
    threshold: float,
    operator: str,
    statistics: Optional[Dict[str, Any]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    available = actual is not None
    if operator == ">=":
        passed = available and float(actual) >= threshold
    elif operator == "<=":
        passed = available and float(actual) <= threshold
    else:  # pragma: no cover - internal contract
        raise ValueError(f"Unsupported release gate operator: {operator}")
    result: Dict[str, Any] = {
        "actual": round(float(actual), 4) if available else None,
        "threshold": threshold,
        "operator": operator,
        "available": available,
        "passed": bool(passed),
    }
    if statistics is not None:
        result["statistics"] = statistics
    if details:
        result["details"] = details
    return result


def evaluate_release_readiness(
    summaries: Sequence[Dict[str, Any]],
    *,
    conditions: Optional[Dict[str, Any]] = None,
    baseline_summaries: Optional[Sequence[Dict[str, Any]]] = None,
    baseline_tokens_per_tp: Optional[float] = None,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
    require_improvement_claim: bool = False,
) -> Dict[str, Any]:
    summaries = [item for item in summaries if isinstance(item, dict)]
    trial_protocol = _trial_protocol_status(summaries)
    target_items = [
        item
        for item in summaries
        if str(item.get("condition") or "") == CONDITION_FULL_ZSCOPE
        and _is_valid_release_trial(item)
    ]
    if not target_items:
        return {
            "status": "not_evaluated",
            "passed": False,
            "reason": "no valid formal cold full-pipeline trials",
            "trial_protocol": trial_protocol,
            "hard_gates": {},
            "optional_gates": {},
            "improvement_claim": {
                "status": "not_evaluated",
                "passed": False,
                "reason": "baseline and current paired trials are unavailable",
            },
        }

    def eval_values(key: str, *, fallback: str = "") -> List[float]:
        values = _summary_numeric_values(target_items, "evaluation", key)
        return values or (
            _summary_numeric_values(target_items, "evaluation", fallback)
            if fallback
            else []
        )

    precision_stats = _series_stats(
        eval_values("actionable_precision"),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
    )
    recall_stats = _series_stats(
        eval_values("distinct_root_recall", fallback="recall"),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
    )
    high_stats = _series_stats(
        eval_values("high_critical_recall"),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
    )
    safe_stats = _series_stats(
        eval_values("safe_entry_alert_rate"),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
    )
    actionable_f1_stats = _series_stats(
        eval_values("actionable_f1"),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
    )
    wall_stats = _series_stats(
        _summary_numeric_values(target_items, "cost", "wall_time_seconds", positive_only=True),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    token_stats = _series_stats(
        _summary_numeric_values(target_items, "cost", "billable_tokens", positive_only=True),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    token_per_tp_stats = _series_stats(
        _summary_numeric_values(
            target_items,
            "cost",
            "tokens_per_verified_issue",
            positive_only=True,
        ),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    report_tail_stats = _series_stats(
        _summary_numeric_values(target_items, "cost", "report_tail_seconds"),
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    issue_sets = [
        set(item.get("evaluation", {}).get("issue_identities") or [])
        for item in target_items
    ]
    tp_sets = [
        set(item.get("evaluation", {}).get("true_positive_truth_ids") or [])
        for item in target_items
    ]
    tp_jaccard = _mean_pairwise_jaccard(tp_sets)
    alert_jaccard = _mean_pairwise_jaccard(issue_sets)
    cwe_stats = _aggregate_cwe_series(
        target_items,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
    )
    eligible_cwes = {
        cwe: row
        for cwe, row in cwe_stats.items()
        if int(row.get("sample_count") or 0)
        >= int(RELEASE_THRESHOLDS["per_cwe_min_samples"])
    }
    failing_cwes = {
        cwe: row
        for cwe, row in eligible_cwes.items()
        if float(row.get("mean") or 0.0) < RELEASE_THRESHOLDS["per_cwe_recall"]
    }

    hard_gates: Dict[str, Any] = {
        "trial_protocol": {
            "actual": trial_protocol.get("paired_trial_count", 0),
            "threshold": MIN_RELEASE_TRIALS,
            "operator": ">=",
            "available": True,
            "passed": bool(trial_protocol.get("passed")),
            "details": trial_protocol,
        },
        "actionable_precision": _metric_gate(
            actual=precision_stats.get("mean") if precision_stats["values"] else None,
            threshold=RELEASE_THRESHOLDS["actionable_precision"],
            operator=">=",
            statistics=precision_stats,
        ),
        "distinct_root_recall": _metric_gate(
            actual=recall_stats.get("mean") if recall_stats["values"] else None,
            threshold=RELEASE_THRESHOLDS["distinct_root_recall"],
            operator=">=",
            statistics=recall_stats,
        ),
        "high_critical_recall": _metric_gate(
            actual=high_stats.get("mean") if len(high_stats["values"]) == len(target_items) else None,
            threshold=RELEASE_THRESHOLDS["high_critical_recall"],
            operator=">=",
            statistics=high_stats,
        ),
        "safe_entry_alert_rate": _metric_gate(
            actual=safe_stats.get("mean") if len(safe_stats["values"]) == len(target_items) else None,
            threshold=RELEASE_THRESHOLDS["safe_entry_alert_rate"],
            operator="<=",
            statistics=safe_stats,
        ),
        "per_cwe_recall": {
            "actual": (
                min(float(row.get("mean") or 0.0) for row in eligible_cwes.values())
                if eligible_cwes
                else None
            ),
            "threshold": RELEASE_THRESHOLDS["per_cwe_recall"],
            "operator": ">=",
            "available": True,
            "passed": not failing_cwes,
            "details": {
                "minimum_samples": RELEASE_THRESHOLDS["per_cwe_min_samples"],
                "eligible": eligible_cwes,
                "failing": failing_cwes,
            },
        },
        "actionable_f1_stdev": _metric_gate(
            actual=float(actionable_f1_stats.get("stdev") or 0.0)
            if actionable_f1_stats["values"]
            else None,
            threshold=RELEASE_THRESHOLDS["actionable_f1_stdev"],
            operator="<=",
            statistics=actionable_f1_stats,
        ),
        "true_positive_jaccard": _metric_gate(
            actual=tp_jaccard,
            threshold=RELEASE_THRESHOLDS["true_positive_jaccard"],
            operator=">=",
        ),
        "alert_jaccard": _metric_gate(
            actual=alert_jaccard,
            threshold=RELEASE_THRESHOLDS["alert_jaccard"],
            operator=">=",
        ),
        "median_wall_time_seconds": _metric_gate(
            actual=wall_stats.get("median") if len(wall_stats["values"]) == len(target_items) else None,
            threshold=RELEASE_THRESHOLDS["median_wall_time_seconds"],
            operator="<=",
            statistics=wall_stats,
        ),
        "median_billable_tokens": _metric_gate(
            actual=token_stats.get("median") if len(token_stats["values"]) == len(target_items) else None,
            threshold=RELEASE_THRESHOLDS["median_billable_tokens"],
            operator="<=",
            statistics=token_stats,
        ),
        "median_report_tail_seconds": _metric_gate(
            actual=(
                report_tail_stats.get("median")
                if len(report_tail_stats["values"]) == len(target_items)
                else None
            ),
            threshold=RELEASE_THRESHOLDS["median_report_tail_seconds"],
            operator="<=",
            statistics=report_tail_stats,
        ),
    }

    provided_baseline_summaries = [
        item for item in (baseline_summaries or []) if isinstance(item, dict)
    ]
    baseline_protocol = (
        _trial_protocol_status(provided_baseline_summaries)
        if provided_baseline_summaries
        else None
    )
    baseline_items = [
        item
        for item in provided_baseline_summaries
        if str(item.get("condition") or "") == CONDITION_FULL_ZSCOPE
        and _is_valid_release_trial(item)
    ]
    baseline_token_value = (
        float(baseline_tokens_per_tp)
        if isinstance(baseline_tokens_per_tp, (int, float))
        and not isinstance(baseline_tokens_per_tp, bool)
        and float(baseline_tokens_per_tp) > 0
        else None
    )
    if (
        baseline_token_value is None
        and baseline_items
        and baseline_protocol is not None
        and baseline_protocol.get("passed")
    ):
        baseline_token_stats = _series_stats(
            _summary_numeric_values(
                baseline_items,
                "cost",
                "tokens_per_verified_issue",
                positive_only=True,
            ),
            bootstrap_samples=bootstrap_samples,
            confidence_level=confidence_level,
            ci_statistic="median",
        )
        if baseline_token_stats["values"]:
            baseline_token_value = float(baseline_token_stats["median"])
    current_token_value = (
        float(token_per_tp_stats["median"])
        if token_per_tp_stats["values"]
        else None
    )
    if baseline_token_value is not None:
        reduction = (
            (baseline_token_value - current_token_value) / baseline_token_value
            if current_token_value is not None
            else None
        )
        token_baseline_gate = _metric_gate(
            actual=reduction,
            threshold=RELEASE_THRESHOLDS["tokens_per_true_positive_reduction"],
            operator=">=",
            statistics=token_per_tp_stats,
            details={
                "baseline_tokens_per_true_positive": baseline_token_value,
                "current_tokens_per_true_positive": current_token_value,
            },
        )
        hard_gates["tokens_per_true_positive_reduction"] = token_baseline_gate
    elif provided_baseline_summaries and baseline_protocol is not None:
        token_baseline_gate = {
            "status": "invalid_baseline",
            "passed": False,
            "available": False,
            "reason": "frozen baseline summaries failed the five-trial protocol",
            "details": baseline_protocol,
        }
        hard_gates["tokens_per_true_positive_reduction"] = token_baseline_gate
    else:
        token_baseline_gate = {
            "status": "not_evaluated",
            "passed": True,
            "reason": "no frozen baseline was supplied",
        }

    if provided_baseline_summaries and baseline_protocol is not None and not baseline_protocol.get(
        "passed"
    ):
        improvement_claim = {
            "status": "invalid_baseline",
            "passed": False,
            "reason": "baseline summaries failed the five-trial cold protocol",
            "trial_protocol": baseline_protocol,
        }
    else:
        improvement_claim = evaluate_improvement_claim(
            target_items,
            baseline_items,
            bootstrap_samples=bootstrap_samples,
            confidence_level=confidence_level,
        )
    if require_improvement_claim:
        hard_gates["improvement_claim"] = {
            **improvement_claim,
            "available": improvement_claim.get("status") != "not_evaluated",
        }
    passed = all(bool(gate.get("passed")) for gate in hard_gates.values())
    return {
        "status": "passed" if passed else "failed",
        "passed": passed,
        "target_condition": CONDITION_FULL_ZSCOPE,
        "thresholds": dict(RELEASE_THRESHOLDS),
        "trial_protocol": trial_protocol,
        "hard_gates": hard_gates,
        "optional_gates": {
            "tokens_per_true_positive_reduction": token_baseline_gate,
        },
        "improvement_claim": improvement_claim,
        "require_improvement_claim": require_improvement_claim,
    }


def evaluate_improvement_claim(
    current_summaries: Sequence[Dict[str, Any]],
    baseline_summaries: Sequence[Dict[str, Any]],
    *,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
) -> Dict[str, Any]:
    if not current_summaries or not baseline_summaries:
        return {
            "status": "not_evaluated",
            "passed": False,
            "reason": "paired current and baseline summaries are required",
        }
    current_by_index = {
        int(item["trial_index"]): item
        for item in current_summaries
        if isinstance(item.get("trial_index"), int)
        and not isinstance(item.get("trial_index"), bool)
    }
    baseline_by_index = {
        int(item["trial_index"]): item
        for item in baseline_summaries
        if isinstance(item.get("trial_index"), int)
        and not isinstance(item.get("trial_index"), bool)
    }
    paired_indices = sorted(set(current_by_index).intersection(baseline_by_index))
    if len(paired_indices) < MIN_RELEASE_TRIALS:
        return {
            "status": "insufficient_data",
            "passed": False,
            "reason": f"at least {MIN_RELEASE_TRIALS} paired trials are required",
            "paired_trial_indices": paired_indices,
        }
    current_signatures = {
        _artifact_dataset_signature(current_by_index[index]) for index in paired_indices
    }
    baseline_signatures = {
        _artifact_dataset_signature(baseline_by_index[index]) for index in paired_indices
    }
    if len(current_signatures) != 1 or current_signatures != baseline_signatures:
        return {
            "status": "invalid_pairing",
            "passed": False,
            "reason": "current and baseline trials do not share one artifact signature",
            "paired_trial_indices": paired_indices,
        }

    quality_deltas: List[float] = []
    current_walls: List[float] = []
    baseline_walls: List[float] = []
    for index in paired_indices:
        current = current_by_index[index]
        baseline = baseline_by_index[index]
        current_eval = current.get("evaluation")
        baseline_eval = baseline.get("evaluation")
        current_quality = (
            current_eval.get("actionable_f1")
            if isinstance(current_eval, dict)
            else None
        )
        baseline_quality = (
            baseline_eval.get("actionable_f1")
            if isinstance(baseline_eval, dict)
            else None
        )
        if current_quality is None and isinstance(current_eval, dict):
            current_quality = current_eval.get("f1")
        if baseline_quality is None and isinstance(baseline_eval, dict):
            baseline_quality = baseline_eval.get("f1")
        current_cost = current.get("cost")
        baseline_cost = baseline.get("cost")
        current_wall = current_cost.get("wall_time_seconds") if isinstance(current_cost, dict) else None
        baseline_wall = baseline_cost.get("wall_time_seconds") if isinstance(baseline_cost, dict) else None
        if not all(
            isinstance(value, (int, float)) and not isinstance(value, bool)
            for value in (current_quality, baseline_quality, current_wall, baseline_wall)
        ):
            return {
                "status": "insufficient_data",
                "passed": False,
                "reason": "paired trials are missing actionable F1 or wall time",
                "paired_trial_indices": paired_indices,
            }
        quality_deltas.append(float(current_quality) - float(baseline_quality))
        current_walls.append(float(current_wall))
        baseline_walls.append(float(baseline_wall))

    quality_delta = sum(quality_deltas) / len(quality_deltas)
    quality_ci = _bootstrap_ci(
        quality_deltas,
        confidence_level=confidence_level,
        samples=bootstrap_samples,
        statistic="mean",
    )
    current_wall_stats = _series_stats(
        current_walls,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    baseline_wall_stats = _series_stats(
        baseline_walls,
        bootstrap_samples=bootstrap_samples,
        confidence_level=confidence_level,
        ci_statistic="median",
    )
    median_reduction = (
        1.0 - float(current_wall_stats["median"]) / float(baseline_wall_stats["median"])
        if float(baseline_wall_stats["median"]) > 0
        else 0.0
    )
    p95_reduction = (
        1.0 - float(current_wall_stats["p95"]) / float(baseline_wall_stats["p95"])
        if float(baseline_wall_stats["p95"]) > 0
        else 0.0
    )
    quality_gain_path = (
        quality_delta >= 0.05
        and quality_ci is not None
        and float(quality_ci["lower"]) > 0.0
    )
    performance_path = (
        quality_delta >= -0.02
        and max(median_reduction, p95_reduction) >= 0.20
    )
    passed = quality_gain_path or performance_path
    return {
        "status": "passed" if passed else "failed",
        "passed": passed,
        "paired_trial_indices": paired_indices,
        "paired_trial_count": len(paired_indices),
        "quality_metric": "actionable_f1",
        "quality_delta": round(quality_delta, 4),
        "quality_delta_percentage_points": round(quality_delta * 100.0, 4),
        "quality_delta_bootstrap_ci": quality_ci,
        "median_wall_time_reduction": round(median_reduction, 4),
        "p95_wall_time_reduction": round(p95_reduction, 4),
        "quality_gain_path": {
            "required_delta_percentage_points": 5.0,
            "requires_ci_lower_above_zero": True,
            "passed": quality_gain_path,
        },
        "performance_path": {
            "maximum_quality_degradation_percentage_points": 2.0,
            "required_wall_time_reduction": 0.20,
            "passed": performance_path,
        },
    }


def load_summaries(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    summaries: List[Dict[str, Any]] = []
    for path in paths:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(data, dict):
            summaries.append(data)
    return summaries


def _collect_metadata(value: Any) -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    if isinstance(value, dict):
        metadata = value.get("metadata")
        if isinstance(metadata, dict):
            found.append(metadata)
        for item in value.values():
            found.extend(_collect_metadata(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(_collect_metadata(item))
    return found


def _sum_numeric(dicts: Iterable[Dict[str, Any]], keys: Sequence[str]) -> float:
    total = 0.0
    for data in dicts:
        for key in keys:
            value = data.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                total += float(value)
    return round(total, 4)


def _max_numeric(
    dicts: Iterable[Dict[str, Any]],
    keys: Sequence[str],
) -> Optional[float]:
    values: List[float] = []
    for data in dicts:
        for key in keys:
            value = data.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                values.append(float(value))
    return round(max(values), 4) if values else None


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _text_has_category(text: str, truth: Dict[str, Any]) -> bool:
    return bool(_category_match_reason(text, truth))


def _category_match_reason(text: str, truth: Dict[str, Any]) -> str:
    lowered = text.replace("_", " ").replace("-", " ").lower()
    category = str(truth.get("category") or "").lower()
    cwe = str(truth.get("cwe") or "").lower()
    aliases = _category_aliases(category, cwe)
    if cwe and cwe in lowered:
        return f"cwe:{cwe}"
    for alias in aliases:
        if alias and alias in lowered:
            return f"category_alias:{alias}"
    keyword_hits = _truth_keyword_hits(lowered, truth)
    if keyword_hits >= 2:
        return f"keyword_hits:{keyword_hits}"
    return ""


def _category_aliases(category: str, cwe: str) -> List[str]:
    category_key = category.replace("-", "_").lower()
    builtins = {
        "memory_safety": ["memory safety", "bounds", "buffer", "overflow", "leak"],
        "integer_overflow": ["integer overflow", "overflow", "wrap", "signed unsigned", "bounds", "cwe-190"],
        "heap_overflow": ["heap overflow", "heap buffer overflow", "buffer overflow", "bounds", "cwe-122"],
        "buffer_overflow": ["buffer overflow", "heap overflow", "out of bounds", "bounds", "cwe-787", "cwe-122"],
        "out_of_bounds_write": [
            "out of bounds write",
            "out-of-bounds write",
            "out of bounds",
            "bounds",
            "object offset",
            "pointer offset",
            "out of range pointer offset",
            "cwe-787",
            "cwe-823",
        ],
        "out_of_range_pointer_offset": [
            "out of range pointer offset",
            "out-of-range pointer offset",
            "pointer offset",
            "object offset",
            "offset-derived pointer",
            "out of bounds write",
            "out-of-bounds write",
            "out of bounds",
            "bounds",
            "cwe-823",
            "cwe-787",
        ],
        "buffer_overread": ["buffer overread", "buffer over read", "out-of-bounds read", "bounds", "cwe-126"],
        "buffer_over_read": ["buffer overread", "buffer over read", "out-of-bounds read", "bounds", "cwe-126"],
        "buffer_underread": ["buffer underread", "buffer under read", "buffer underflow", "cwe-127"],
        "buffer_underwrite": ["buffer underwrite", "buffer under write", "buffer underflow", "cwe-124"],
        "buffer_underflow": ["buffer underflow", "buffer underread", "buffer underwrite", "cwe-127", "cwe-124"],
        "bounds": [
            "bounds",
            "out of bounds",
            "buffer overflow",
            "heap overflow",
            "buffer overread",
            "buffer over read",
            "buffer underread",
            "buffer underwrite",
            "buffer underflow",
            "overread",
            "over read",
            "protocol validation",
            "magic validation",
            "wide count",
            "unchecked count",
            "count before magic",
            "cwe-125",
            "cwe-787",
            "cwe-20",
        ],
        "format_string": ["format string", "cwe-134"],
        "deadlock": ["deadlock", "lock order", "recursive lock", "callback lock", "timer callback", "lock-order cycle", "cwe-833"],
        "command_injection": ["command injection", "shell injection", "system(", "cwe-78"],
        "memory_leak": ["memory leak", "resource leak", "leak", "child list", "owned member", "children", "proc head", "cwe-401", "cwe-772"],
        "resource_lifecycle": [
            "resource lifecycle",
            "memory leak",
            "resource leak",
            "child list",
            "owned member",
            "children",
            "proc head",
            "cwe-772",
        ],
        "double_free": ["double free", "cwe-415"],
        "use_after_free": ["use after free", "use-after-free", "uaf", "dangling", "cwe-416"],
        "invalid_free": ["invalid free", "non-heap", "cwe-590"],
        "null_pointer_dereference": ["null pointer", "null dereference", "cwe-476"],
        "stack_escape": ["stack escape", "stack address", "cwe-562"],
        "stack_overflow": ["stack overflow", "stack buffer", "vla", "cwe-121"],
        "signed_unsigned": ["signed", "unsigned", "negative", "integer overflow", "bounds", "cwe-195", "cwe-190"],
        "off_by_one": ["off by one", "off-by-one", "one byte", "cwe-193"],
        "uninitialized_read": ["uninitialized", "padding", "cwe-457"],
        "race": [
            "race",
            "data race",
            "toctou",
            "unsynchronized",
            "unsynchronized shared state",
            "shared state race",
            "without synchronization",
            "missing lock",
            "concurrent",
            "use after free",
            "use-after-free",
            "uaf",
            "dangling",
            "unmap",
            "munmap",
            "cwe-362",
            "cwe-367",
        ],
        "data_race": ["data race", "race", "cwe-362"],
        "unsynchronized_shared_state": [
            "unsynchronized shared state",
            "shared state race",
            "data race",
            "race",
            "without synchronization",
            "global state",
            "watermark",
            "map/unmap",
            "mmap",
            "munmap",
            "cwe-362",
        ],
        "shared_state_race": [
            "shared state race",
            "unsynchronized shared state",
            "data race",
            "race",
            "global state",
            "cwe-362",
        ],
        "object_publication": [
            "object publication",
            "published before initialization",
            "half initialized",
            "published",
            "cwe-362",
        ],
        "refcount_race": ["refcount", "reference count", "ref count", "race", "cwe-362"],
        "held_lock_callback": ["held lock callback", "callback while lock", "under lock", "cwe-667"],
        "missing_unlock": ["missing unlock", "return while lock", "forgot unlock", "cwe-667"],
        "unlock_without_lock": [
            "unlock without lock",
            "unlock without owning",
            "unlock without held lock",
            "lock protocol violation",
            "not held",
            "cwe-832",
        ],
        "lock_protocol_violation": [
            "lock protocol violation",
            "unlock without lock",
            "unlock without owning",
            "not held",
            "cwe-832",
        ],
        "double_checked_locking": ["double checked", "lazy initialization", "race", "cwe-362"],
        "lost_wakeup": ["lost wakeup", "condition variable", "pthread_cond_wait", "cwe-366"],
        "realloc_misuse": ["realloc misuse", "direct realloc", "old pointer", "cwe-401"],
        "alignment": ["alignment", "unaligned", "strict alias", "cwe-704"],
        "stale_fd": ["stale fd", "file descriptor", "closed fd", "cwe-672"],
        "fd_leak": ["fd leak", "file descriptor leak", "descriptor leak", "unclosed fd", "unclosed descriptor", "cwe-775"],
        "file_descriptor_leak": [
            "fd leak",
            "file descriptor leak",
            "descriptor leak",
            "unclosed fd",
            "unclosed descriptor",
            "cwe-775",
        ],
        "missing_fd_release": [
            "missing fd release",
            "fd leak",
            "file descriptor leak",
            "descriptor leak",
            "unclosed fd",
            "unclosed descriptor",
            "cwe-775",
        ],
        "state_inconsistency": [
            "state not restored",
            "state inconsistency",
            "rollback",
            "race",
            "resource lifecycle",
            "global state",
            "not restored",
            "unmap",
            "munmap",
            "map rules",
            "cwe-672",
            "cwe-362",
        ],
        "unchecked_return": ["unchecked return", "unchecked result", "return success", "cwe-252"],
        "busy_loop": ["busy loop", "infinite loop", "spin", "no delay", "resource exhaustion", "cwe-400"],
        "infinite_loop": ["infinite loop", "busy loop", "spin", "cwe-835", "cwe-400"],
        "log_amplification": ["log amplification", "log storm", "resource exhaustion", "cwe-400"],
        "key_truncation": ["key truncation", "truncated key", "partial comparison", "cwe-187"],
        "size_limit_mismatch": ["size limit", "fixed limit", "buffer limit", "spec", "cwe-131", "cwe-190"],
        "fd_type_mismatch": ["fd type", "reliable fd", "raw fd", "mismatched parameter", "cwe-628"],
        "permission": [
            "permission",
            "incorrect permission check",
            "mode validation",
            "mode",
            "chmod",
            "requested permission",
            "hard-coded mode",
            "hardcoded mode",
            "cwe-732",
            "cwe-276",
        ],
        "incorrect_permission_check": [
            "incorrect permission check",
            "permission",
            "mode validation",
            "requested permission",
            "cwe-732",
            "cwe-276",
        ],
        "mode_validation": [
            "mode validation",
            "permission",
            "incorrect permission check",
            "cwe-732",
            "cwe-276",
        ],
        "protocol_mixup": [
            "protocol mismatch",
            "protocol mixup",
            "auth level",
            "origin validation",
            "cwe-346",
        ],
        "partial_resource_leak": ["partial resource leak", "resource leak", "retry", "cwe-401"],
        "dynamic_array_race": ["dynamic array", "array expansion", "race", "double free", "cwe-362"],
        "version_filtering": ["version", "missing version", "low version", "filter", "cwe-20"],
        "missing_refcount": ["refcount", "reference count", "shared resource", "cleanup", "cwe-772"],
        "thread_cache_leak": [
            "thread cache leak",
            "cache leak",
            "cached blocks",
            "memory leak",
            "resource leak",
            "resource allocation without limits",
            "unbounded allocation",
            "tls",
            "thread cache",
            "cwe-772",
            "cwe-770",
        ],
        "sigpipe_unhandled": ["sigpipe", "signal", "closed peer", "not handled", "cwe-404"],
        "premature_destroy": [
            "premature destroy",
            "active tasks",
            "active users",
            "pool",
            "shared pool",
            "use after free",
            "use-after-free",
            "uaf",
            "resource lifecycle",
            "dangling",
            "cwe-416",
        ],
        "registration_race": ["registration race", "check then act", "ops registration", "race", "cwe-362"],
        "alloc_free_mismatch": ["allocator mismatch", "alloc free mismatch", "allocator pairing", "cwe-762"],
        "key_generation_race": ["ftok", "key generation", "key collision", "path state", "cwe-362"],
        "fd_encoding_mismatch": ["encoded fd", "fd encoding", "check value", "raw fd", "cwe-587"],
        "type_confusion": ["type confusion", "wrong type", "invalid mutex", "sharedresources", "cwe-843"],
        "semantic_mismatch": ["semantic mismatch", "callback parameter", "counter domain", "busy work", "cwe-628"],
        "byte_order_logic": ["byte order", "endian", "ctz", "trailing zero", "cwe-682"],
        "reader_state_race": ["reader state", "reader pid", "multiple readers", "rwlock", "race", "cwe-362"],
        "uninitialized_output": ["uninitialized output", "partially initialized", "output parameter", "cwe-457"],
        "file_type_validation": [
            "file type",
            "character device",
            "regular file",
            "mapping size",
            "incorrect validation order",
            "validation order",
            "validate file type",
            "file type validation",
            "cwe-20",
        ],
        "ownership_contract_violation": [
            "ownership contract",
            "ownership transfer",
            "memory leak",
            "resource lifecycle",
            "resource leak",
            "orphan",
            "owner",
            "cwe-772",
        ],
        "resource_allocation_without_limits": [
            "resource allocation without limits",
            "unbounded allocation",
            "without limit",
            "missing quota",
            "no quota",
            "resource exhaustion",
            "memory leak",
            "thread cache leak",
            "cwe-770",
            "cwe-772",
        ],
        "log_level_misuse": ["log level", "logged at error", "alert noise", "cwe-778"],
        "logic_error": ["logic error", "wrong group", "wrong index", "cwe-682"],
        "global_mode_race": ["global mode", "qrcu", "crcu", "race", "cwe-362"],
        "slot_race": ["slot race", "cas result", "process slot", "race", "cwe-362"],
        "shared_memory_race": ["shared memory race", "lookup before lock", "concurrent create", "memzone", "cwe-362"],
        "state_machine": ["state machine", "missing transition", "lifecycle state", "cwe-672"],
        "signal_deadlock": ["signal deadlock", "signal handler", "semaphore", "deadlock", "cwe-833"],
        "signal_race": ["signal race", "signal handler", "async signal", "callstack", "cwe-479"],
        "callback_self_destroy_race": ["callback self destroy", "self destruction", "callback can free", "use after free", "cwe-416"],
    }
    aliases = builtins.get(category_key, [category_key.replace("_", " ")])
    if cwe:
        aliases = aliases + [cwe]
    return aliases


def _truth_keyword_hits(text: str, truth: Dict[str, Any]) -> int:
    keywords = truth.get("keywords")
    if not isinstance(keywords, list):
        return 0
    hits = 0
    for keyword in keywords:
        needle = str(keyword or "").replace("_", " ").replace("-", " ").lower().strip()
        if needle and needle in text:
            hits += 1
    return hits


def _issue_function(issue: Dict[str, Any]) -> str:
    return str(issue.get("function") or issue.get("func_name") or "").lower()


def _function_match_reason(issue: Dict[str, Any], text: str, truth: Dict[str, Any]) -> str:
    expected = _truth_function_anchors(truth)
    if not expected:
        return "no_expected_function"

    anchors = _issue_function_anchors(issue)
    for kind, func in expected:
        if func in anchors:
            return f"{kind}:structured_anchor"
    for kind, func in expected:
        if func in text:
            return f"{kind}:text_anchor"
    return ""


def _truth_function_anchors(truth: Dict[str, Any]) -> List[tuple[str, str]]:
    expected: List[tuple[str, str]] = []

    def add(kind: str, value: Any) -> None:
        func = str(value or "").strip().lower()
        if func and (kind, func) not in expected:
            expected.append((kind, func))

    add("primary", truth.get("function"))
    add("secondary", truth.get("secondary_function"))

    add("sibling", truth.get("sibling_function"))

    for field in ("related_functions", "additional_functions", "sibling_functions"):
        values = truth.get(field)
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, dict):
                add(field, value.get("function") or value.get("name"))
            else:
                add(field, value)

    locations = truth.get("additional_locations")
    if isinstance(locations, list):
        for item in locations:
            if isinstance(item, dict):
                add("additional", item.get("function"))

    return expected


def _issue_function_anchors(issue: Dict[str, Any]) -> Set[str]:
    anchors: Set[str] = set()

    def add(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, dict):
            for item in value.values():
                add(item)
            return
        if isinstance(value, list):
            for item in value:
                add(item)
            return
        text = str(value).strip().lower()
        if text:
            anchors.add(text)

    for key in (
        "function",
        "func_name",
        "entry_function",
        "sink_function",
        "target_function",
        "analyzed_from",
    ):
        add(issue.get(key))
    for key in ("call_path", "call_paths"):
        add(issue.get(key))
    evidence_pack = issue.get("evidence_pack")
    if isinstance(evidence_pack, dict):
        for key in (
            "entry_function",
            "sink_function",
            "target_function",
            "call_path",
            "call_paths",
            "duplicate_sources",
        ):
            add(evidence_pack.get(key))
        path = evidence_pack.get("path")
        if isinstance(path, dict):
            for key in (
                "entry_function",
                "sink_function",
                "target_function",
                "call_path",
                "call_paths",
            ):
                add(path.get(key))
    return anchors


def _location_file(issue: Dict[str, Any]) -> str:
    location = str(issue.get("location") or issue.get("file") or "")
    if ":" in location:
        return location.split(":", 1)[0]
    return location


def _file_match_reason(text: str, truth: Dict[str, Any]) -> str:
    expected_file = str(truth.get("file") or "").lower().replace("\\", "/")
    if not expected_file:
        return "no_expected_file"
    basename = Path(expected_file).name.lower()
    if expected_file in text:
        return "path"
    if basename and basename in text:
        return "basename"
    secondary_file = str(truth.get("secondary_file") or "").lower().replace("\\", "/")
    if secondary_file and secondary_file in text:
        return "secondary_path"
    if secondary_file:
        secondary_basename = Path(secondary_file).name.lower()
        if secondary_basename and secondary_basename in text:
            return "secondary_basename"
    locations = truth.get("additional_locations")
    if isinstance(locations, list):
        for idx, item in enumerate(locations):
            if not isinstance(item, dict):
                continue
            file_value = str(item.get("file") or "").lower().replace("\\", "/")
            if not file_value:
                continue
            if file_value in text:
                return f"additional_path:{idx}"
            additional_basename = Path(file_value).name.lower()
            if additional_basename and additional_basename in text:
                return f"additional_basename:{idx}"
    return ""


def _line_match_reason(
    issue: Dict[str, Any],
    truth: Dict[str, Any],
    line_tolerance: int,
) -> str:
    expected_ranges = _truth_line_ranges(truth)
    if not expected_ranges:
        return "no_expected_line"
    actual_ranges = _issue_line_ranges(issue)
    if not actual_ranges:
        return "no_issue_line"
    for actual_start, actual_end in actual_ranges:
        for label, start, end in expected_ranges:
            if start - line_tolerance <= actual_end and actual_start <= end + line_tolerance:
                return f"{label}:within_tolerance"
    return ""


def _truth_line_ranges(truth: Dict[str, Any]) -> List[tuple[str, int, int]]:
    ranges: List[tuple[str, int, int]] = []

    def add(label: str, start_key: str, end_key: str) -> None:
        start_value = truth.get(start_key)
        if start_value in (None, ""):
            return
        try:
            start = int(start_value)
        except (TypeError, ValueError):
            return
        if start <= 1:
            return
        try:
            end = int(truth.get(end_key) or start)
        except (TypeError, ValueError):
            end = start
        if end < start:
            end = start
        ranges.append((label, start, end))

    add("primary_line", "line", "end_line")
    add("current_primary_line", "_current_line", "_current_end_line")
    add("secondary_line", "secondary_line", "secondary_end_line")
    add("current_secondary_line", "_current_secondary_line", "_current_secondary_end_line")
    locations = truth.get("additional_locations")
    if isinstance(locations, list):
        for idx, item in enumerate(locations):
            if not isinstance(item, dict):
                continue
            try:
                start = int(item.get("line") or 0)
            except (TypeError, ValueError):
                continue
            if start <= 1:
                continue
            try:
                end = int(item.get("end_line") or start)
            except (TypeError, ValueError):
                end = start
            if end < start:
                end = start
            ranges.append((f"additional_line:{idx}", start, end))
    return ranges


def _location_line(issue: Dict[str, Any]) -> Optional[int]:
    line_range = _location_line_range(issue)
    return line_range[0] if line_range else None


def _location_line_range(issue: Dict[str, Any]) -> Optional[tuple[int, int]]:
    ranges = _issue_line_ranges(issue)
    return ranges[0] if ranges else None


def _issue_line_ranges(issue: Dict[str, Any]) -> List[tuple[int, int]]:
    ranges: List[tuple[int, int]] = []
    seen: Set[tuple[int, int]] = set()

    def add_range(start_value: Any, end_value: Any = None) -> None:
        try:
            start = int(start_value)
        except (TypeError, ValueError):
            return
        if start <= 0:
            return
        try:
            end = int(end_value) if end_value not in (None, "") else start
        except (TypeError, ValueError):
            end = start
        span = (start, max(start, end))
        if span not in seen:
            seen.add(span)
            ranges.append(span)

    def add_location(value: Any) -> None:
        if not isinstance(value, str):
            return
        for token in value.split(":")[1:]:
            match = re.match(r"\s*(\d+)(?:\s*-\s*(\d+))?", token)
            if match:
                add_range(match.group(1), match.group(2) or match.group(1))

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if "line" in value or "start_line" in value:
                add_range(value.get("line") or value.get("start_line"), value.get("end_line"))
            for key in (
                "location",
                "file",
                "source_location",
                "sink_location",
                "primary_location",
                "secondary_location",
            ):
                add_location(value.get(key))
            for nested in value.values():
                walk(nested)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(issue)
    return ranges

def _short_text(issue: Dict[str, Any]) -> str:
    text = str(issue.get("description") or issue.get("message") or issue.get("title") or "")
    return " ".join(text.lower().split())[:120]


def _percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = min(1.0, max(0.0, quantile)) * (len(ordered) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _bootstrap_ci(
    values: Sequence[float],
    *,
    confidence_level: float = 0.95,
    samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    statistic: str = "mean",
) -> Optional[Dict[str, Any]]:
    values = [float(value) for value in values]
    samples = max(0, int(samples))
    if not values or samples <= 0:
        return None
    if statistic not in {"mean", "median"}:
        raise ValueError(f"Unsupported bootstrap statistic: {statistic}")
    confidence_level = min(0.999, max(0.001, float(confidence_level)))
    rng = random.Random(0)
    estimates: List[float] = []
    size = len(values)
    for _ in range(samples):
        resample = [values[rng.randrange(size)] for _ in range(size)]
        if statistic == "median":
            estimate = _percentile(resample, 0.5)
        else:
            estimate = sum(resample) / size
        estimates.append(estimate)
    alpha = (1.0 - confidence_level) / 2.0
    return {
        "confidence_level": round(confidence_level, 4),
        "method": "percentile_bootstrap",
        "statistic": statistic,
        "samples": samples,
        "lower": round(_percentile(estimates, alpha), 4),
        "upper": round(_percentile(estimates, 1.0 - alpha), 4),
    }


def _series_stats(
    values: Sequence[float],
    *,
    bootstrap_samples: int = DEFAULT_BOOTSTRAP_SAMPLES,
    confidence_level: float = 0.95,
    ci_statistic: str = "mean",
) -> Dict[str, Any]:
    if not values:
        return {
            "mean": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "min": 0.0,
            "max": 0.0,
            "stdev": 0.0,
            "values": [],
            "bootstrap_ci": None,
        }
    numeric_values = [float(value) for value in values]
    mean = sum(numeric_values) / len(numeric_values)
    variance = sum((value - mean) ** 2 for value in numeric_values) / len(numeric_values)
    return {
        "mean": round(mean, 4),
        "median": round(_percentile(numeric_values, 0.5), 4),
        "p95": round(_percentile(numeric_values, 0.95), 4),
        "min": round(min(numeric_values), 4),
        "max": round(max(numeric_values), 4),
        "stdev": round(math.sqrt(variance), 4),
        "values": [round(value, 4) for value in numeric_values],
        "bootstrap_ci": _bootstrap_ci(
            numeric_values,
            confidence_level=confidence_level,
            samples=bootstrap_samples,
            statistic=ci_statistic,
        ),
    }


def _mean_pairwise_jaccard(sets: Sequence[Set[str]]) -> float:
    if len(sets) < 2:
        return 1.0
    scores: List[float] = []
    for left_idx, left in enumerate(sets):
        for right in sets[left_idx + 1 :]:
            scores.append(_jaccard(left, right))
    return round(sum(scores) / len(scores), 4) if scores else 1.0


def _jaccard(left: Set[str], right: Set[str]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def _git_commit_sha(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=5,
        )
    except Exception:
        return ""
    if completed.returncode != 0:
        return ""
    return completed.stdout.strip()


def _redact_url(value: str) -> str:
    if not value:
        return ""
    if "@" not in value:
        return value
    scheme, rest = value.split("://", 1) if "://" in value else ("", value)
    host = rest.rsplit("@", 1)[-1]
    return f"{scheme}://[redacted]@{host}" if scheme else f"[redacted]@{host}"
