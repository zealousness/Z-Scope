"""Machine-readable benchmark protocol and metrics for Z-SCOPE."""

from __future__ import annotations

import json
import math
import os
import platform
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
    vulns = [item for item in truth.get("vulnerabilities", []) if isinstance(item, dict)]
    matched_truth: Dict[str, int] = {}
    matched_pairs: List[Dict[str, Any]] = []
    matched_issues: Set[int] = set()
    potential_pairs: List[Dict[str, Any]] = []
    for truth_index, vuln in enumerate(vulns):
        truth_id = str(vuln.get("id") or truth_index)
        for issue_index, issue in enumerate(issues):
            match_detail = issue_match_detail(issue, vuln, line_tolerance)
            if match_detail is not None:
                potential_pairs.append(
                    {
                        "truth_index": truth_index,
                        "truth_id": truth_id,
                        "issue_index": issue_index,
                        "issue": issue,
                        "match": match_detail,
                        "score": _issue_match_score(issue, vuln, match_detail),
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
    for pair in potential_pairs:
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
    recall = tp / len(vulns) if vulns else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
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
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": truth.get("benchmark", "unknown"),
        "suite": truth.get("suite", "unknown"),
        "view": view,
        "report_issue_count": len(issues),
        "ground_truth_count": len(vulns),
        "safe_entry_count": len(truth.get("safe_entries", [])),
        "true_positives": tp,
        "false_positives": fp,
        "false_positives_raw": raw_fp,
        "false_positives_effective": effective_fp,
        "duplicate_of_matched_count": len(duplicate_of_matched_indices),
        "false_negatives": fn,
        "precision": round(precision, 4),
        "false_positive_rate": round(fp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(recall, 4),
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
        },
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
) -> Optional[Dict[str, str]]:
    text = _flatten(issue).lower().replace("\\", "/")
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


def _issue_match_score(issue: Dict[str, Any], truth: Dict[str, Any], detail: Dict[str, str]) -> int:
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
    text = _flatten(issue).lower().replace("\\", "/")
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
    billable_tokens = cumulative_tokens or context_tokens
    verified = max(1, int(evaluation.get("true_positives") or 0))
    return {
        "context_tokens": context_tokens,
        "cumulative_total_tokens": cumulative_tokens,
        "billable_tokens": billable_tokens,
        "tool_calls": tool_calls,
        "wall_time_seconds": round(wall_time_seconds, 4),
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
    final_outcome_score = float(evaluation.get("f1") or 0.0)
    has_trajectory = bool(trajectory.get("conversation_files") or trajectory.get("workflow_progress"))
    evidence_score = 1.0 if has_trajectory or trajectory.get("worker_report_count", 0) else 0.5
    tool_behavior_score = 1.0
    if cost.get("tool_calls_per_verified_issue", 0.0) > 80:
        tool_behavior_score = 0.5
    return {
        "schema_version": SCHEMA_VERSION,
        "final_outcome": {
            "score": round(final_outcome_score, 4),
            "basis": "F1 against generated ground truth.",
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


def aggregate_trial_summaries(summaries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    summaries = [summary for summary in summaries if isinstance(summary, dict)]
    by_condition: Dict[str, List[Dict[str, Any]]] = {}
    for summary in summaries:
        by_condition.setdefault(str(summary.get("condition") or "unknown"), []).append(summary)

    conditions: Dict[str, Any] = {}
    for condition, items in by_condition.items():
        f1_values = [float(item.get("evaluation", {}).get("f1") or 0.0) for item in items]
        precision_values = [
            float(item.get("evaluation", {}).get("precision") or 0.0) for item in items
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
        conditions[condition] = {
            "trial_count": len(items),
            "precision": _series_stats(precision_values),
            "recall": _series_stats(recall_values),
            "f1": _series_stats(f1_values),
            "issue_jaccard": _mean_pairwise_jaccard(issue_sets),
            "true_positive_overlap": _mean_pairwise_jaccard(tp_sets),
            "false_positive_overlap": _mean_pairwise_jaccard(fp_sets),
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "trial_count": len(summaries),
        "conditions": conditions,
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
        "integer_overflow": ["integer overflow", "overflow", "wrap", "cwe-190"],
        "bounds": [
            "bounds",
            "out of bounds",
            "buffer overflow",
            "buffer overread",
            "overread",
            "over read",
            "cwe-125",
            "cwe-787",
        ],
        "format_string": ["format string", "cwe-134"],
        "deadlock": ["deadlock", "lock order", "recursive lock", "cwe-833"],
        "command_injection": ["command injection", "shell injection", "system(", "cwe-78"],
        "memory_leak": ["memory leak", "resource leak", "leak", "cwe-401"],
        "double_free": ["double free", "cwe-415"],
        "use_after_free": ["use after free", "use-after-free", "uaf", "dangling", "cwe-416"],
        "invalid_free": ["invalid free", "non-heap", "cwe-590"],
        "null_pointer_dereference": ["null pointer", "null dereference", "cwe-476"],
        "stack_escape": ["stack escape", "stack address", "cwe-562"],
        "stack_overflow": ["stack overflow", "stack buffer", "vla", "cwe-121"],
        "signed_unsigned": ["signed", "unsigned", "negative", "cwe-195"],
        "off_by_one": ["off by one", "off-by-one", "one byte", "cwe-193"],
        "uninitialized_read": ["uninitialized", "padding", "cwe-457"],
        "race": [
            "race",
            "data race",
            "toctou",
            "unsynchronized",
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
        "double_checked_locking": ["double checked", "lazy initialization", "race", "cwe-362"],
        "lost_wakeup": ["lost wakeup", "condition variable", "pthread_cond_wait", "cwe-366"],
        "realloc_misuse": ["realloc misuse", "direct realloc", "old pointer", "cwe-401"],
        "alignment": ["alignment", "unaligned", "strict alias", "cwe-704"],
        "stale_fd": ["stale fd", "file descriptor", "closed fd", "cwe-672"],
        "state_inconsistency": ["state not restored", "state inconsistency", "rollback", "cwe-672"],
        "unchecked_return": ["unchecked return", "unchecked result", "return success", "cwe-252"],
        "busy_loop": ["busy loop", "infinite loop", "spin", "no delay", "resource exhaustion", "cwe-400"],
        "infinite_loop": ["infinite loop", "busy loop", "spin", "cwe-835", "cwe-400"],
        "log_amplification": ["log amplification", "log storm", "resource exhaustion", "cwe-400"],
        "key_truncation": ["key truncation", "truncated key", "partial comparison", "cwe-187"],
        "size_limit_mismatch": ["size limit", "fixed limit", "buffer limit", "spec", "cwe-131", "cwe-190"],
        "fd_type_mismatch": ["fd type", "reliable fd", "raw fd", "mismatched parameter", "cwe-628"],
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
        "sigpipe_unhandled": ["sigpipe", "signal", "closed peer", "not handled", "cwe-404"],
        "premature_destroy": ["premature destroy", "active tasks", "pool", "use after free", "cwe-416"],
        "registration_race": ["registration race", "check then act", "ops registration", "race", "cwe-362"],
        "alloc_free_mismatch": ["allocator mismatch", "alloc free mismatch", "allocator pairing", "cwe-762"],
        "key_generation_race": ["ftok", "key generation", "key collision", "path state", "cwe-362"],
        "fd_encoding_mismatch": ["encoded fd", "fd encoding", "check value", "raw fd", "cwe-587"],
        "type_confusion": ["type confusion", "wrong type", "invalid mutex", "sharedresources", "cwe-843"],
        "semantic_mismatch": ["semantic mismatch", "callback parameter", "counter domain", "busy work", "cwe-628"],
        "byte_order_logic": ["byte order", "endian", "ctz", "trailing zero", "cwe-682"],
        "reader_state_race": ["reader state", "reader pid", "multiple readers", "rwlock", "race", "cwe-362"],
        "uninitialized_output": ["uninitialized output", "partially initialized", "output parameter", "cwe-457"],
        "file_type_validation": ["file type", "character device", "regular file", "mapping size", "cwe-20"],
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


def _series_stats(values: Sequence[float]) -> Dict[str, Any]:
    if not values:
        return {"mean": 0.0, "stdev": 0.0, "values": []}
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    return {
        "mean": round(mean, 4),
        "stdev": round(math.sqrt(variance), 4),
        "values": [round(value, 4) for value in values],
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
