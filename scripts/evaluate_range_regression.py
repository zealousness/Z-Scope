"""Evaluate Z-SCOPE range benchmark reports or local candidate coverage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from zscope.config.config import AnalysisConfig, IndexingConfig
from zscope.benchmarking.protocol import (
    issue_match_detail,
    report_issues as benchmark_report_issues,
    score_report,
    score_report_views,
)
from zscope.common.issue_identity import deduplicate_issues
from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.graph import GraphCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.orchestration.budget import RiskBudgetPlanner
from zscope.retrieval.code_index import CodeIndex
from zscope.semantics.models import LocalPatternSemantics


class _EmptyUserConfig:
    def list_external_functions(self) -> List[Dict[str, Any]]:
        return []

    def list_paired_functions(self) -> List[Dict[str, Any]]:
        return []

    def list_dispatchers(self) -> List[Dict[str, Any]]:
        return []

    def list_module_lifecycle(self) -> List[Dict[str, Any]]:
        return []

    def get_pointer_targets(self) -> List[Dict[str, Any]]:
        return []

    def list_function_intents(self) -> List[Dict[str, Any]]:
        return []


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _empty_semantic_overlay() -> Dict[str, Any]:
    return {
        "resource_models": [],
        "lock_models": [],
        "macro_models": [],
        "dispatcher_models": [],
        "lifecycle_models": [],
        "pointer_target_models": [],
        "function_intent_models": [],
        "summary": {},
    }


def _candidate_report(project_root: Path, entries_path: Path, *, backend: str = "regex") -> Dict[str, Any]:
    entries = _load_json(entries_path).get("functions", [])
    compile_commands = project_root / "build" / "compile_commands.json"
    index = CodeIndex(
        project_root,
        compile_commands_path=compile_commands if compile_commands.exists() else None,
        source_root=project_root,
        indexing_config=IndexingConfig(backend="regex"),
    )
    semantics = LocalPatternSemantics()
    overlay = _empty_semantic_overlay()
    analyzer = object.__new__(Analyzer)
    analyzer.code_index = index
    analyzer.user_config = _EmptyUserConfig()
    analyzer._local_pattern_semantics = semantics
    analyzer._semantic_overlay = overlay
    analyzer._clang_tooling_provider = None
    analyzer._clang_tooling_evidence_cache = {}
    analyzer.budget_planner = RiskBudgetPlanner(AnalysisConfig())
    analyzer._candidate_backend_profile = lambda: backend  # type: ignore[method-assign]
    graph_generator = GraphCandidateGenerator(index, semantics, semantic_overlay=overlay)
    issues: List[Dict[str, Any]] = []
    graph_issues: List[Dict[str, Any]] = []
    missing: List[str] = []
    entry_names: List[str] = []
    for entry in entries:
        func = str(entry.get("function_name") or "")
        if not func:
            continue
        entry_names.append(func)
        impl = index.get_function_impl(func)
        if not impl:
            missing.append(func)
            continue
        issues.extend(
            analyzer._detect_local_rule_candidates(
                {"entry_func": func, "impl_result": impl}
            )
        )
    graph_issues.extend(graph_generator.generate_for_functions(entry_names))
    issues.extend(graph_issues)
    issues = deduplicate_issues(issues)
    issue_sources: Dict[str, int] = {}
    for issue in issues:
        source = str(issue.get("candidate_source") or issue.get("finding_kind") or "unknown")
        issue_sources[source] = issue_sources.get(source, 0) + 1
    return {
        "entry_function": f"range_{backend}_candidates",
        "overall_verdict": "issues_found" if issues else "no_issue_found",
        "issues": issues,
        "metadata": {
            "mode": f"{backend}_candidate_coverage",
            "candidate_backend": backend,
            "missing_entry_impls": missing,
            "local_issue_count": len(issues) - len(graph_issues),
            "regex_issue_count": len(issues) - len(graph_issues) if backend == "regex" else 0,
            "graph_issue_count": len(graph_issues),
            "issue_sources": issue_sources,
        },
    }


def _legacy_regex_candidate_report(project_root: Path, entries_path: Path) -> Dict[str, Any]:
    entries = _load_json(entries_path).get("functions", [])
    compile_commands = project_root / "build" / "compile_commands.json"
    index = CodeIndex(
        project_root,
        compile_commands_path=compile_commands if compile_commands.exists() else None,
        source_root=project_root,
        indexing_config=IndexingConfig(backend="regex"),
    )
    generator = RegexCandidateGenerator()
    graph_generator = GraphCandidateGenerator(index)
    issues: List[Dict[str, Any]] = []
    graph_issues: List[Dict[str, Any]] = []
    missing: List[str] = []
    entry_names: List[str] = []
    for entry in entries:
        func = str(entry.get("function_name") or "")
        if not func:
            continue
        entry_names.append(func)
        impl = index.get_function_impl(func)
        if not impl:
            missing.append(func)
            continue
        issues.extend(generator.generate_issues(func, impl["code"], impl["file"]))
    graph_issues.extend(graph_generator.generate_for_functions(entry_names))
    issues.extend(graph_issues)
    issues = deduplicate_issues(issues)
    return {
        "entry_function": "range_regex_candidates",
        "overall_verdict": "issues_found" if issues else "no_issue_found",
        "issues": issues,
        "metadata": {
            "mode": "regex_candidate_coverage",
            "candidate_backend": "regex",
            "missing_entry_impls": missing,
            "local_issue_count": len(issues) - len(graph_issues),
            "regex_issue_count": len(issues) - len(graph_issues),
            "graph_issue_count": len(graph_issues),
        },
    }


def _candidate_miss_analysis(
    report: Dict[str, Any],
    truth: Dict[str, Any],
    *,
    tolerance: int,
    missed_ids: List[str],
) -> List[Dict[str, Any]]:
    if not missed_ids:
        return []
    issues = benchmark_report_issues(report)
    issues = [issue for issue in issues if isinstance(issue, dict)]
    vulns = {
        str(vuln.get("id") or ""): vuln
        for vuln in truth.get("vulnerabilities", [])
        if isinstance(vuln, dict)
    }
    rows: List[Dict[str, Any]] = []
    for truth_id in missed_ids:
        vuln = vulns.get(str(truth_id))
        if not vuln:
            continue
        probes = []
        for issue in issues:
            detail = issue_match_detail(issue, vuln, tolerance)
            text = json.dumps(issue, ensure_ascii=False).lower().replace("_", " ").replace("-", " ")
            truth_function = str(vuln.get("function") or "").lower()
            secondary_function = str(vuln.get("secondary_function") or "").lower()
            category = str(vuln.get("category") or "").lower().replace("_", " ").replace("-", " ")
            keywords = [str(k or "").lower().replace("_", " ").replace("-", " ") for k in vuln.get("keywords", [])]
            same_function = bool(truth_function and truth_function in text) or bool(
                secondary_function and secondary_function in text
            )
            category_match = bool(category and category in text)
            keyword_hits = sum(1 for keyword in keywords if keyword and keyword in text)
            if detail is None and not (same_function or category_match or keyword_hits):
                continue
            probes.append(
                {
                    "candidate_id": issue.get("candidate_id") or issue.get("id"),
                    "candidate_source": issue.get("candidate_source") or issue.get("finding_kind"),
                    "function": issue.get("function"),
                    "location": issue.get("location"),
                    "defect_class": issue.get("defect_class") or issue.get("category"),
                    "same_function": same_function,
                    "category_match": category_match,
                    "keyword_hits": keyword_hits,
                    "protocol_match": detail,
                }
            )
        same_function_count = sum(1 for item in probes if item["same_function"])
        category_count = sum(1 for item in probes if item["category_match"])
        keyword_count = sum(1 for item in probes if item["keyword_hits"])
        if not probes:
            reason = "no_related_candidate"
        elif same_function_count == 0:
            reason = "no_candidate_in_truth_function"
        elif category_count == 0:
            reason = "candidate_category_drift"
        elif keyword_count == 0:
            reason = "candidate_missing_truth_keywords"
        else:
            reason = "candidate_related_but_protocol_did_not_match"
        source_counts: Dict[str, int] = {}
        for item in probes:
            source = str(item.get("candidate_source") or "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1
        rows.append(
            {
                "truth_id": truth_id,
                "truth_function": vuln.get("function"),
                "truth_secondary_function": vuln.get("secondary_function"),
                "truth_file": vuln.get("_current_file") or vuln.get("file"),
                "truth_line": vuln.get("_current_line") or vuln.get("line"),
                "truth_category": vuln.get("category"),
                "reason": reason,
                "related_candidate_count": len(probes),
                "same_function_candidate_count": same_function_count,
                "category_match_candidate_count": category_count,
                "keyword_match_candidate_count": keyword_count,
                "candidate_sources": source_counts,
                "top_candidates": probes[:5],
            }
        )
    return rows


def evaluate_range_regression(
    *,
    project_root: Path = Path("test/range"),
    benchmark_dir: Optional[Path] = None,
    truth_path: Optional[Path] = None,
    entries_path: Optional[Path] = None,
    report_path: Optional[Path] = None,
    regex_candidates: bool = False,
    candidate_backend: Optional[str] = None,
    line_tolerance: int = 5,
    min_precision: Optional[float] = None,
    min_recall: Optional[float] = None,
    min_f1: Optional[float] = None,
) -> Dict[str, Any]:
    benchmark_dir = benchmark_dir or project_root / "benchmark"
    truth_path = truth_path or benchmark_dir / "ground_truth.json"
    entries_path = entries_path or benchmark_dir / "entries.json"

    if regex_candidates:
        report = _legacy_regex_candidate_report(project_root, entries_path)
        candidate_backend = "regex"
    elif candidate_backend:
        report = _candidate_report(project_root, entries_path, backend=candidate_backend)
    elif report_path:
        report = _load_json(report_path)
    else:
        raise ValueError("Pass report_path, regex_candidates=True, or candidate_backend")

    truth = _load_json(truth_path)
    result = score_report(report, truth, line_tolerance=line_tolerance)
    result["report_views"] = score_report_views(report, truth, line_tolerance=line_tolerance)
    if candidate_backend:
        result["candidate_coverage_mode"] = True
        result["candidate_backend"] = candidate_backend
        result["missing_entry_impls"] = report.get("metadata", {}).get("missing_entry_impls", [])
        result["local_issue_count"] = report.get("metadata", {}).get("local_issue_count", 0)
        result["regex_issue_count"] = report.get("metadata", {}).get("regex_issue_count", 0)
        result["graph_issue_count"] = report.get("metadata", {}).get("graph_issue_count", 0)
        result["issue_sources"] = report.get("metadata", {}).get("issue_sources", {})
        result["miss_analysis"] = _candidate_miss_analysis(
            report,
            truth,
            tolerance=line_tolerance,
            missed_ids=[str(item) for item in result.get("missed", [])],
        )
        miss_reason_summary: Dict[str, int] = {}
        for row in result["miss_analysis"]:
            reason = str(row.get("reason") or "unknown")
            miss_reason_summary[reason] = miss_reason_summary.get(reason, 0) + 1
        result["miss_reason_summary"] = miss_reason_summary
    thresholds = {
        "precision": min_precision,
        "recall": min_recall,
        "f1": min_f1,
    }
    active_thresholds = {k: v for k, v in thresholds.items() if v is not None}
    if active_thresholds:
        failures = {
            metric: {"actual": float(result.get(metric, 0.0)), "required": float(required)}
            for metric, required in active_thresholds.items()
            if float(result.get(metric, 0.0)) < float(required)
        }
        result["thresholds"] = active_thresholds
        result["threshold_status"] = "failed" if failures else "passed"
        result["threshold_failures"] = failures
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path("test/range"))
    parser.add_argument("--benchmark-dir", type=Path, default=None)
    parser.add_argument("--truth", type=Path, default=None)
    parser.add_argument("--entries", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--regex-candidates", action="store_true")
    parser.add_argument("--candidate-backend", choices=["regex", "clang", "unified"], default=None)
    parser.add_argument("--line-tolerance", type=int, default=5)
    parser.add_argument("--min-precision", type=float, default=None)
    parser.add_argument("--min-recall", type=float, default=None)
    parser.add_argument("--min-f1", type=float, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    result = evaluate_range_regression(
        project_root=args.project_root,
        benchmark_dir=args.benchmark_dir,
        truth_path=args.truth,
        entries_path=args.entries,
        report_path=args.report,
        regex_candidates=args.regex_candidates,
        candidate_backend=args.candidate_backend,
        line_tolerance=args.line_tolerance,
        min_precision=args.min_precision,
        min_recall=args.min_recall,
        min_f1=args.min_f1,
    )

    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)
    if result.get("threshold_status") == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()


