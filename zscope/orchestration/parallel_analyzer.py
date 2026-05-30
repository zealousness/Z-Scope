"""
Parallel Analyzer for Z-SCOPE.
Supports concurrent analysis of multiple functions using thread pool.
"""

import concurrent.futures
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field

from ..config.config import ZScopeConfig
from ..config.function_entry import FunctionEntry
from ..config.user_config_store import UserConfigStore
from ..core.candidates.evidence import SemanticOverlayCompiler
from ..core.analysis.analyzer import Analyzer
from ..semantics.inference import LocalPatternSemanticBuilder
from ..semantics.models import LocalPatternSemantics
from ..snapshots.store import SnapshotStore
from ..retrieval.code_index import CodeIndex
from ..orchestration.candidates import CandidateLedger
from ..common.issue_identity import (
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
    deduplicate_issues,
    flatten_issue_text,
    issue_rank,
    normalize_issue_category,
    normalize_issue_key_part,
    parse_issue_location,
)
from ..reporting.views import build_report_views, report_view_summary

logger = logging.getLogger(__name__)


@dataclass
class ParallelAnalysisResult:
    """Result of parallel analysis across multiple functions."""
    function_name: str
    verdict: str
    issues: List[Dict[str, Any]] = field(default_factory=list)
    audit_observations: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0
    context_tokens: int = 0
    cumulative_prompt_tokens: int = 0
    cumulative_completion_tokens: int = 0
    cumulative_total_tokens: int = 0
    diff_focus: Optional[Dict[str, Any]] = None


class ParallelAnalyzer:
    """
    Parallel analyzer that can analyze multiple functions concurrently.
    
    Uses a thread pool to run up to max_workers LLM analysis sessions
    simultaneously, significantly reducing total analysis time.
    """
    
    def __init__(self, config: ZScopeConfig, code_index: Optional[CodeIndex] = None,
                 user_config: Optional[UserConfigStore] = None,
                 force_ignore_history: bool = False,
                 maintain_mode: bool = False):
        self.base_config = config
        self.max_workers = config.analysis.parallel_workers
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode

        if code_index:
            self.code_index = code_index
        else:
            self.code_index = CodeIndex(
                config.project.project_root,
                config.project.compile_commands_path,
                source_root=config.project.source_root,
                indexing_config=config.indexing,
                include_paths=config.project.include_paths,
                exclude_paths=config.project.exclude_paths,
            )
        self.snapshot_store = SnapshotStore(Path(config.analysis.snapshot_dir))
        db_dir = Path(config.analysis.user_config_db) if config.analysis.user_config_db else Path(config.analysis.snapshot_dir)
        self.user_config = user_config or UserConfigStore(db_dir)
        self._shared_local_pattern_semantics: Optional[LocalPatternSemantics] = None
        self._shared_semantic_overlay: Optional[Dict[str, Any]] = None
        self._shared_semantics_lock = threading.Lock()

    @staticmethod
    def _normalize_md_text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value)
        return text.replace("\\n", "\n")
        
    def analyze_function_entries(
        self,
        entries: List[FunctionEntry],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> Dict[str, ParallelAnalysisResult]:
        """
        Analyze multiple function entries with custom prompts.
        
        Args:
            entries: List of FunctionEntry objects with function names and custom prompts
            progress_callback: Optional callback(completed, total, func_name) for progress
            
        Returns:
            Dict mapping function name to analysis result
        """
        results = {}
        total = len(entries)
        completed = 0
        
        logger.info(f"Starting parallel analysis of {total} function entries with {self.max_workers} workers")
        if total and not self.maintain_mode:
            self._prepare_shared_semantics()
        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            # Submit all analysis tasks
            future_to_entry = {
                executor.submit(self._analyze_single_entry, entry): entry
                for entry in entries
            }
            
            # Collect results as they complete
            try:
                for future in concurrent.futures.as_completed(future_to_entry):
                    entry = future_to_entry[future]
                    completed += 1
                    
                    try:
                        result = future.result()
                        results[self._entry_result_key(entry)] = result
                        logger.info(f"[{completed}/{total}] {entry.function_name}: {result.verdict} ({len(result.issues)} issues, ctx ≈ {result.context_tokens:,} tokens)")
                    except concurrent.futures.CancelledError:
                        logger.warning(f"[{completed}/{total}] {entry.function_name}: Cancelled due to interrupt")
                    except Exception as e:
                        logger.error(f"[{completed}/{total}] {entry.function_name}: ERROR - {e}")
                        results[self._entry_result_key(entry)] = ParallelAnalysisResult(
                            function_name=entry.function_name,
                            verdict="error",
                            error=str(e),
                            diff_focus=entry.diff_focus,
                        )
                    
                    if progress_callback:
                        progress_callback(completed, total, entry.function_name)
            
            except KeyboardInterrupt:
                self._interrupted = True
                logger.warning("\n[!] Scan interrupted by user (Ctrl+C). Instantly killing threads and gathering partial results...")
                
                # Instantly destroy the thread pool without waiting for running threads to finish
                executor.shutdown(wait=False, cancel_futures=True)
                
                logger.info(f"Returning {len(results)} completed results out of {total} total.")
                return results

        finally:
            # Under normal successful execution, properly wait and clean up resources
            if executor and not getattr(self, '_interrupted', False):
                try:
                    executor.shutdown(wait=True)
                except Exception:
                    pass
                    
        return results

    @staticmethod
    def _entry_result_key(entry: FunctionEntry) -> str:
        focus = entry.diff_focus if isinstance(entry.diff_focus, dict) else {}
        component = str(focus.get("component") or "").strip()
        file_path = str(entry.file_path or focus.get("entry_file_path") or "").strip()
        if component or file_path:
            return f"{component or 'default'}:{entry.function_name}@{file_path or '<unknown>'}"
        return entry.function_name
    
    def analyze_functions(
        self, 
        function_names: List[str],
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> Dict[str, ParallelAnalysisResult]:
        """
        Analyze multiple functions in parallel.
        
        Args:
            function_names: List of function names to analyze
            progress_callback: Optional callback(completed, total, func_name) for progress
            
        Returns:
            Dict mapping function name to analysis result
        """
        # Convert to FunctionEntry objects
        entries = [FunctionEntry(function_name=name) for name in function_names]
        return self.analyze_function_entries(entries, progress_callback)

    
    def _analyze_single_entry(self, entry: FunctionEntry) -> ParallelAnalysisResult:
        """Analyze a single function entry with optional custom prompt."""
        start_time = time.time()
        
        try:
            # Create a config copy with this function as entry point and custom prompt
            config_copy = self._create_config_for_entry(entry)
            
            # Create analyzer and run with shared components
            analyzer = Analyzer(
                 config_copy,
                 code_index=self.code_index,
                 snapshot_store=self.snapshot_store,
                 user_config=self.user_config,
                 force_ignore_history=self.force_ignore_history,
                 maintain_mode=self.maintain_mode,
                 candidate_ledger=CandidateLedger(),
                 shared_local_pattern_semantics=(
                     None if self.maintain_mode else self._get_shared_local_pattern_semantics()
                 ),
                 shared_semantic_overlay=(
                     None if self.maintain_mode else self._get_shared_semantic_overlay()
                 ),
            )
            report_dict = analyzer.run()
            
            duration = time.time() - start_time
            
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict=report_dict.get("overall_verdict", "unknown"),
                issues=report_dict.get("issues", []),
                audit_observations=report_dict.get("metadata", {}).get("audit_observations", []),
                duration_seconds=duration,
                context_tokens=report_dict.get("metadata", {}).get("context_tokens", 0),
                cumulative_prompt_tokens=report_dict.get("metadata", {}).get("cumulative_prompt_tokens", 0),
                cumulative_completion_tokens=report_dict.get("metadata", {}).get("cumulative_completion_tokens", 0),
                cumulative_total_tokens=report_dict.get("metadata", {}).get("cumulative_total_tokens", 0),
                diff_focus=entry.diff_focus,
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict="error",
                error=str(e),
                duration_seconds=duration,
                diff_focus=entry.diff_focus,
            )
    
    def _prepare_shared_semantics(self) -> None:
        """Warm shared project semantics before entry-level analyzers fan out."""
        self._get_shared_local_pattern_semantics()
        self._get_shared_semantic_overlay()

    def _get_shared_local_pattern_semantics(self) -> LocalPatternSemantics:
        if self._shared_local_pattern_semantics is None:
            with self._shared_semantics_lock:
                if self._shared_local_pattern_semantics is None:
                    self._shared_local_pattern_semantics = LocalPatternSemanticBuilder(
                        self.code_index,
                        self.user_config,
                        self.snapshot_store,
                        self.base_config.project.exclude_paths,
                    ).build()
        return self._shared_local_pattern_semantics

    def _get_shared_semantic_overlay(self) -> Dict[str, Any]:
        if self._shared_semantic_overlay is None:
            with self._shared_semantics_lock:
                if self._shared_semantic_overlay is None:
                    self._shared_semantic_overlay = SemanticOverlayCompiler(self.user_config).compile()
        return self._shared_semantic_overlay

    def _create_config_for_entry(self, entry: FunctionEntry) -> ZScopeConfig:
        """Create a ZScopeConfig copy with the specified entry and custom prompt."""
        from copy import deepcopy
        config = deepcopy(self.base_config)
        config.project.entry_function = entry.function_name
        config.project.entry_diff_focus = entry.diff_focus
        
        # Keep entry-specific focus separate from the configured task so skill
        # routing remains driven by the global vulnerability scope.
        if entry.custom_prompt:
            for agent_cfg in config.project.agents:
                if agent_cfg.name == "vulnerability_analyzer":
                    agent_cfg.entry_custom_prompt = entry.custom_prompt
        
        return config
    

    def generate_combined_report(
        self, 
        results: Dict[str, ParallelAnalysisResult],
        output_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Generate a combined report from all parallel analysis results.
        
        Args:
            results: Dict of function name to analysis result
            output_path: Optional path to save combined report
            
        Returns:
            Combined report dict
        """
        all_issues = []
        all_observations = []
        function_summaries = []
        total_duration = 0.0
        
        for entry_key, result in results.items():
            total_duration += result.duration_seconds
            
            function_summaries.append({
                "function": result.function_name,
                "entry_key": entry_key,
                "verdict": result.verdict,
                "issue_count": len(result.issues),
                "audit_observation_count": len(result.audit_observations),
                "duration_seconds": round(result.duration_seconds, 2),
                "context_tokens": result.context_tokens,
                "cumulative_prompt_tokens": result.cumulative_prompt_tokens,
                "cumulative_completion_tokens": result.cumulative_completion_tokens,
                "cumulative_total_tokens": result.cumulative_total_tokens,
                "error": result.error
            })
            
            # Add function context to each issue
            for issue in result.issues:
                issue_copy = issue.copy()
                issue_copy["analyzed_from"] = result.function_name
                if entry_key != result.function_name:
                    issue_copy["entry_key"] = entry_key
                self._annotate_diff_relevance(issue_copy, result.diff_focus)
                all_issues.append(issue_copy)
            for observation in result.audit_observations:
                observation_copy = observation.copy()
                observation_copy["analyzed_from"] = result.function_name
                if entry_key != result.function_name:
                    observation_copy["entry_key"] = entry_key
                self._annotate_diff_relevance(observation_copy, result.diff_focus)
                all_observations.append(observation_copy)
        
        # Deduplicate issues by location
        unique_issues = self._deduplicate_issues(all_issues)
        unique_observations = self._deduplicate_issues(all_observations)
        report_views = build_report_views(unique_issues, unique_observations)
        view_summary = report_view_summary({"report_views": report_views})
        with_review_view = report_views.get("with_needs_review", {})
        
        diff_relevance_summary = self._diff_relevance_summary(unique_issues, unique_observations)

        combined_report = {
            "type": "parallel_analysis_report",
            "summary": {
                "functions_analyzed": len(results),
                "total_issues": len(unique_issues),
                "unique_issues": len(unique_issues),
                "audit_observations": len(unique_observations),
                "needs_review_issues": int(
                    with_review_view.get("included_needs_review_count") or 0
                ),
                "total_issues_with_needs_review": int(
                    with_review_view.get("issue_count") or len(with_review_view.get("issues", []))
                ),
                "total_duration_seconds": round(total_duration, 2),
                "total_context_tokens": sum(r.context_tokens for r in results.values()),
                "total_cumulative_prompt_tokens": sum(r.cumulative_prompt_tokens for r in results.values()),
                "total_cumulative_completion_tokens": sum(r.cumulative_completion_tokens for r in results.values()),
                "total_cumulative_total_tokens": sum(r.cumulative_total_tokens for r in results.values()),
                "parallel_speedup": f"{len(results)}x potential (using {self.max_workers} workers)",
                "diff_relevance": diff_relevance_summary["issues"],
            },
            "function_results": function_summaries,
            "issues": unique_issues,
            "issues_by_severity": self._group_by_severity(unique_issues),
            "report_views": report_views,
            "issues_with_needs_review": with_review_view.get("issues", []),
            "issues_by_severity_with_needs_review": with_review_view.get("issues_by_severity", {}),
            "metadata": {
                "audit_observation_count": len(unique_observations),
                "audit_observations": unique_observations,
                "report_view_summary": view_summary,
                "diff_relevance_summary": diff_relevance_summary,
                "context_tokens": sum(r.context_tokens for r in results.values()),
                "cumulative_prompt_tokens": sum(r.cumulative_prompt_tokens for r in results.values()),
                "cumulative_completion_tokens": sum(r.cumulative_completion_tokens for r in results.values()),
                "cumulative_total_tokens": sum(r.cumulative_total_tokens for r in results.values()),
            },
        }
        
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(combined_report, f, indent=2, ensure_ascii=False)
            logger.info(f"Combined report saved to: {output_path}")
        
        return combined_report

    @classmethod
    def _annotate_diff_relevance(
        cls,
        issue: Dict[str, Any],
        diff_focus: Optional[Dict[str, Any]],
    ) -> None:
        if not isinstance(diff_focus, dict) or diff_focus.get("mode") != "diff_impact":
            return
        relevance = cls._classify_diff_relevance(issue, diff_focus)
        label = {
            "incremental": "[增量]",
            "existing": "[存量]",
            "unknown": "[影响待确认]",
        }.get(relevance, "[影响待确认]")
        issue["diff_relevance"] = relevance
        issue["diff_relevance_label"] = label
        issue["diff_focus"] = cls._compact_diff_focus_for_issue(diff_focus)
        cls._prefix_issue_summary(issue, label)

    @classmethod
    def _classify_diff_relevance(
        cls,
        issue: Dict[str, Any],
        diff_focus: Dict[str, Any],
    ) -> str:
        changed_functions = diff_focus.get("changed_functions")
        if not isinstance(changed_functions, list):
            return "unknown"
        changed_names = {
            str(item.get("function_name") or "")
            for item in changed_functions
            if isinstance(item, dict)
        }
        issue_func = str(issue.get("function") or issue.get("func_name") or "")
        if issue_func and issue_func in changed_names:
            return "incremental"

        issue_file, issue_line = parse_issue_location(str(issue.get("location") or ""))
        if issue_file and issue_line is not None:
            for item in changed_functions:
                if not isinstance(item, dict):
                    continue
                changed_file = str(item.get("file_path") or "")
                changed_lines = item.get("changed_lines")
                if not isinstance(changed_lines, list):
                    continue
                if cls._same_report_path(issue_file, changed_file) and issue_line in {
                    int(line) for line in changed_lines if str(line).isdigit()
                }:
                    return "incremental"

        affected_path_nodes = set()
        for path_item in diff_focus.get("affected_paths") or []:
            if not isinstance(path_item, dict):
                continue
            path = path_item.get("path")
            if isinstance(path, list):
                affected_path_nodes.update(str(node) for node in path if str(node))
        if issue_func and issue_func in affected_path_nodes:
            return "incremental"
        if diff_focus.get("fallback_reasons"):
            return "unknown"
        return "existing"

    @staticmethod
    def _same_report_path(left: str, right: str) -> bool:
        left_norm = str(left or "").replace("\\", "/").lstrip("./")
        right_norm = str(right or "").replace("\\", "/").lstrip("./")
        return bool(
            left_norm
            and right_norm
            and (left_norm == right_norm or left_norm.endswith("/" + right_norm) or right_norm.endswith("/" + left_norm))
        )

    @staticmethod
    def _compact_diff_focus_for_issue(diff_focus: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "component": diff_focus.get("component", ""),
            "base_ref": diff_focus.get("base_ref", ""),
            "head_ref": diff_focus.get("head_ref", ""),
            "entry_function": diff_focus.get("entry_function", ""),
            "entry_exposure": diff_focus.get("entry_exposure", ""),
            "fallback_reasons": list(diff_focus.get("fallback_reasons") or []),
            "changed_functions": [
                {
                    "function_name": item.get("function_name", ""),
                    "file_path": item.get("file_path", ""),
                    "changed_lines": list(item.get("changed_lines") or []),
                }
                for item in diff_focus.get("changed_functions") or []
                if isinstance(item, dict)
            ],
        }

    @staticmethod
    def _prefix_issue_summary(issue: Dict[str, Any], label: str) -> None:
        for key in ("title", "summary", "description"):
            value = issue.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            if value.startswith("[增量]") or value.startswith("[存量]") or value.startswith("[影响待确认]"):
                return
            issue[key] = f"{label} {value}"
            return
        issue["summary"] = label

    @staticmethod
    def _diff_relevance_summary(
        issues: List[Dict[str, Any]],
        observations: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, int]]:
        def count(items: List[Dict[str, Any]]) -> Dict[str, int]:
            result = {"incremental": 0, "existing": 0, "unknown": 0, "unscoped": 0}
            for item in items:
                relevance = str(item.get("diff_relevance") or "unscoped")
                if relevance not in result:
                    relevance = "unknown"
                result[relevance] += 1
            return result

        return {"issues": count(issues), "audit_observations": count(observations)}

    def generate_combined_markdown_report(
        self, 
        results: Dict[str, ParallelAnalysisResult], 
        output_path: Path
    ) -> str:
        """
        Generate a human-readable Markdown report for batch analysis.
        
        Args:
            results: Dict of function name to analysis result
            output_path: Path to save combined report
            
        Returns:
            Markdown report content
        """
        summary = {
            "total": len(results),
            "issues_found": sum(1 for r in results.values() if r.verdict == "issues_found"),
            "no_issue": sum(1 for r in results.values() if r.verdict == "no_issue_found"),
            "error": sum(1 for r in results.values() if r.verdict == "error"),
            "total_issues": sum(len(r.issues) for r in results.values()),
            "audit_observations": sum(len(r.audit_observations) for r in results.values()),
        }
        
        md = [
            "# Z-SCOPE Batch Analysis Report",
            "",
            "## Summary",
            f"- **Functions Analyzed**: {summary['total']}",
            f"- **Issues Found**: {summary['issues_found']}",
            f"- **No Issues Found**: {summary['no_issue']}",
            f"- **Errors**: {summary['error']}",
            f"- **Total Issues Detected**: {summary['total_issues']}",
            f"- **Audit Observations**: {summary['audit_observations']}",
            "",
            "## Function Details",
            "",
            "| Function | Verdict | Issues | Needs Review / Audit | Duration |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]
        
        for name, res in sorted(results.items()):
            duration_str = f"{res.duration_seconds:.1f}s" if res.duration_seconds else "N/A"
            display_name = res.function_name if name == res.function_name else f"{res.function_name} ({name})"
            needs_review_count = sum(
                1
                for issue in res.audit_observations
                if str(issue.get("validation_status") or "").lower() == "needs_review"
            )
            md.append(
                f"| {display_name} | {res.verdict} | {len(res.issues)} | "
                f"{needs_review_count} / {len(res.audit_observations)} | {duration_str} |"
            )
        
        md.append("")
        md.append("## Detected Issues")
        md.append("")
        
        # Group issues by analyzed_from (entry function)
        issues_by_entry = {}
        for entry_key, r in results.items():
            if r.verdict == "issues_found":
                issues_by_entry[entry_key] = r.issues

        if not issues_by_entry:
            md.append("*No issues detected.*")
        else:
            for entry_func, issues in sorted(issues_by_entry.items()):
                md.append(f"### Entry Function: `{entry_func}`")
                md.append("")
                
                # Simple deduplication per entry if needed
                seen_in_entry = set()
                
                for idx, issue in enumerate(issues, 1):
                    # Skip rejected issues in offline markdown report
                    if issue.get("validation_status") == "rejected":
                        continue
                    
                    issue_key = f"{issue.get('location', 'N/A')}:{issue.get('description', '')[:50]}"
                    if issue_key in seen_in_entry:
                        continue
                    seen_in_entry.add(issue_key)
                    
                    impact = str(issue.get("impact_level", "UNKNOWN")).upper()
                    conf = issue.get("confidence", "N/A")
                    if isinstance(conf, float):
                        conf = f"{conf:.2f}"
                        
                    snippet = issue.get("code_snippet")
                    md.extend([
                        f"#### {idx}. [{impact}] {issue.get('id', f'ISSUE_{idx}')}: {issue.get('function', 'N/A')}",
                        f"- **Location**: `{issue.get('location', 'N/A')}`",
                        f"- **Confidence**: `{conf}`",
                        f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                    ])
                    if snippet:
                        md.append(f"- **Relevant Code**:\n```c\n{self._normalize_md_text(snippet)}\n```")
                    
                    md.append(f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}")
                    
                    # Add reasoning if present
                    reasoning = issue.get('reasoning')
                    if reasoning:
                        md.append(f"- **Analysis Reasoning**: {self._normalize_md_text(reasoning)}")
                    
                    md.append(f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}")
                    md.append(f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}")
                    
                    # Add validation status and reasoning
                    val_status = issue.get('validation_status')
                    if val_status:
                        status_emoji = {"validated": "✅", "rejected": "❌", "pending": "⏳", "unvalidated": "⚠️"}.get(val_status, "")
                        md.append(f"- **Validation Status**: {status_emoji} {val_status}")
                        
                        val_reasoning = issue.get('validation_reasoning')
                        if val_reasoning:
                            md.append(f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}")
                    
                    md.append("")

        needs_review_by_entry = {}
        for entry_key, r in results.items():
            review_items = [
                issue
                for issue in r.audit_observations
                if str(issue.get("validation_status") or "").lower() == "needs_review"
            ]
            if review_items:
                needs_review_by_entry[entry_key] = review_items

        md.append("")
        md.append("## Needs Review Findings")
        md.append("")
        if not needs_review_by_entry:
            md.append("*No needs_review observations.*")
        else:
            for entry_func, issues in sorted(needs_review_by_entry.items()):
                md.append(f"### Entry Function: `{entry_func}`")
                md.append("")
                for idx, issue in enumerate(issues, 1):
                    impact = str(issue.get("impact_level", "UNKNOWN")).upper()
                    conf = issue.get("confidence", "N/A")
                    if isinstance(conf, float):
                        conf = f"{conf:.2f}"
                    md.extend([
                        f"#### {idx}. [{impact}] {issue.get('id', f'REVIEW_{idx}')}: {issue.get('function', 'N/A')}",
                        f"- **Location**: `{issue.get('location', 'N/A')}`",
                        f"- **Confidence**: `{conf}`",
                        f"- **Category**: {issue.get('category', 'N/A')} ({issue.get('subcategory', 'N/A')})",
                        f"- **Description**: {self._normalize_md_text(issue.get('description', 'N/A'))}",
                        f"- **Root Cause**: {self._normalize_md_text(issue.get('root_cause', 'N/A'))}",
                        f"- **Suggested Fix**: {self._normalize_md_text(issue.get('suggested_fix', 'N/A'))}",
                    ])
                    val_reasoning = issue.get("validation_reasoning")
                    if val_reasoning:
                        md.append(f"- **Validation Reasoning**: {self._normalize_md_text(val_reasoning)}")
                    md.append("")
                
        content = "\n".join(md)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        logger.info(f"Markdown report saved to: {output_path}")
        return content

    
    def _deduplicate_issues(self, issues: List[Dict]) -> List[Dict]:
        """Remove duplicate issues based on canonical sink/root-cause evidence."""
        semantic_cfg = getattr(getattr(getattr(self, "config", None), "reporting", None), "semantic_dedup", None)
        if semantic_cfg is not None and getattr(semantic_cfg, "enabled", True):
            deduped, _summary = deduplicate_semantic_issues_programmatic(issues)
            return deduped
        return deduplicate_issues(issues)

    @staticmethod
    def _issue_rank(issue: Dict[str, Any]) -> tuple[int, float, int]:
        return issue_rank(issue)

    @classmethod
    def _canonical_issue_key(cls, issue: Dict[str, Any]) -> str:
        return canonical_issue_key(issue)

    @staticmethod
    def _normalize_issue_category(value: str) -> str:
        return normalize_issue_category(value)

    @staticmethod
    def _normalize_issue_key_part(value: Any) -> str:
        return normalize_issue_key_part(value)

    @classmethod
    def _flatten_issue_text(cls, value: Any) -> str:
        return flatten_issue_text(value)

    @staticmethod
    def _parse_issue_location(location: str) -> tuple[str, Optional[int]]:
        return parse_issue_location(location)
    
    def _group_by_severity(self, issues: List[Dict]) -> Dict[str, List[Dict]]:
        """Group issues by impact level."""
        groups: Dict[str, List[Dict[str, Any]]] = {"critical": [], "high": [], "medium": [], "low": []}
        
        for issue in issues:
            level = issue.get("impact_level", "medium").lower()
            if level in groups:
                groups[level].append(issue)
            else:
                groups["medium"].append(issue)
        
        return groups
