"""
Parallel Analyzer for Z-SCOPE.
Supports concurrent analysis of multiple functions using thread pool.
"""

import concurrent.futures
import json
import logging
import re
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
from ..framework.llm_client import LLMClient
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

_ENTRY_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_ENTRY_CONTROL_RE = re.compile(r"\b(if|for|while|switch|case|goto)\b")
_ENTRY_HEAVY_TEXT_RE = re.compile(
    r"(pthread|thread|callback|worker|recv|send|read|write|open|fopen|mmap|"
    r"malloc|calloc|realloc|free|lock|unlock|shared|global|argv|getenv|protocol|"
    r"message|runtime|dispatch|session)",
    re.IGNORECASE,
)
_ENTRY_EXPOSURE_WEIGHTS = {
    "other_user_input": 420,
    "communication": 380,
    "thread": 360,
    "api": 140,
}


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
    metadata: Dict[str, Any] = field(default_factory=dict)


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
        self._shared_llm_clients = self._build_shared_llm_clients(config)

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
                svf_parallel_workers=config.analysis.parallel_workers,
            )
        self.snapshot_store = SnapshotStore(Path(config.analysis.snapshot_dir))
        db_dir = Path(config.analysis.user_config_db) if config.analysis.user_config_db else Path(config.analysis.snapshot_dir)
        self.user_config = user_config or UserConfigStore(db_dir)
        self._interrupted = False
        self._shared_local_pattern_semantics: Optional[LocalPatternSemantics] = None
        self._shared_semantic_overlay: Optional[Dict[str, Any]] = None
        self._shared_semantics_lock = threading.Lock()
        self._last_batch_wall_seconds = 0.0

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
        batch_started = time.time()
        
        logger.info(f"Starting parallel analysis of {total} function entries with {self.max_workers} workers")
        if total and not self.maintain_mode:
            semantics_started = time.time()
            logger.info("[entry-worker] shared-semantics start entries=%d", total)
            self._prepare_shared_semantics()
            logger.info(
                "[entry-worker] shared-semantics end entries=%d duration=%.2fs",
                total,
                time.time() - semantics_started,
            )

        scheduled_entries = self._prioritize_entries_for_execution(entries)
        
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            # Submit all analysis tasks
            future_to_entry = {
                executor.submit(self._analyze_single_entry, entry): entry
                for entry in scheduled_entries
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
            self._last_batch_wall_seconds = time.time() - batch_started
            # Under normal successful execution, properly wait and clean up resources
            if executor and not getattr(self, '_interrupted', False):
                try:
                    executor.shutdown(wait=True)
                except Exception:
                    pass
                    
        return results

    @staticmethod
    def _build_shared_llm_clients(config: ZScopeConfig) -> Dict[str, LLMClient]:
        clients: Dict[str, LLMClient] = {}
        for name, llm_cfg in config.llms.items():
            clients[name] = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=llm_cfg.timeout,
                max_retries=llm_cfg.max_retries,
                max_tokens=llm_cfg.max_tokens,
                base_url_rate_limit_per_minute=getattr(
                    llm_cfg, "base_url_rate_limit_per_minute", 0
                ),
                base_url_max_concurrent_requests=getattr(
                    llm_cfg, "base_url_max_concurrent_requests", 0
                ),
            )
        return clients

    def _prioritize_entries_for_execution(self, entries: List[FunctionEntry]) -> List[FunctionEntry]:
        """Schedule likely long-running entries first to reduce batch tail idle time."""
        if len(entries) <= 1:
            return list(entries)

        scored = [
            (self._entry_scheduling_score(entry), index, entry)
            for index, entry in enumerate(entries)
        ]
        scored.sort(key=lambda item: (-item[0], item[1]))
        prioritized = [entry for _score, _index, entry in scored]
        if [entry.function_name for entry in prioritized] != [entry.function_name for entry in entries]:
            preview = ", ".join(
                f"{entry.function_name}:{score}"
                for score, _index, entry in scored[: min(8, len(scored))]
            )
            logger.info("[entry-worker] prioritized entry schedule top=%s", preview)
        return prioritized

    def _entry_scheduling_score(self, entry: FunctionEntry) -> int:
        score = 0
        exposure = str(getattr(entry, "exposure", "") or "").strip().lower()
        score += _ENTRY_EXPOSURE_WEIGHTS.get(exposure, 0)
        reason_text = " ".join(str(reason) for reason in getattr(entry, "reasons", []) or [])
        metadata_text = " ".join(
            part
            for part in (
                str(entry.custom_prompt or ""),
                exposure,
                reason_text,
            )
            if part
        )
        if _ENTRY_HEAVY_TEXT_RE.search(metadata_text):
            score += 80

        try:
            impl = self.code_index.get_function_impl(
                entry.function_name,
                max_lines=self.base_config.analysis.max_function_lines,
                include_context=False,
                warn_missing=False,
                file_path=str(entry.file_path or ""),
            )
        except Exception as exc:
            logger.debug(
                "Unable to estimate scheduling cost for '%s': %s",
                entry.function_name,
                exc,
            )
            impl = None

        if isinstance(impl, dict):
            code = str(impl.get("code") or "")
            code_without_entry_name = re.sub(
                rf"\b{re.escape(entry.function_name)}\b",
                "",
                code,
            )
            line_count = max(0, len(code.splitlines()))
            score += min(600, line_count * 4)
            call_names = {
                name
                for name in _ENTRY_CALL_RE.findall(code_without_entry_name)
                if name
                and name
                not in {"if", "for", "while", "switch", "return", "sizeof"}
            }
            score += min(360, len(call_names) * 18)
            score += min(220, len(_ENTRY_CONTROL_RE.findall(code_without_entry_name)) * 12)
            score += min(260, len(_ENTRY_HEAVY_TEXT_RE.findall(code_without_entry_name)) * 18)
        return int(score)

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
        entry_key = self._entry_result_key(entry)
        logger.info(
            "[entry-worker] start entry=%s key=%s file=%s",
            entry.function_name,
            entry_key,
            entry.file_path or "",
        )
        
        try:
            # Create a config copy with this function as entry point and custom prompt
            phase_started = time.time()
            config_copy = self._create_config_for_entry(entry)
            logger.info(
                "[entry-worker] config-ready entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - phase_started,
            )
            
            # Create analyzer and run with shared components
            phase_started = time.time()
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
                 llm_clients=self._shared_llm_clients,
                 write_root_reports=False,
            )
            logger.info(
                "[entry-worker] analyzer-ready entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - phase_started,
            )
            run_started = time.time()
            logger.info(
                "[entry-worker] run-start entry=%s key=%s",
                entry.function_name,
                entry_key,
            )
            report_dict = analyzer.run()
            report_metadata = report_dict.get("metadata", {}) if isinstance(report_dict.get("metadata"), dict) else {}
            logger.info(
                "[entry-worker] run-end entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                time.time() - run_started,
            )
            
            duration = time.time() - start_time
            logger.info(
                "[entry-worker] end entry=%s key=%s verdict=%s issues=%d duration=%.2fs",
                entry.function_name,
                entry_key,
                report_dict.get("overall_verdict", "unknown"),
                len(report_dict.get("issues", [])),
                duration,
            )
            
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict=report_dict.get("overall_verdict", "unknown"),
                issues=report_dict.get("issues", []),
                audit_observations=report_metadata.get("audit_observations", []),
                duration_seconds=duration,
                context_tokens=report_metadata.get("context_tokens", 0),
                cumulative_prompt_tokens=report_metadata.get("cumulative_prompt_tokens", 0),
                cumulative_completion_tokens=report_metadata.get("cumulative_completion_tokens", 0),
                cumulative_total_tokens=report_metadata.get("cumulative_total_tokens", 0),
                diff_focus=entry.diff_focus,
                metadata=report_metadata,
            )
            
        except Exception as e:
            duration = time.time() - start_time
            logger.exception(
                "[entry-worker] error entry=%s key=%s duration=%.2fs",
                entry.function_name,
                entry_key,
                duration,
            )
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
        config.project.entry_file_path = entry.file_path
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
            validation_performance = (
                result.metadata.get("validation_performance", {})
                if isinstance(result.metadata, dict)
                else {}
            )
            
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
                "validation_performance": validation_performance,
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
        diff_coverage = self._diff_coverage_metadata()
        batch_wall_seconds = round(float(getattr(self, "_last_batch_wall_seconds", 0.0) or 0.0), 2)
        effective_speedup = (total_duration / batch_wall_seconds) if batch_wall_seconds > 0 else 0.0
        worker_utilization = (
            effective_speedup / max(1, int(self.max_workers or 1))
            if batch_wall_seconds > 0
            else 0.0
        )
        validation_performance_summary = self._validation_performance_summary(results)
        va_candidate_coverage_summary = self._va_candidate_coverage_summary(results)

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
                "batch_wall_seconds": batch_wall_seconds,
                "total_context_tokens": sum(r.context_tokens for r in results.values()),
                "total_cumulative_prompt_tokens": sum(r.cumulative_prompt_tokens for r in results.values()),
                "total_cumulative_completion_tokens": sum(r.cumulative_completion_tokens for r in results.values()),
                "total_cumulative_total_tokens": sum(r.cumulative_total_tokens for r in results.values()),
                "parallel_speedup": f"{effective_speedup:.2f}x observed (using {self.max_workers} workers)",
                "parallel_worker_utilization": round(worker_utilization, 4),
                "diff_relevance": diff_relevance_summary["issues"],
                "diff_coverage": diff_coverage.get("coverage_summary", {}),
                "validation_performance": validation_performance_summary,
                "va_candidate_coverage": va_candidate_coverage_summary,
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
                "diff_impact_coverage": diff_coverage,
                "context_tokens": sum(r.context_tokens for r in results.values()),
                "cumulative_prompt_tokens": sum(r.cumulative_prompt_tokens for r in results.values()),
                "cumulative_completion_tokens": sum(r.cumulative_completion_tokens for r in results.values()),
                "cumulative_total_tokens": sum(r.cumulative_total_tokens for r in results.values()),
                "validation_performance": validation_performance_summary,
                "va_candidate_coverage_summary": va_candidate_coverage_summary,
            },
        }
        
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(combined_report, f, indent=2, ensure_ascii=False)
            logger.info(f"Combined report saved to: {output_path}")
        
        return combined_report

    @staticmethod
    def _validation_performance_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, int]:
        keys = (
            "iterations",
            "tool_call_count",
            "validator_fast_path_attempted",
            "validator_fast_path_accepted",
            "prevalidation_decision_count",
            "clang_prevalidation_decision_count",
            "static_audit_observation_count",
            "static_suppressed_count",
        )
        summary = {key: 0 for key in keys}
        for result in results.values():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            perf = metadata.get("validation_performance") if isinstance(metadata.get("validation_performance"), dict) else {}
            for key in keys:
                try:
                    summary[key] += int(perf.get(key, 0) or 0)
                except (TypeError, ValueError):
                    continue
        return summary

    @staticmethod
    def _va_candidate_coverage_summary(
        results: Dict[str, ParallelAnalysisResult],
    ) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for result in results.values():
            metadata = result.metadata if isinstance(result.metadata, dict) else {}
            coverage = metadata.get("va_candidate_coverage_summary")
            if not isinstance(coverage, dict):
                continue
            for key, value in coverage.items():
                try:
                    summary[key] = summary.get(key, 0) + int(value or 0)
                except (TypeError, ValueError):
                    continue
        return summary

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
        issue_file, issue_line = parse_issue_location(str(issue.get("location") or ""))
        if issue_func:
            if issue_file:
                for item in changed_functions:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("function_name") or "") != issue_func:
                        continue
                    if cls._same_report_path(issue_file, str(item.get("file_path") or "")):
                        return "incremental"
            elif issue_func in changed_names:
                return "incremental"

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
        affected_path_pairs = set()
        saw_path_refs = False
        for path_item in diff_focus.get("affected_paths") or []:
            if not isinstance(path_item, dict):
                continue
            path = path_item.get("path")
            if isinstance(path, list):
                affected_path_nodes.update(str(node) for node in path if str(node))
            for ref in path_item.get("path_refs") or []:
                if not isinstance(ref, dict):
                    continue
                saw_path_refs = True
                ref_name = str(ref.get("function_name") or "")
                ref_file = str(ref.get("file_path") or "")
                if ref_name and ref_file:
                    affected_path_pairs.add((ref_name, ref_file))
        if issue_func and issue_file and affected_path_pairs:
            if any(
                name == issue_func and cls._same_report_path(issue_file, file_path)
                for name, file_path in affected_path_pairs
            ):
                return "incremental"
        elif issue_func and issue_func in affected_path_nodes and (not issue_file or not saw_path_refs):
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

    def _diff_coverage_metadata(self) -> Dict[str, Any]:
        if not hasattr(self, "base_config"):
            return {}
        project = getattr(self.base_config, "project", None)
        entry_list = getattr(project, "entry_functions_list", None)
        if not entry_list:
            return {}
        path = Path(entry_list)
        if not path.exists() or not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.debug("Unable to read diff coverage metadata from %s: %s", path, exc)
            return {}
        diff_impact = data.get("diff_impact") if isinstance(data, dict) else None
        if not isinstance(diff_impact, dict):
            return {}
        return {
            "coverage_summary": diff_impact.get("coverage_summary") or {},
            "function_coverage": diff_impact.get("function_coverage") or [],
            "analysis_obligations": diff_impact.get("analysis_obligations") or [],
        }

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
        ]

        diff_coverage = self._diff_coverage_metadata()
        coverage_summary = diff_coverage.get("coverage_summary") if isinstance(diff_coverage, dict) else {}
        if isinstance(coverage_summary, dict) and coverage_summary:
            md.extend(
                [
                    "",
                    "## Diff Impact Coverage",
                    f"- **Changed Functions**: {coverage_summary.get('changed_total', 0)}",
                    f"- **Scan Entries**: {coverage_summary.get('scan_entry_count', 0)}",
                    f"- **Covered By Scan**: {coverage_summary.get('covered_by_scan', 0)}",
                    f"- **Context Only**: {coverage_summary.get('context_only', 0)}",
                    f"- **Triage Only**: {coverage_summary.get('triage_only', 0)}",
                    f"- **Unresolved**: {coverage_summary.get('unresolved', 0)}",
                ]
            )
            not_root = [
                item
                for item in diff_coverage.get("function_coverage", [])
                if isinstance(item, dict)
                and str(item.get("coverage_status") or "") != "scanned_as_root"
            ]
            if not_root:
                md.extend(
                    [
                        "",
                        "| Function | Coverage | Scan Entry | Reason |",
                        "| :--- | :--- | :--- | :--- |",
                    ]
                )
                for item in not_root[:20]:
                    md.append(
                        "| "
                        f"`{item.get('function_name', '')}` | "
                        f"{item.get('coverage_status', '')} | "
                        f"`{item.get('scan_entry', '')}` | "
                        f"{item.get('reason', '')} |"
                    )
                if len(not_root) > 20:
                    md.append(f"| ... | ... | ... | +{len(not_root) - 20} more |")

        md.extend(
            [
                "",
                "## Function Details",
                "",
                "| Function | Verdict | Issues | Needs Review / Audit | Duration |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        
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
        semantic_cfg = getattr(getattr(getattr(self, "base_config", None), "reporting", None), "semantic_dedup", None)
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
