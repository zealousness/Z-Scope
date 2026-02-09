"""
Parallel Analyzer for Z-SCOPE.
Supports concurrent analysis of multiple functions using thread pool.
"""

import concurrent.futures
import json
import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from ..config.config import ZScopeConfig
from ..config.function_entry import FunctionEntry
from .analyzer import Analyzer
from .snapshot_store import SnapshotStore
from ..retrieval.code_index import CodeIndex

logger = logging.getLogger(__name__)


@dataclass
class ParallelAnalysisResult:
    """Result of parallel analysis across multiple functions."""
    function_name: str
    verdict: str
    issues: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: float = 0.0


class ParallelAnalyzer:
    """
    Parallel analyzer that can analyze multiple functions concurrently.
    
    Uses a thread pool to run up to max_workers LLM analysis sessions
    simultaneously, significantly reducing total analysis time.
    """
    
    def __init__(self, config: ZScopeConfig, code_index: Optional[CodeIndex] = None):
        """
        Initialize parallel analyzer.
        
        Args:
            config: Base ZScope configuration
            code_index: Optional shared CodeIndex to avoid rebuilding
        """
        self.base_config = config
        self.max_workers = config.analysis.parallel_workers
        
        # Use provided code_index or create new one
        if code_index:
            self.code_index = code_index
        else:
            self.code_index = CodeIndex(
                config.project.project_root, 
                config.project.compile_commands_path
            )
        self.snapshot_store = SnapshotStore(Path(config.analysis.snapshot_dir))

    @staticmethod
    def _normalize_md_text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value)
        return text.replace("\\n", "\n")
        
    def analyze_function_entries(
        self,
        entries: List[FunctionEntry],
        progress_callback: Optional[callable] = None
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
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all analysis tasks
            future_to_entry = {
                executor.submit(self._analyze_single_entry, entry): entry
                for entry in entries
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_entry):
                entry = future_to_entry[future]
                completed += 1
                
                try:
                    result = future.result()
                    results[entry.function_name] = result
                    logger.info(f"[{completed}/{total}] {entry.function_name}: {result.verdict} ({len(result.issues)} issues)")
                except Exception as e:
                    logger.error(f"[{completed}/{total}] {entry.function_name}: ERROR - {e}")
                    results[entry.function_name] = ParallelAnalysisResult(
                        function_name=entry.function_name,
                        verdict="error",
                        error=str(e)
                    )
                
                if progress_callback:
                    progress_callback(completed, total, entry.function_name)
        
        return results
    
    def analyze_functions(
        self, 
        function_names: List[str],
        progress_callback: Optional[callable] = None
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
                 snapshot_store=self.snapshot_store
            )
            report_dict = analyzer.run()
            
            duration = time.time() - start_time
            
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict=report_dict.get("overall_verdict", "unknown"),
                issues=report_dict.get("issues", []),
                duration_seconds=duration
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return ParallelAnalysisResult(
                function_name=entry.function_name,
                verdict="error",
                error=str(e),
                duration_seconds=duration
            )
    
    def _create_config_for_entry(self, entry: FunctionEntry) -> ZScopeConfig:
        """Create a ZScopeConfig copy with the specified entry and custom prompt."""
        from copy import deepcopy
        config = deepcopy(self.base_config)
        config.project.entry_function = entry.function_name
        
        # Merge custom prompt with agent tasks
        if entry.custom_prompt:
            for agent_cfg in config.project.agents:
                if agent_cfg.name == "vulnerability_analyzer" and agent_cfg.task:
                    # Append custom prompt to base task
                    agent_cfg.task = f"{agent_cfg.task}\n\n额外关注点：{entry.custom_prompt}"
                elif agent_cfg.name == "vulnerability_analyzer":
                    agent_cfg.task = entry.custom_prompt
        
        return config
    
    def get_public_api_functions(self, header_files: Optional[List[str]] = None) -> List[str]:
        """
        Get list of public API functions from header files.
        
        Args:
            header_files: List of header file paths to scan, or None for auto-detect
            
        Returns:
            List of function names declared in headers
        """
        all_functions = self.code_index.get_all_functions()
        
        if header_files:
            # Filter to functions from specified headers
            public_funcs = []
            for func_info in all_functions:
                if any(h in func_info.get("file", "") for h in header_files):
                    public_funcs.append(func_info["name"])
            return public_funcs
        
        # Default: return all functions from .h files
        public_funcs = []
        for name, info in all_functions.items() if isinstance(all_functions, dict) else [(f["name"], f) for f in all_functions]:
            file_path = info.get("file", "") if isinstance(info, dict) else ""
            if ".h" in file_path or "_public" in name or not name.startswith("_"):
                public_funcs.append(name if isinstance(name, str) else info["name"])
        
        return public_funcs
    
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
        function_summaries = []
        total_duration = 0.0
        
        for func_name, result in results.items():
            total_duration += result.duration_seconds
            
            function_summaries.append({
                "function": func_name,
                "verdict": result.verdict,
                "issue_count": len(result.issues),
                "duration_seconds": round(result.duration_seconds, 2),
                "error": result.error
            })
            
            # Add function context to each issue
            for issue in result.issues:
                issue_copy = issue.copy()
                issue_copy["analyzed_from"] = func_name
                all_issues.append(issue_copy)
        
        # Deduplicate issues by location
        unique_issues = self._deduplicate_issues(all_issues)
        
        combined_report = {
            "type": "parallel_analysis_report",
            "summary": {
                "functions_analyzed": len(results),
                "total_issues": len(unique_issues),
                "unique_issues": len(unique_issues),
                "total_duration_seconds": round(total_duration, 2),
                "parallel_speedup": f"{len(results)}x potential (using {self.max_workers} workers)"
            },
            "function_results": function_summaries,
            "issues": unique_issues,
            "issues_by_severity": self._group_by_severity(unique_issues)
        }
        
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(combined_report, f, indent=2)
            logger.info(f"Combined report saved to: {output_path}")
        
        return combined_report

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
            "",
            "## Function Details",
            "",
            "| Function | Verdict | Issues | Duration |",
            "| :--- | :--- | :--- | :--- |"
        ]
        
        for name, res in sorted(results.items()):
            duration_str = f"{res.duration_seconds:.1f}s" if res.duration_seconds else "N/A"
            md.append(f"| {name} | {res.verdict} | {len(res.issues)} | {duration_str} |")
        
        md.append("")
        md.append("## Detected Issues")
        md.append("")
        
        # Group issues by analyzed_from (entry function)
        issues_by_entry = {}
        for r in results.values():
            if r.verdict == "issues_found":
                issues_by_entry[r.function_name] = r.issues

        if not issues_by_entry:
            md.append("*No issues detected.*")
        else:
            for entry_func, issues in sorted(issues_by_entry.items()):
                md.append(f"### Entry Function: `{entry_func}`")
                md.append("")
                
                # Simple deduplication per entry if needed
                seen_in_entry = set()
                
                for idx, issue in enumerate(issues, 1):
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
                
        content = "\n".join(md)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
            
        logger.info(f"Markdown report saved to: {output_path}")
        return content

    
    def _deduplicate_issues(self, issues: List[Dict]) -> List[Dict]:
        """Remove duplicate issues based on location and description."""
        seen = set()
        unique = []
        
        for issue in issues:
            # Safer key construction: ensure all parts are strings
            loc = str(issue.get("location", ""))
            sub = str(issue.get("subcategory", ""))
            desc = str(issue.get("description", ""))[:100]
            
            key = (loc, sub, desc)
            if key not in seen:
                seen.add(key)
                unique.append(issue)
        
        return unique
    
    def _group_by_severity(self, issues: List[Dict]) -> Dict[str, List[Dict]]:
        """Group issues by impact level."""
        groups = {"critical": [], "high": [], "medium": [], "low": []}
        
        for issue in issues:
            level = issue.get("impact_level", "medium").lower()
            if level in groups:
                groups[level].append(issue)
            else:
                groups["medium"].append(issue)
        
        return groups
