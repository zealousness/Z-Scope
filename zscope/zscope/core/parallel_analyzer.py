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
from .analyzer import Analyzer
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
    
    def __init__(self, config: ZScopeConfig, max_workers: int = 3):
        """
        Initialize parallel analyzer.
        
        Args:
            config: Base ZScope configuration
            max_workers: Maximum number of concurrent LLM sessions (default: 3)
        """
        self.base_config = config
        self.max_workers = min(max_workers, 3)  # Cap at 3 to avoid overwhelming LLM
        self.code_index = CodeIndex(
            config.project.project_root, 
            config.project.compile_commands_path
        )
        
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
        results = {}
        total = len(function_names)
        completed = 0
        
        logger.info(f"Starting parallel analysis of {total} functions with {self.max_workers} workers")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all analysis tasks
            future_to_func = {
                executor.submit(self._analyze_single_function, func_name): func_name
                for func_name in function_names
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_func):
                func_name = future_to_func[future]
                completed += 1
                
                try:
                    result = future.result()
                    results[func_name] = result
                    logger.info(f"[{completed}/{total}] {func_name}: {result.verdict} ({len(result.issues)} issues)")
                except Exception as e:
                    logger.error(f"[{completed}/{total}] {func_name}: ERROR - {e}")
                    results[func_name] = ParallelAnalysisResult(
                        function_name=func_name,
                        verdict="error",
                        error=str(e)
                    )
                
                if progress_callback:
                    progress_callback(completed, total, func_name)
        
        return results
    
    def _analyze_single_function(self, func_name: str) -> ParallelAnalysisResult:
        """Analyze a single function and return result."""
        start_time = time.time()
        
        try:
            # Create a config copy with this function as entry point
            config_copy = self._create_config_for_function(func_name)
            
            # Create analyzer and run
            analyzer = Analyzer(config_copy)
            report_dict = analyzer.run()
            
            duration = time.time() - start_time
            
            return ParallelAnalysisResult(
                function_name=func_name,
                verdict=report_dict.get("overall_verdict", "unknown"),
                issues=report_dict.get("issues", []),
                duration_seconds=duration
            )
            
        except Exception as e:
            duration = time.time() - start_time
            return ParallelAnalysisResult(
                function_name=func_name,
                verdict="error",
                error=str(e),
                duration_seconds=duration
            )
    
    def _create_config_for_function(self, func_name: str) -> ZScopeConfig:
        """Create a ZScopeConfig copy with the specified entry function."""
        from copy import deepcopy
        config = deepcopy(self.base_config)
        config.project.entry_function = func_name
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
    
    def _deduplicate_issues(self, issues: List[Dict]) -> List[Dict]:
        """Remove duplicate issues based on location and description."""
        seen = set()
        unique = []
        
        for issue in issues:
            key = (
                issue.get("location", ""),
                issue.get("subcategory", ""),
                issue.get("description", "")[:100]
            )
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
