#!/usr/bin/env python3
"""
Parallel scan script for Z-SCOPE.
Analyzes multiple functions concurrently for faster scanning.
"""

import sys
import json
import time
import argparse
from pathlib import Path

# Add zscope to path
sys.path.insert(0, str(Path(__file__).parent / "zscope"))

from zscope.config import ConfigLoader
from zscope.parallel_analyzer import ParallelAnalyzer


def main():
    parser = argparse.ArgumentParser(
        description="Z-SCOPE Parallel Analyzer - Scan multiple functions concurrently"
    )
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=Path("zscope.yaml"),
        help="Path to config file (default: zscope.yaml)"
    )
    parser.add_argument(
        "-f", "--functions",
        nargs="+",
        help="List of function names to analyze (default: auto-detect from headers)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=3,
        help="Max number of concurrent workers (default: 3, max: 3)"
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("parallel_report.json"),
        help="Output file for combined report"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Z-SCOPE Parallel Analyzer")
    print("=" * 60)
    
    # Load configuration
    print(f"\nLoading configuration from: {args.config}")
    try:
        config = ConfigLoader.load(str(args.config))
    except Exception as e:
        print(f"ERROR: Failed to load config: {e}")
        sys.exit(1)
    
    # Initialize parallel analyzer
    analyzer = ParallelAnalyzer(config, max_workers=args.workers)
    print(f"Initialized with {args.workers} concurrent workers")
    
    # Get functions to analyze
    if args.functions:
        functions = args.functions
    else:
        # Auto-detect from config or use common API functions
        functions = [
            "cache_create", "cache_put", "cache_get", 
            "cache_delete", "cache_clear", "cache_save",
            "cache_load", "cache_destroy"
        ]
    
    print(f"\nFunctions to analyze: {len(functions)}")
    for f in functions:
        print(f"  - {f}")
    
    # Progress callback
    def progress(completed, total, func_name):
        pct = (completed / total) * 100
        print(f"[{completed}/{total}] ({pct:.0f}%) Completed: {func_name}")
    
    # Run parallel analysis
    print("\n" + "-" * 60)
    print("Starting parallel analysis...")
    print("-" * 60)
    
    start_time = time.time()
    results = analyzer.analyze_functions(functions, progress_callback=progress)
    total_time = time.time() - start_time
    
    # Generate combined report
    print("\n" + "-" * 60)
    print("Generating combined report...")
    print("-" * 60)
    
    report = analyzer.generate_combined_report(results, args.output)
    
    # Print summary
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    
    summary = report["summary"]
    print(f"\nFunctions analyzed: {summary['functions_analyzed']}")
    print(f"Total issues found: {summary['total_issues']}")
    print(f"Total time: {total_time:.1f}s")
    print(f"Parallel speedup: ~{summary['functions_analyzed'] / max(1, total_time / 30):.1f}x")
    
    # Issues by severity
    by_severity = report.get("issues_by_severity", {})
    print("\nIssues by severity:")
    print(f"  🔴 Critical: {len(by_severity.get('critical', []))}")
    print(f"  🟠 High:     {len(by_severity.get('high', []))}")
    print(f"  🟡 Medium:   {len(by_severity.get('medium', []))}")
    print(f"  🔵 Low:      {len(by_severity.get('low', []))}")
    
    # Top issues
    if report.get("issues"):
        print("\nTop issues:")
        for i, issue in enumerate(report["issues"][:5], 1):
            print(f"  {i}. [{issue.get('impact_level', 'unknown').upper()}] "
                  f"{issue.get('subcategory', 'unknown')} in {issue.get('function', 'unknown')}")
            print(f"     {issue.get('description', '')[:80]}...")
    
    print(f"\nFull report saved to: {args.output}")
    
    # Exit with error code if critical issues found
    critical_count = len(by_severity.get('critical', []))
    if critical_count > 0:
        print(f"\n⚠️  Found {critical_count} critical issues!")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
