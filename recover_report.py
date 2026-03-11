import json
import sqlite3
import os
import time
from pathlib import Path
import sys

# Change this if your config file has a different name
YAML_CONFIG_FILE = "zscope.yaml"

try:
    from zscope.config.config import ConfigLoader
    from zscope.config.function_entry import FunctionListLoader
    from zscope.core.parallel_analyzer import ParallelAnalyzer, ParallelAnalysisResult
    import click
except ImportError:
    print("Please run this script from the Z-Scope virtual environment.")
    sys.exit(1)

def recover_report(config_path: str):
    config = ConfigLoader.load(config_path)
    snapshot_dir = Path(config.analysis.snapshot_dir)
    db_path = snapshot_dir / "snapshots.db"
    
    if not db_path.exists():
        print(f"Error: Snapshot database not found at {db_path}")
        return
        
    entries = []
    if config.project.entry_functions_list and Path(config.project.entry_functions_list).exists():
        entries = FunctionListLoader.load(config.project.entry_functions_list)
        print(f"Loaded {len(entries)} functions to recover from {config.project.entry_functions_list}")
    else:
        print("Error: No entry_functions_list configured or file not found in yaml.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    results = {}
    
    for entry in entries:
        func = entry.function_name
        # Fetch the most recent snapshot file for this function
        try:
            cursor.execute("SELECT final_report_file, snapshot_file FROM snapshots WHERE func_name=? ORDER BY timestamp DESC", (func,))
            rows = cursor.fetchall()
        except sqlite3.OperationalError:
            cursor.execute("SELECT snapshot_file FROM snapshots WHERE func_name=? ORDER BY timestamp DESC", (func,))
            rows = [(None, row[0]) for row in cursor.fetchall()]
        
        found_report = False
        duration = 1.0 # Mock duration
        
        for final_file, snap_file in rows:
            target = final_file if final_file else snap_file
            if not target:
                continue
                
            file_path = snapshot_dir / target
            if not file_path.exists():
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # If it has issues, it's a vulnerability analysis result
                if "issues" in data or "suspicious_points" in data:
                    issues = data.get("issues", data.get("suspicious_points", []))
                    
                    # Ensure formatting is clean
                    clean_issues = []
                    for iss in issues:
                         if isinstance(iss, dict):
                              clean_issues.append(iss)
                    
                    verdict = "issues_found" if clean_issues else "no_issue_found"
                    if "overall_verdict" in data:
                         verdict = data["overall_verdict"]

                    results[func] = ParallelAnalysisResult(
                        function_name=func,
                        verdict=verdict,
                        issues=clean_issues,
                        duration_seconds=duration
                    )
                    found_report = True
                    break
            except Exception as e:
                pass
                
        if not found_report:
            print(f"Warning: No completed report found in cache for {func}")
            results[func] = ParallelAnalysisResult(
                function_name=func,
                verdict="unknown",
                issues=[],
                error="No valid snapshot found in DB"
            )

    conn.close()
    
    # We can use ParallelAnalyzer to combine everything and regenerate standard Markdown/JSON
    print(f"Recovered {len(results)} function outcomes from SQLite cache.")
    
    # Create lightweight mock ParallelAnalyzer to call generate methods
    analyzer = ParallelAnalyzer(config)
    json_path = config.project.project_root / "zscope_batch_report.json"
    md_path = config.project.project_root / "zscope_batch_report.md"
    
    analyzer.generate_combined_report(results, json_path)
    analyzer.generate_combined_markdown_report(results, md_path)
    
    print("\n[SUCCESS] Reports fully recovered and re-generated:")
    print(f" -> {json_path.absolute()}")
    print(f" -> {md_path.absolute()}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Recover deleted batch reports from Z-Scope local SQLite Cache")
    parser.add_argument("-c", "--config", default="zscope.yaml", help="Path to zscope.yaml")
    args = parser.parse_args()
    
    recover_report(args.config)
