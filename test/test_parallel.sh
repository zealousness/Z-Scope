#!/bin/bash
# Test parallel analysis with 2 workers (reduced for Ollama compatibility)

cd /app/zscope/tests/cache_module

echo "=========================================="
echo "Z-SCOPE Parallel Analysis Test"
echo "Workers: 2, Recursion Depth: 10"
echo "=========================================="

python3 -c "
from zscope.parallel_analyzer import ParallelAnalyzer
from zscope.config import ConfigLoader
import time

print('\\n[1] Loading configuration...')
config = ConfigLoader.load('zscope_blind.yaml')
print(f'    Recursion depth: {config.analysis.max_recursion_depth}')

# Increase timeout for Ollama
config.llm.timeout = 600

print('\\n[2] Initializing parallel analyzer with 2 workers...')
analyzer = ParallelAnalyzer(config, max_workers=2)

print('\\n[3] Starting parallel analysis of 3 key functions...')
functions = ['cache_get', 'cache_clear', 'cache_save']

start = time.time()
results = analyzer.analyze_functions(functions)
elapsed = time.time() - start

print(f'\\n[4] Analysis completed in {elapsed:.1f} seconds')

print('\\n[5] Generating combined report...')
report = analyzer.generate_combined_report(results, 'parallel_report.json')

print('\\n' + '='*60)
print('RESULTS SUMMARY')
print('='*60)
print(f\"Functions analyzed: {report['summary']['functions_analyzed']}\")
print(f\"Total issues found: {report['summary']['total_issues']}\")
print(f\"Time taken: {elapsed:.1f}s\")

by_sev = report.get('issues_by_severity', {})
print(f\"\\nBy severity:\")
print(f\"  Critical: {len(by_sev.get('critical', []))}\")
print(f\"  High:     {len(by_sev.get('high', []))}\")
print(f\"  Medium:   {len(by_sev.get('medium', []))}\")
print(f\"  Low:      {len(by_sev.get('low', []))}\")

print('\\nDetailed issues:')
for i, issue in enumerate(report.get('issues', [])[:15], 1):
    print(f\"  {i}. [{issue.get('impact_level', '?').upper()}] {issue.get('subcategory', '?')} in {issue.get('function', '?')}\")
    desc = issue.get('description', '')
    print(f\"     {desc[:120]}...\")

print('\\n' + '='*60)
"

echo ""
echo "=== REPORT JSON ==="
cat parallel_report.json 2>/dev/null | head -150
