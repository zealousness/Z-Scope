#!/usr/bin/env python3
"""
Run ZScope and capture detailed output for analysis iteration
"""
import subprocess
import sys
import json
from pathlib import Path

iteration = sys.argv[1] if len(sys.argv) > 1 else "1"
print(f"\n{'='*80}")
print(f"ZSCOPE ANALYSIS - ITERATION {iteration}")
print('='*80)

# Run ZScope with detailed logging
result = subprocess.run(
    ['zscope', '--config', 'zscope_optimized.yaml'],
    cwd='/app/zscope/tests/cache_module',
    capture_output=True,
    text=True
)

# Save full output
output_file = f'/tmp/zscope_iteration_{iteration}.log'
with open(output_file, 'w') as f:
    f.write("=== STDOUT ===\n")
    f.write(result.stdout)
    f.write("\n\n=== STDERR ===\n")
    f.write(result.stderr)

print(f"\nFull log saved to: {output_file}")
print(f"Exit code: {result.returncode}\n")

# Extract key information
stdout_lines = result.stdout.split('\n')
stderr_lines = result.stderr.split('\n')

print("Key Events:")
print("-" * 80)

for line in stderr_lines:
    if'Indexed' in line or 'issues found' in line or 'Verdict' in line:
        print(f"  {line.strip()}")
    elif 'Tool call:' in line:
        print(f"  {line.strip()}")
    elif 'Conversation iteration' in line:
        print(f"  {line.strip()}")
    elif 'ERROR' in line or 'WARNING' in line:
        print(f"  {line.strip()}")

# Check for report files
report_json = Path('/app/zscope/tests/cache_module/report.json')
report_md = Path('/app/zscope/tests/cache_module/report.md')

print("\n" + "=" * 80)
if report_json.exists():
    print("✓ report.json generated")
    with open(report_json) as f:
        report = json.load(f)
    print(f"  Verdict: {report.get('overall_verdict')}")
    print(f"  Issues: {len(report.get('issues', []))}")
    if report.get('issues'):
        for i, issue in enumerate(report['issues'][:5]):
            print(f"\n  Issue #{i+1}:")
            print(f"    Category: {issue.get('category')}/{issue.get('subcategory')}")
            print(f"    Function: {issue.get('function')}")
            print(f"    Location: {issue.get('location')}")
            print(f"    Description: {issue.get('description', '')[:100]}...")
else:
    print("✗ report.json NOT generated")

if report_md.exists():
    print("\n✓ report.md generated")
else:
    print("✗ report.md NOT generated")

print("=" * 80)
sys.exit(result.returncode)
