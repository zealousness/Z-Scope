#!/usr/bin/env python
"""Test script for extract_json_blocks."""

import sys
sys.path.insert(0, r"c:\Users\10273\home\work\Z-Scope\zscope")

from zscope.common.utils import extract_json_blocks, is_valid_report

# Test cases
test_cases = [
    # Simple JSON
    '{"type": "final_report", "issues": []}',
    
    # JSON with thinking tags (common in local LLMs)
    '<think>Let me analyze this...</think>\n{"type": "final_report", "issues": []}',
    
    # JSON in markdown code block
    '```json\n{"type": "final_report", "issues": []}\n```',
    
    # Just issues key
    '{"issues": [{"id": "ISSUE_1"}]}',
    
    # Nested in wrapper
    '{"final_report": {"issues": []}}',
]

for i, text in enumerate(test_cases):
    print(f"Test {i+1}: {text[:50]}...")
    blocks = extract_json_blocks(text)
    print(f"  Found {len(blocks)} blocks")
    for b in blocks:
        print(f"  is_valid_report: {is_valid_report(b)}, keys: {list(b.keys())}")
    print()
