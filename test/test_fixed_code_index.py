#!/usr/bin/env python3
"""
Test the fixed code_index.py directly
"""
import logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')

from pathlib import Path
import sys
sys.path.insert(0, '/app')  # Use installed zscope

from zscope.code_index import CodeIndex

print("=" * 70)
print("Testing FIXED CodeIndex")
print("=" * 70)

project_root = Path('/app/test_c_project_multi')
compile_db = project_root / 'compile_commands.json'

print(f"\nProject: {project_root}")
print(f"Compile DB: {compile_db}")
print(f"Exists: {compile_db.exists()}\n")

# Create index
print("[Creating CodeIndex with libclang...]")
code_index = CodeIndex(project_root, compile_db)

# List functions
functions = code_index.list_functions(limit=100)
print(f"\n[Results]")
print(f"Functions found: {len(functions)}")

if functions:
    print("\nFunction list:")
    for func in sorted(functions):
        loc = code_index.get_function_location(func)
        print(f"  - {func:30s} {loc}")
else:
    print("  ⚠ No functions found!")
    print("\n  This suggests:")
    print("    1. compile_commands.json path resolution still has issues")
    print("    2. OR libclang parsing is failing")
    print("    3. OR function extraction logic has a bug")

sys.exit(0 if len(functions) > 0 else 1)
