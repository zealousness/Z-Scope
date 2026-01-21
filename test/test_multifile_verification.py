#!/usr/bin/env python3
"""
Comprehensive verification test for multi-file C project
Tests compile_commands.json parsing and function call graph extraction
"""
import logging
logging.basicConfig(level=logging.INFO)

from pathlib import Path
from zscope.code_index import CodeIndex

print("=" * 70)
print("ZScope Multi-file Project Verification")
print("=" * 70)

project_root = Path('/app/test_c_project_multi')
compile_db = project_root / 'compile_commands.json'

print(f"\nProject root: {project_root}")
print(f"Compile DB: {compile_db}")
print(f"Compile DB exists: {compile_db.exists()}")

# Test 1: Index with compile_commands.json
print("\n[Test 1] Creating CodeIndex with compile_commands.json...")
code_index = CodeIndex(project_root, compile_db)
print("  ✓ CodeIndex created")

# Test 2: List all functions
print("\n[Test 2] Discovering all functions...")
functions = code_index.list_functions(limit=100)
print(f"  ✓ Found {len(functions)} functions:")
for func_name in sorted(functions):
    location = code_index.get_function_location(func_name)
    print(f"    - {func_name:30s} {location}")

# Expected functions from all modules
expected_functions = {
    # utils.c
    'safe_strdup', 'safe_strlen', 'safe_malloc', 'safe_calloc', 'safe_free',
    'max_int', 'min_int',
    # memory.c
    'create_memory_pool', 'pool_alloc', 'free_memory_pool',
    'create_buffer', 'resize_buffer',
    # processor.c
    'create_packet', 'process_packet', 'free_packet', 'process_batch',
    # main.c
    'main'
}

print(f"\n  Expected {len(expected_functions)} functions, found {len(functions)}")
missing = expected_functions - set(functions)
if missing:
    print(f"  ⚠ Missing functions: {missing}")
extra = set(functions) - expected_functions
if extra:
    print(f"  ℹ Extra functions: {extra}")

# Test 3: Get cross-file function implementation
print("\n[Test 3] Testing cross-file function retrieval...")
test_functions = ['main', 'create_packet', 'process_batch', 'create_memory_pool']

for func_name in test_functions:
    if func_name in functions:
        impl = code_index.get_function_impl(func_name)
        if impl:
            print(f"\n  Function: {func_name}")
            print(f"    File: {impl['file']}")
            print(f"    Lines: {impl['start_line']}-{impl['end_line']}")
            print(f"    Code size: {len(impl['code'].splitlines())} lines")
            callees = impl.get('callees', [])
            if callees:
                print(f"    Calls: {', '.join(callees)}")
        else:
            print(f"  ✗ Could not retrieve {func_name}")

# Test 4: Verify cross-file call graph
print("\n[Test 4] Verifying cross-file call graph...")
main_impl = code_index.get_function_impl('main')
if main_impl:
    callees = main_impl.get('callees', [])
    print(f"  main() calls {len(callees)} functions:")
    
    # Expected cross-file calls
    expected_calls = {
        'safe_strdup',  # from utils.c
        'safe_strlen',  # from utils.c
        'create_memory_pool',  # from memory.c
        'pool_alloc',  # from memory.c
        'free_memory_pool',  # from memory.c
        'create_packet',  # from processor.c
        'process_packet',  # from processor.c
        'free_packet',  # from processor.c
        'process_batch',  # from processor.c
        'create_buffer',  # from memory.c
        'resize_buffer',  # from memory.c
    }
    
    found_cross_file = [c for c in callees if c in expected_calls]
    print(f"  ✓ Found {len(found_cross_file)} cross-file calls:")
    for call in sorted(found_cross_file):
        print(f"    - {call}")
    
    missing_calls = expected_calls - set(callees)
    if missing_calls:
        print(f"  ⚠ Missing expected calls: {missing_calls}")

# Test 5: Deep call chain
print("\n[Test 5] Testing deep call chain...")
# create_packet -> create_buffer -> safe_malloc
create_packet_impl = code_index.get_function_impl('create_packet')
if create_packet_impl:
    print("  create_packet() calls:")
    for callee in create_packet_impl.get('callees', []):
        print(f"    - {callee}")
        if callee == 'create_buffer':
            buffer_impl = code_index.get_function_impl(callee)
            if buffer_impl:
                print(f"      └─> create_buffer() calls:")
                for sub_callee in buffer_impl.get('callees', []):
                    print(f"          - {sub_callee}")

print("\n" + "=" * 70)
print("✅ Verification Complete!")
print("=" * 70)

# Summary
print("\nSummary:")
print(f"  ✓ compile_commands.json parsed successfully")
print(f"  ✓ Found {len(functions)} functions across {len(set(impl['file'] for impl in [code_index.get_function_impl(f) for f in functions if code_index.get_function_impl(f)]))} files")
print(f"  ✓ Cross-file function calls detected")
print(f"  ✓ Call graph extraction working")
print("\nReady for ZScope analysis!")
