#!/usr/bin/env python3
"""
Comprehensive libclang debugging for cache module
"""
import os
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

try:
    from clang.cindex import Index, CursorKind, TranslationUnit, CompilationDatabase
except ImportError:
    print("ERROR: libclang not available")
    sys.exit(1)

print("=" * 80)
print("LIBCLANG CACHE MODULE DEBUG")
print("=" * 80)

# Setup paths
project_root = Path('/app/zscope/tests/cache_module')
compile_db_path = project_root / 'compile_commands.json'

print(f"\n[1] Environment Check")
print(f"  Project root: {project_root}")
print(f"  Exists: {project_root.exists()}")
print(f"  Compile DB: {compile_db_path}")
print(f"  Exists: {compile_db_path.exists()}")

# Read compile_commands.json
print(f"\n[2] Compilation Database Content")
import json
with open(compile_db_path) as f:
    compile_cmds = json.load(f)
    print(f"  Entries: {len(compile_cmds)}")
    for i, entry in enumerate(compile_cmds):
        print(f"\n  Entry {i}:")
        print(f"    directory: {entry.get('directory')}")
        print(f"    file: {entry.get('file')}")
        print(f"    command: {entry.get('command')}")

# Load compilation database
print(f"\n[3] Loading CompilationDatabase")
build_dir = str(compile_db_path.parent)
print(f"  Build dir: {build_dir}")

try:
    compdb = CompilationDatabase.fromDirectory(build_dir)
    print(f"  ✓ CompilationDatabase loaded")
except Exception as e:
    print(f"  ✗ Failed: {e}")
    sys.exit(1)

# Get all compile commands
cmds = compdb.getAllCompileCommands()
print(f"  Commands found: {len(cmds)}")

# Process first command in detail
if not cmds:
    print("  ✗ No commands found!")
    sys.exit(1)

print(f"\n[4] Processing First Command in Detail")
cmd = cmds[0]

print(f"  Working directory: {cmd.directory}")
print(f"  Filename (raw): {cmd.filename}")

# Resolve file path
work_dir = cmd.directory
src_file_rel = cmd.filename

if os.path.isabs(src_file_rel):
    src_file = os.path.realpath(src_file_rel)
else:
    src_file = os.path.realpath(os.path.join(work_dir, src_file_rel))

print(f"  Resolved path: {src_file}")
print(f"  File exists: {os.path.isfile(src_file)}")

if not os.path.isfile(src_file):
    print(f"\n  ✗ ERROR: File not found at resolved path!")
    print(f"  Let's check what files actually exist:")
    src_dir = os.path.join(work_dir, 'src')
    if os.path.isdir(src_dir):
        print(f"\n  Files in {src_dir}:")
        for f in os.listdir(src_dir):
            print(f"    - {f}")
    sys.exit(1)

# Extract compilation arguments
print(f"\n[5] Compilation Arguments")
args_list = list(cmd.arguments)
print(f"  Raw arguments: {args_list}")

# Clean arguments (remove compiler and -c/-o flags)
cleaned_args = []
skip_next = False
for arg in args_list[1:]:  # Skip compiler
    if skip_next:
        skip_next = False
        continue
    if arg in ("-c", "-o"):
        skip_next = True
        continue
    cleaned_args.append(arg)

print(f"  Cleaned arguments: {cleaned_args}")

# Try parsing with libclang
print(f"\n[6] Parsing Translation Unit")
index = Index.create()

try:
    tu = index.parse(
        src_file,
        args=cleaned_args,
        options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    )
    print(f"  ✓ Translation unit created")
except Exception as e:
    print(f"  ✗ Parsing failed: {e}")
    sys.exit(1)

# Check diagnostics
print(f"\n[7] Diagnostics")
diagnostics = list(tu.diagnostics)
print(f"  Total diagnostics: {len(diagnostics)}")

if diagnostics:
    for i, diag in enumerate(diagnostics[:10]):  # Show first 10
        severity_names = {0: 'IGNORED', 1: 'NOTE', 2: 'WARNING', 3: 'ERROR', 4: 'FATAL'}
        severity = severity_names.get(diag.severity, str(diag.severity))
        print(f"  [{i}] {severity}: {diag.spelling}")
        if diag.location.file:
            print(f"      at {diag.location.file.name}:{diag.location.line}")

# Count errors
errors = [d for d in diagnostics if d.severity >= 3]  # ERROR or FATAL
warnings = [d for d in diagnostics if d.severity == 2]
print(f"\n  Summary: {len(errors)} errors, {len(warnings)} warnings")

# Examine translation unit cursor
print(f"\n[8] Translation Unit Structure")
print(f"  TU cursor kind: {tu.cursor.kind}")
print(f"  TU cursor spelling: {tu.cursor.spelling}")

# List top-level children
print(f"\n[9] Top-Level Cursors (first 30)")
children = list(tu.cursor.get_children())
print(f"  Total children: {len(children)}")

for i, child in enumerate(children[:30]):
    location_info = ""
    if child.location.file:
        location_info = f" @ {os.path.basename(child.location.file.name)}:{child.location.line}"
    
    print(f"  [{i}] {child.kind.name}: {child.spelling}{location_info}")
    
    if child.kind == CursorKind.FUNCTION_DECL:
        print(f"       -> is_definition: {child.is_definition()}")
        print(f"       -> extent: {child.extent.start.line}-{child.extent.end.line}")

# Count function declarations
print(f"\n[10] Function Analysis")
all_func_decls = [c for c in children if c.kind == CursorKind.FUNCTION_DECL]
func_definitions = [c for c in all_func_decls if c.is_definition()]
func_declarations = [c for c in all_func_decls if not c.is_definition()]

print(f"  Total FUNCTION_DECL nodes: {len(all_func_decls)}")
print(f"  Definitions: {len(func_definitions)}")
print(f"  Declarations only: {len(func_declarations)}")

if func_definitions:
    print(f"\n  Function Definitions Found:")
    for func in func_definitions:
        file_info = "unknown"
        if func.location.file:
            file_info = os.path.basename(func.location.file.name)
        print(f"    - {func.spelling} @ {file_info}")
else:
    print(f"\n  ✗ NO FUNCTION DEFINITIONS FOUND!")
    print(f"  This is the problem - libclang isn't finding definitions")

# Check file filtering
print(f"\n[11] File Filtering Check")
print(f"  Target source file: {src_file}")

if func_definitions:
    for func in func_definitions:
        if func.location.file:
            func_file = func.location.file.name
            print(f"\n  Function: {func.spelling}")
            print(f"    Location file: {func_file}")
            print(f"    Target file: {src_file}")
            
            try:
                same = os.path.samefile(func_file, src_file)
                print(f"    samefile(): {same}")
            except Exception as e:
                print(f"    samefile() ERROR: {e}")

print(f"\n" + "=" * 80)
print("DEBUG COMPLETE")
print("=" * 80)
