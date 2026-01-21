#!/usr/bin/env python3
"""
Debug libclang function extraction issue
"""
import logging
logging.basicConfig(level=logging.DEBUG)

from pathlib import Path
import os

try:
    from clang.cindex import Index, CursorKind, TranslationUnit

    project_root = Path('/app/test_c_project_multi')
    compile_db_path = project_root / 'compile_commands.json'

    print("=" * 70)
    print("LibClang Debug Analysis")
    print("=" * 70)

    print(f"\nProject root: {project_root}")
    print(f"Compile DB: {compile_db_path}")
    print(f"Compile DB exists: {compile_db_path.exists()}")

    from clang.cindex import CompilationDatabase
    build_dir = str(compile_db_path.parent)
    compdb = CompilationDatabase.fromDirectory(build_dir)
    cmds = compdb.getAllCompileCommands()
    
    print(f"\nFound {len(cmds)} compilation commands")

    index = Index.create()
    
    # Parse first file
    if cmds:
        cmd = cmds[0]
        src_file = os.path.realpath(cmd.filename)
        print(f"\n[Test File] {src_file}")
        print(f"  Exists: {os.path.isfile(src_file)}")
        
        args = list(cmd.arguments)[1:]
        cleaned_args = []
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg in ("-c", "-o"):
                skip_next = True
                continue
            cleaned_args.append(arg)
        
        print(f"  Args: {cleaned_args}")
        
        # Parse
        tu = index.parse(src_file, args=cleaned_args)
        
        print(f"\n  Parsing diagnostics:")
        for diag in tu.diagnostics:
            print(f"    {diag.severity}: {diag.spelling}")
        
        print(f"\n  Top-level cursors:")
        for i, child in enumerate(tu.cursor.get_children()):
            if i < 20:  # Limit output
                print(f"    {child.kind}: {child.spelling}")
                if child.kind == CursorKind.FUNCTION_DECL:
                    print(f"      Is definition: {child.is_definition()}")
                    if child.location.file:
                        print(f"      Location file: {child.location.file.name}")
                        print(f"      Realpath match: {os.path.realpath(child.location.file.name)}")
                        print(f"      Expected: {src_file}")
                        try:
                            same = os.path.samefile(child.location.file.name, src_file)
                            print(f"      samefile result: {same}")
                        except Exception as e:
                            print(f"      samefile ERROR: {e}")
        
        print(f"\n  Function definitions found:")
        func_count = 0
        for child in tu.cursor.get_children():
            if child.kind == CursorKind.FUNCTION_DECL and child.is_definition():
                if child.location.file:
                    try:
                        if os.path.samefile(child.location.file.name, src_file):
                            print(f"    ✓ {child.spelling}")
                            func_count += 1
                    except Exception as e:
                        print(f"    ✗ {child.spelling} (samefile failed: {e})")
        
        print(f"\n  Total functions extracted: {func_count}")

except ImportError:
    print("libclang not available")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
