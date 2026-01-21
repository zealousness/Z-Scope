"""
Code indexing and function locator for C projects.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

from ..common.utils import extract_function_calls, normalize_path

logger = logging.getLogger(__name__)


class CodeIndex:
    """
    Indexes C project to locate function implementations.
    Supports compile_commands.json + libclang or fallback regex parsing.
    """

    def __init__(self, project_root: Path, compile_commands_path: Optional[Path] = None):
        """Initialize code index."""
        self.project_root = Path(project_root).resolve()
        self.compile_commands_path = compile_commands_path
        self._function_index: Dict[str, Dict[str, Any]] = {}
        self._use_clang = False

        # Try to initialize libclang if available
        if compile_commands_path and compile_commands_path.exists():
            try:
                import clang.cindex

                self._use_clang = True
                self._clang = clang.cindex
                logger.info("Using libclang for code indexing")
            except ImportError:
                logger.warning("libclang not available, using regex fallback")

        self._build_index()

    def _build_index(self) -> None:
        """Build function index from project."""
        if self._use_clang:
            self._build_index_clang()
        else:
            self._build_index_regex()

        logger.info(f"Indexed {len(self._function_index)} functions")

    def _build_index_clang(self) -> None:
        """Build index using libclang with CompilationDatabase API."""
        try:
            # Use CompilationDatabase API for more robust parsing
            build_dir = str(self.compile_commands_path.parent)
            try:
                compdb = self._clang.CompilationDatabase.fromDirectory(build_dir)
            except Exception as e:
                logger.warning(f"Failed to open CompilationDatabase: {e}")
                raise

            cmds = compdb.getAllCompileCommands()
            logger.info(f"Found {len(cmds)} compilation commands")

            index = self._clang.Index.create()
            parsed_files = set()

            for cmd in cmds:
                # Get the compilation directory
                work_dir = cmd.directory
                
                # Get the source file path and resolve it relative to work_dir
                src_file_rel = cmd.filename
                
                # Resolve to absolute path
                if os.path.isabs(src_file_rel):
                    src_file = os.path.realpath(src_file_rel)
                else:
                    # File is relative to the compilation directory
                    src_file = os.path.realpath(os.path.join(work_dir, src_file_rel))
                
                logger.debug(f"Processing: {src_file_rel} -> {src_file}")
                
                # Skip if already parsed
                if src_file in parsed_files:
                    continue
                parsed_files.add(src_file)

                # Skip if file doesn't exist
                if not os.path.isfile(src_file):
                    logger.warning(f"Source file not found: {src_file}")
                    continue

                # Extract and clean compilation arguments
                # cmd.arguments returns a list like ['clang', '-c', 'file.c', '-o', 'file.o', ...]
                args = list(cmd.arguments)[1:]  # Skip the compiler executable
                
                cleaned_args = []
                skip_next = False
                for arg in args:
                    if skip_next:
                        skip_next = False
                        continue
                    # Remove -c and -o flags and their arguments
                    if arg in ("-c", "-o"):
                        skip_next = True
                        continue
                    # Skip source files and object files
                    if arg.endswith('.c') or arg.endswith('.cpp') or arg.endswith('.cc') or \
                       arg.endswith('.o') or arg.endswith('.obj'):
                        continue
                    # Keep all compiler flags (start with - or are paths)
                    cleaned_args.append(arg)

                # Add libclang's built-in system include path
                # This is needed to find stddef.h, limits.h, etc.
                try:
                    # Get clang's resource directory which contains system headers
                    clang_resource_dir = None
                    if hasattr(self._clang, 'conf') and hasattr(self._clang.conf, 'lib'):
                        # Try to get resource dir from clang binary
                        import subprocess
                        try:
                            result = subprocess.run(
                                ['clang', '-print-resource-dir'],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )
                            if result.returncode == 0:
                                clang_resource_dir = result.stdout.strip()
                        except:
                            pass
                    
                    if clang_resource_dir and os.path.isdir(clang_resource_dir):
                        include_dir = os.path.join(clang_resource_dir, 'include')
                        if os.path.isdir(include_dir):
                            cleaned_args.insert(0, f'-I{include_dir}')
                            logger.debug(f"Added clang resource include: {include_dir}")
                except Exception as e:
                    logger.debug(f"Could not determine clang resource dir: {e}")

                logger.debug(f"Parsing: {src_file}")
                try:
                    # Parse the translation unit
                    tu = index.parse(
                        src_file,
                        args=cleaned_args,
                        options=self._clang.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
                    )

                    # Check for parsing errors/warnings
                    diagnostics = list(tu.diagnostics)
                    errors = [d for d in diagnostics if d.severity >= self._clang.Diagnostic.Error]
                    warnings = [d for d in diagnostics if d.severity == self._clang.Diagnostic.Warning]
                    
                    # Extract functions and log what was found
                    funcs_before = len(self._function_index)
                    self._extract_functions_from_tu(tu, Path(src_file))
                    funcs_after = len(self._function_index)
                    funcs_found = funcs_after - funcs_before
                    
                    # Log parsing status based on results
                    if errors:
                        if funcs_found > 0:
                            # Has errors but still extracted functions - probably non-critical
                            logger.debug(
                                f"TU parsed with {len(errors)} error(s) but extracted "
                                f"{funcs_found} function(s) from {os.path.basename(src_file)}"
                            )
                        else:
                            # Has errors and no functions extracted - more serious
                            logger.warning(
                                f"TU parsing failed for {os.path.basename(src_file)}: "
                                f"{len(errors)} error(s), no functions extracted"
                            )
                            for err in errors[:2]:  # Show first 2 errors
                                logger.debug(f"  Error: {err.spelling}")
                    elif warnings:
                        logger.debug(f"TU parsed with {len(warnings)} warning(s) for {src_file}")
                        if funcs_found > 0:
                            logger.info(f"Extracted {funcs_found} function(s) from {os.path.basename(src_file)}")
                    else:
                        logger.debug(f"TU parsed successfully for {src_file}")
                        if funcs_found > 0:
                            logger.info(f"Extracted {funcs_found} function(s) from {os.path.basename(src_file)}")
                    
                    if funcs_found == 0:
                        logger.debug(f"No functions extracted from {src_file}")
                        
                except Exception as e:
                    logger.debug(f"Failed to parse {src_file}: {e}")
                    continue
                    
        except Exception as e:
            logger.warning(f"Clang indexing failed: {e}, falling back to regex")
            self._use_clang = False
            self._build_index_regex()

    def _extract_functions_from_tu(self, tu, file_path: Path) -> None:
        """
        Extract function definitions from translation unit.
        Only processes top-level function definitions (file scope).
        """
        from clang.cindex import CursorKind
        
        extracted_funcs = []
        
        # Iterate only over top-level children of the translation unit
        for child in tu.cursor.get_children():
            # Check if this is a function declaration/definition
            if child.kind == CursorKind.FUNCTION_DECL and child.is_definition():
                func_name = child.spelling
                extent = child.extent
                
                # Only index functions from the current source file
                # (not from included headers)
                if child.location.file and os.path.samefile(
                    child.location.file.name, str(file_path)
                ):
                    self._function_index[func_name] = {
                        "file": str(file_path),
                        "start_line": extent.start.line,
                        "end_line": extent.end.line,
                        "signature": child.displayname,
                    }
                    extracted_funcs.append(func_name)
        
        # Debug output of extracted functions
        if extracted_funcs:
            logger.debug(f"  Functions: {', '.join(extracted_funcs)}")

    def _build_index_regex(self) -> None:
        """Build index using regex pattern matching (fallback)."""
        # Find all .c and .h files
        c_files = list(self.project_root.rglob("*.c"))
        h_files = list(self.project_root.rglob("*.h"))
        all_files = c_files + h_files

        logger.info(f"Scanning {len(all_files)} C/H files with regex")

        for file_path in all_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                self._extract_functions_regex(file_path, content)
            except Exception as e:
                logger.debug(f"Failed to read {file_path}: {e}")

    def _extract_functions_regex(self, file_path: Path, content: str) -> None:
        """
        Extract function definitions using regex.
        Matches patterns like: return_type function_name(...) {
        """
        # Pattern to match function definitions
        # This is a simplified pattern and may not catch all cases
        pattern = r"""
            ^                                   # Start of line
            (?:static\s+|inline\s+|extern\s+)*  # Optional storage class
            (\w+(?:\s*\*)*)\s+                  # Return type (with optional *)
            (\w+)\s*                            # Function name
            \(([^)]*)\)\s*                      # Parameters
            \{                                   # Opening brace
        """

        lines = content.split("\n")
        in_function = False
        func_start = 0
        func_name = ""
        brace_count = 0

        for line_no, line in enumerate(lines, start=1):
            # Remove comments for matching
            clean_line = re.sub(r"//.*$", "", line)
            clean_line = re.sub(r"/\*.*?\*/", "", clean_line)

            # Try to match function start
            match = re.search(
                r"^(?:static\s+|inline\s+|extern\s+)?(\w+(?:\s*\*)*)\s+(\w+)\s*\([^)]*\)\s*\{",
                clean_line.strip(),
            )

            if match and not in_function:
                in_function = True
                func_start = line_no
                func_name = match.group(2)
                brace_count = clean_line.count("{") - clean_line.count("}")

            elif in_function:
                brace_count += clean_line.count("{") - clean_line.count("}")
                if brace_count == 0:
                    # Function end
                    self._function_index[func_name] = {
                        "file": str(file_path),
                        "start_line": func_start,
                        "end_line": line_no,
                        "signature": func_name + "(...)",  # Simplified
                    }
                    in_function = False

    def get_function_impl(
        self, func_name: str, max_lines: int = 500
    ) -> Optional[Dict[str, Any]]:
        """
        Get function implementation.

        Args:
            func_name: Function name to lookup
            max_lines: Maximum lines to return (truncate if larger)

        Returns:
            Dict with file, start_line, end_line, code, callees, signature
        """
        if func_name not in self._function_index:
            logger.warning(f"Function '{func_name}' not found in index")
            return None

        func_info = self._function_index[func_name]
        file_path = Path(func_info["file"])

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            start = func_info["start_line"] - 1
            end = func_info["end_line"]

            # Truncate if too long
            if end - start > max_lines:
                logger.warning(
                    f"Function '{func_name}' has {end - start} lines, truncating to {max_lines}"
                )
                end = start + max_lines

            code_lines = lines[start:end]
            code = "".join(code_lines)

            # Extract callees
            callees = list(set(extract_function_calls(code)))

            return {
                "func_name": func_name,
                "file": normalize_path(file_path, self.project_root),
                "start_line": func_info["start_line"],
                "end_line": min(func_info["end_line"], start + max_lines + 1),
                "code": code,
                "callees": callees,
                "signature": func_info.get("signature", f"{func_name}(...)"),
                "truncated": end - start > max_lines,
            }
        except Exception as e:
            logger.error(f"Failed to read function '{func_name}': {e}")
            return None

    def get_file_snippet(
        self, file_path: str, start_line: int, end_line: int
    ) -> Optional[Dict[str, Any]]:
        """
        Get a snippet from a file.

        Args:
            file_path: File path (relative to project root or absolute)
            start_line: Start line (1-indexed)
            end_line: End line (1-indexed, inclusive)

        Returns:
            Dict with file, start_line, end_line, code
        """
        # Try to resolve path
        if Path(file_path).is_absolute():
            full_path = Path(file_path)
        else:
            full_path = self.project_root / file_path

        if not full_path.exists():
            logger.warning(f"File not found: {file_path}")
            return None

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            start = max(0, start_line - 1)
            end = min(len(lines), end_line)
            code_lines = lines[start:end]
            code = "".join(code_lines)

            return {
                "file": normalize_path(full_path, self.project_root),
                "start_line": start_line,
                "end_line": end_line,
                "code": code,
            }
        except Exception as e:
            logger.error(f"Failed to read file snippet: {e}")
            return None

    def list_functions(self, prefix: Optional[str] = None, limit: int = 50) -> List[str]:
        """
        List known functions.

        Args:
            prefix: Optional prefix filter
            limit: Maximum number of results

        Returns:
            List of function names
        """
        funcs = list(self._function_index.keys())
        if prefix:
            funcs = [f for f in funcs if f.startswith(prefix)]
        return sorted(funcs)[:limit]

    def get_function_location(self, func_name: str) -> Optional[str]:
        """Get function location string (file:line-line)."""
        if func_name not in self._function_index:
            return None
        info = self._function_index[func_name]
        file_path = normalize_path(Path(info["file"]), self.project_root)
        return f"{file_path}:{info['start_line']}-{info['end_line']}"
