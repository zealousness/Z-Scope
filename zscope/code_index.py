"""
Code indexing and function locator for C projects.
"""

import json
import logging
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

from .utils import extract_function_calls, normalize_path

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
        """Build index using libclang (if available)."""
        try:
            # Load compile commands
            with open(self.compile_commands_path, "r") as f:
                compile_commands = json.load(f)

            index = self._clang.Index.create()

            for entry in compile_commands:
                file_path = Path(entry["file"])
                if not file_path.exists():
                    continue

                try:
                    tu = index.parse(
                        str(file_path),
                        args=entry.get("arguments", []),
                        options=self._clang.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES,
                    )

                    self._extract_functions_from_tu(tu, file_path)
                except Exception as e:
                    logger.debug(f"Failed to parse {file_path}: {e}")
                    continue
        except Exception as e:
            logger.warning(f"Clang indexing failed: {e}, falling back to regex")
            self._use_clang = False
            self._build_index_regex()

    def _extract_functions_from_tu(self, tu, file_path: Path) -> None:
        """Extract function definitions from translation unit."""

        def visit_node(node):
            if node.kind == self._clang.CursorKind.FUNCTION_DECL:
                if node.is_definition():
                    func_name = node.spelling
                    location = node.location
                    extent = node.extent

                    self._function_index[func_name] = {
                        "file": str(file_path),
                        "start_line": extent.start.line,
                        "end_line": extent.end.line,
                        "signature": node.displayname,
                    }

            for child in node.get_children():
                visit_node(child)

        visit_node(tu.cursor)

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
