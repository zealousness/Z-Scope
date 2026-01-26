"""
Code indexing and function locator for C projects.
"""

import logging
import os
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

from ..common.utils import extract_function_calls, normalize_path
from ..common.lsp_client import LSPClient

logger = logging.getLogger(__name__)


class CodeIndex:
    """
    Indexes C project to locate function implementations.
    Supports clangd via LSP or fallback regex parsing.
    """

    def __init__(self, project_root: Path, compile_commands_path: Optional[Path] = None, backend: str = "clangd"):
        """Initialize code index."""
        self.project_root = Path(project_root).resolve()
        self.compile_commands_path = compile_commands_path
        self._function_index: Dict[str, Dict[str, Any]] = {}
        self._backend = backend
        self._lsp_client: Optional[LSPClient] = None

        if self._backend == "clangd" and compile_commands_path and compile_commands_path.exists():
            self._lsp_client = LSPClient(self.project_root)
            if self._lsp_client.start():
                logger.info("Using clangd LSP for code indexing")
            else:
                logger.warning("Failed to start clangd, falling back to regex")
                self._backend = "regex"
        else:
            self._backend = "regex"

        self._build_index()

    def _build_index(self) -> None:
        """Build function index from project."""
        if self._backend == "clangd" and self._lsp_client:
            self._build_index_lsp()
        else:
            self._build_index_regex()

        logger.info(f"Indexed {len(self._function_index)} functions")

    def _build_index_lsp(self) -> None:
        """
        Build index using LSP workspace symbols.
        For very large projects, we don't necessarily need to pre-index everything
        if workspace/symbol is fast, but we'll do a basic pass for known functions.
        """
        try:
            # Query for all functions (empty query or generic one)
            # Many LSP servers return a limited set for empty query.
            # We'll use this to populate common functions.
            symbols = self._lsp_client.get_workspace_symbols("")
            for sym in symbols:
                if sym.get("kind") == 12:  # Function
                    name = sym.get("name")
                    location = sym.get("location")
                    if location:
                        uri = location.get("uri")
                        # Convert URI to path
                        # Robust URI to path conversion
                        from urllib.parse import urlparse, unquote
                        parsed_uri = urlparse(uri)
                        path_str = unquote(parsed_uri.path)
                        
                        # On Windows, urlparse might leave a leading slash on the path (e.g., /C:/...)
                        if os.name == 'nt' and path_str.startswith('/') and path_str[2:3] == ':':
                            path_str = path_str[1:].replace('/', '\\')
                        
                        file_path = Path(path_str)
                        range_data = location.get("range")
                        self._function_index[name] = {
                            "file": str(file_path),
                            "start_line": range_data["start"]["line"] + 1,
                            "end_line": range_data["end"]["line"] + 1,
                            "signature": name + "(...)",
                        }
        except Exception as e:
            logger.warning(f"LSP indexing failed: {e}, falling back to regex")
            self._backend = "regex"
            self._build_index_regex()

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
        """Extract function definitions using regex."""
        lines = content.split("\n")
        in_function = False
        func_start = 0
        func_name = ""
        brace_count = 0

        for line_no, line in enumerate(lines, start=1):
            clean_line = re.sub(r"//.*$", "", line)
            clean_line = re.sub(r"/\*.*?\*/", "", clean_line)

            match = re.search(
                r"^(?:static\s+|inline\s+|extern\s+)?(?:\w+(?:\s*\*)*)\s+(\w+)\s*\([^)]*\)\s*\{",
                clean_line.strip(),
            )

            if match and not in_function:
                in_function = True
                func_start = line_no
                func_name = match.group(1)
                brace_count = clean_line.count("{") - clean_line.count("}")

            elif in_function:
                brace_count += clean_line.count("{") - clean_line.count("}")
                if brace_count == 0:
                    self._function_index[func_name] = {
                        "file": str(file_path),
                        "start_line": func_start,
                        "end_line": line_no,
                        "signature": func_name + "(...)",
                    }
                    in_function = False

    def get_function_impl(
        self, func_name: str, max_lines: int = 500
    ) -> Optional[Dict[str, Any]]:
        """Get function implementation."""
        # If not in index, try LSP workspace search if available
        if func_name not in self._function_index and self._backend == "clangd" and self._lsp_client:
            symbols = self._lsp_client.get_workspace_symbols(func_name)
            for sym in symbols:
                if sym.get("name") == func_name and sym.get("kind") == 12:
                    location = sym.get("location")
                    if location:
                        from urllib.parse import unquote
                        import platform
                        path_str = unquote(location["uri"][8:])
                        if platform.system() == "Windows":
                            path_str = path_str.replace("/", "\\")
                        
                        file_path = Path(path_str)
                        # Now use Go to Definition for more precise location
                        # or just use the symbol range
                        range_data = location.get("range")
                        self._function_index[func_name] = {
                            "file": str(file_path),
                            "start_line": range_data["start"]["line"] + 1,
                            "end_line": range_data["end"]["line"] + 1,
                            "signature": func_name + "(...)",
                        }
                        break

        if func_name not in self._function_index:
            logger.warning(f"Function '{func_name}' not found in index")
            return None

        func_info = self._function_index[func_name]
        file_path = Path(func_info["file"])

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # If using LSP, we might need to broaden the range if only declaration was found
            # But clangd definition should give the full range.
            start = func_info["start_line"] - 1
            end = func_info["end_line"]

            if end - start > max_lines:
                logger.warning(
                    f"Function '{func_name}' has {end - start} lines, truncating to {max_lines}"
                )
                end = start + max_lines

            code_lines = lines[start:end]
            code = "".join(code_lines)
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

    def get_definition(self, file_path: str, line: int, character: int) -> List[Dict[str, Any]]:
        """Find definition using LSP."""
        if self._backend != "clangd" or not self._lsp_client:
            return []
        
        full_path = self.project_root / file_path
        defs = self._lsp_client.get_definition(full_path, line, character)
        results = []
        for d in defs:
            # Handle Location or LocationLink
            target_uri = d.get("uri") or d.get("targetUri")
            target_range = d.get("range") or d.get("targetRange")
            if target_uri and target_range:
                from urllib.parse import unquote
                import platform
                path_str = unquote(target_uri[8:])
                if platform.system() == "Windows":
                    path_str = path_str.replace("/", "\\")
                
                results.append({
                    "file": normalize_path(Path(path_str), self.project_root),
                    "start_line": target_range["start"]["line"] + 1,
                    "start_char": target_range["start"]["character"],
                    "end_line": target_range["end"]["line"] + 1,
                    "end_char": target_range["end"]["character"],
                })
        return results

    def get_references(self, file_path: str, line: int, character: int) -> List[Dict[str, Any]]:
        """Find references using LSP."""
        if self._backend != "clangd" or not self._lsp_client:
            return []
        
        full_path = self.project_root / file_path
        refs = self._lsp_client.get_references(full_path, line, character)
        results = []
        for r in refs:
            uri = r.get("uri")
            range_data = r.get("range")
            if uri and range_data:
                from urllib.parse import unquote
                import platform
                path_str = unquote(uri[8:])
                if platform.system() == "Windows":
                    path_str = path_str.replace("/", "\\")
                
                results.append({
                    "file": normalize_path(Path(path_str), self.project_root),
                    "line": range_data["start"]["line"] + 1,
                    "character": range_data["start"]["character"],
                })
        return results

    def get_hover_info(self, file_path: str, line: int, character: int) -> Optional[str]:
        """Get type info or documentation using LSP hover."""
        if self._backend != "clangd" or not self._lsp_client:
            return None
        
        full_path = self.project_root / file_path
        hover = self._lsp_client.get_hover(full_path, line, character)
        if hover and "contents" in hover:
            contents = hover["contents"]
            if isinstance(contents, dict) and "value" in contents:
                return contents["value"]
            if isinstance(contents, list):
                return "\n".join([c.get("value", str(c)) if isinstance(c, dict) else str(c) for c in contents])
            return str(contents)
        return None

    def get_file_snippet(
        self, file_path: str, start_line: int, end_line: int
    ) -> Optional[Dict[str, Any]]:
        """Get a snippet from a file."""
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
        """List known functions."""
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

    def close(self):
        """Close LSP client."""
        if self._lsp_client:
            self._lsp_client.stop()
