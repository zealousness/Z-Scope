"""
Code indexing and function locator for C projects.
Uses Joern CPG as the primary backend with regex fallback.
"""

import logging
import re
from pathlib import Path
from typing import Optional, Dict, Any, List

from ..common.utils import extract_function_calls, normalize_path
from ..common.joern_client import JoernClient

logger = logging.getLogger(__name__)


class CodeIndex:
    """
    Indexes C project to locate function implementations.
    Uses Joern CPG as primary backend with regex fallback.
    """

    def __init__(
        self,
        project_root: Path,
        compile_commands_path: Optional[Path] = None,
        source_root: Optional[Path] = None,
        indexing_config: Optional[Any] = None,
        priority_functions: Optional[List[str]] = None,
        wait_for_cpg: bool = True,
        joern_client: Optional[JoernClient] = None,
    ):
        self.project_root = Path(project_root).resolve()
        self.source_root = Path(source_root).resolve() if source_root else self.project_root
        self.compile_commands_path = compile_commands_path
        self._function_index: Dict[str, Dict[str, Any]] = {}
        self._joern: Optional[JoernClient] = joern_client
        self._index_ready = False

        if self._joern is None:
            backend = indexing_config.backend if indexing_config else "joern"
            if backend == "joern":
                cfg = indexing_config
                self._joern = JoernClient(
                    joern_path=cfg.joern_path if cfg else "joern",
                    host=cfg.joern_server_host if cfg else "127.0.0.1",
                    port=cfg.joern_server_port if cfg else 8080,
                    heap_size=cfg.joern_heap_size if cfg else "8g",
                )
                if self._joern.start_server():
                    cc_path = str(self.compile_commands_path) if self.compile_commands_path else None
                    if wait_for_cpg:
                        if not self._joern.import_cpg(str(self.source_root), str(self.project_root), cc_path):
                            logger.warning("Joern CPG import failed, falling back to regex")
                            self._joern.stop_server()
                            self._joern = None
                    else:
                        self._joern.import_cpg_async(str(self.source_root), str(self.project_root), cc_path)
                else:
                    logger.warning("Joern server failed to start, falling back to regex")
                    self._joern = None

        if wait_for_cpg:
            self._build_index()
            self._index_ready = True

    def ensure_index_ready(self, timeout: Optional[int] = None) -> bool:
        """Wait for CPG and build index. For non-blocking mode."""
        if self._index_ready:
            return True
        if self._joern and not self._joern.wait_for_cpg(timeout=timeout):
            logger.warning("CPG build failed or timed out, falling back to regex")
            self._joern.stop_server()
            self._joern = None
        self._build_index()
        self._index_ready = True
        return True

    @property
    def joern_client(self) -> Optional[JoernClient]:
        return self._joern

    def _build_index(self) -> None:
        """Build function index from project."""
        if self._joern:
            self._build_index_joern()
        else:
            self._build_index_regex()
        logger.info(f"Indexed {len(self._function_index)} functions")

    def _build_index_joern(self) -> None:
        """Build index using Joern CPG method nodes."""
        result = self._joern.query(
            'cpg.method.isExternal(false).map(m => Map('
            '"name" -> m.name, "filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1), '
            '"lineNumberEnd" -> m.lineNumberEnd.getOrElse(-1), '
            '"signature" -> m.signature'
            ')).l.toJson'
        )
        if not isinstance(result, list):
            logger.warning("Joern index query returned unexpected result, falling back to regex")
            self._build_index_regex()
            return
        for m in result:
            name = m.get("name", "")
            fname = m.get("filename", "")
            if not name or name.startswith("<") or not fname or fname.startswith("<"):
                continue
            self._function_index[name] = {
                "file": m.get("filename", ""),
                "start_line": m.get("lineNumber", -1),
                "end_line": m.get("lineNumberEnd", -1),
                "signature": m.get("signature", f"{name}(...)"),
            }

    def _build_index_regex(self) -> None:
        """Build index using regex pattern matching (fallback)."""
        all_files = []
        for ext in ["*.c", "*.cpp", "*.h", "*.hpp", "*.cc"]:
            all_files.extend(list(self.source_root.rglob(ext)))
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

    # ── Core retrieval methods ──

    def get_function_impl(self, func_name: str, max_lines: int = 500) -> Optional[Dict[str, Any]]:
        """Get function implementation."""
        # Try Joern lookup if not in index
        if func_name not in self._function_index and self._joern:
            m = self._joern.get_method(func_name)
            if m and m.get("filename"):
                self._function_index[func_name] = {
                    "file": m["filename"],
                    "start_line": m.get("lineNumber", -1),
                    "end_line": m.get("lineNumberEnd", -1),
                    "signature": m.get("signature", f"{func_name}(...)"),
                }

        indexed_file = self._function_index.get(func_name, {}).get("file", "")
        if not indexed_file or indexed_file.startswith("<"):
            macro_result = self._find_macro_definition(func_name)
            if macro_result:
                return macro_result
            logger.warning(f"Function '{func_name}' not found in index")
            return None

        func_info = self._function_index[func_name]
        file_path = self._resolve_file_path(func_info["file"])
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            start = func_info["start_line"] - 1
            end = func_info["end_line"]
            if end - start > max_lines:
                end = start + max_lines
            code_lines = lines[start:end]
            code = "".join(code_lines)

            # Get callees from Joern if available, else regex
            if self._joern:
                callee_data = self._joern.get_method_callees(func_name)
                callees = [c["name"] for c in callee_data if c.get("name")]
            else:
                callees = list(set(extract_function_calls(code)))

            return {
                "func_name": func_name,
                "file": normalize_path(file_path, self.source_root),
                "start_line": func_info["start_line"],
                "end_line": min(func_info["end_line"], start + max_lines + 1),
                "code": code,
                "callees": callees,
                "signature": func_info.get("signature", f"{func_name}(...)"),
                "truncated": (func_info["end_line"] - func_info["start_line"] + 1) > max_lines,
            }
        except Exception as e:
            logger.error(f"Failed to read function '{func_name}': {e}")
            return None

    def get_file_snippet(
        self, file_path: str, start_line: Optional[int], end_line: Optional[int]
    ) -> Optional[Dict[str, Any]]:
        """Get a snippet from a file."""
        full_path = self._resolve_file_path(file_path)
        if not full_path.exists() or full_path.is_dir():
            return None
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            total_lines = len(lines)
            if total_lines == 0:
                return {"file": self._normalize_path(full_path), "start_line": 1, "end_line": 0, "code": ""}
            if start_line is None or start_line < 1:
                start_line = 1
            if end_line is None or end_line < 1:
                end_line = min(total_lines, start_line + 199)
            if end_line < start_line:
                end_line = min(total_lines, start_line + 199)
            start = max(0, start_line - 1)
            end = min(total_lines, end_line)
            code = "".join(lines[start:end])
            return {"file": self._normalize_path(full_path), "start_line": start_line, "end_line": end_line, "code": code}
        except Exception as e:
            logger.error(f"Failed to read file snippet: {e}")
            return None

    def list_functions(self, pattern: Optional[str] = None, limit: int = 50) -> List[str]:
        """List known functions, optionally filtered by regex pattern."""
        funcs = list(self._function_index.keys())
        if pattern:
            try:
                pat = re.compile(pattern)
                funcs = [f for f in funcs if pat.search(f)]
            except re.error:
                funcs = [f for f in funcs if f.startswith(pattern)]
        return sorted(funcs)[:limit]

    # ── New Joern-powered methods ──

    def get_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get functions that call the given function."""
        if not self._joern:
            return []
        return self._joern.get_method_callers(func_name, limit=limit)

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Get functions called by the given function."""
        if not self._joern:
            return []
        return self._joern.get_method_callees(func_name, limit=limit)

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        """Get struct/union/enum definition and members."""
        if not self._joern:
            return None
        decl = self._joern.get_type_decl(type_name)
        if not decl:
            return None
        members = self._joern.get_type_members(type_name)
        decl["members"] = members
        return decl

    def get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        """Trace data flow from source parameter to sink."""
        if not self._joern:
            return []
        return self._joern.get_data_flow_to_sink(source_func, source_param, sink_pattern)

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """Find function pointer assignments/callback registrations."""
        if not self._joern:
            return []
        return self._joern.find_function_pointers(func_name)

    def get_header_declared_functions(self, header_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get functions declared in header files (public API)."""
        if self._joern:
            return self._get_header_funcs_joern(header_files)
        return self._get_header_funcs_regex(header_files)

    def _get_header_funcs_joern(self, header_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        filter_clause = '.filter(_.filename.matches(".*\\\\.h$"))'
        if header_files:
            patterns = "|".join(re.escape(h) for h in header_files)
            filter_clause = f'.filter(_.filename.matches(".*({patterns})"))'
        result = self._joern.query(
            f'cpg.method.isExternal(false){filter_clause}'
            '.map(m => Map("name" -> m.name, "filename" -> m.filename, '
            '"lineNumber" -> m.lineNumber.getOrElse(-1))).l.toJson'
        )
        if isinstance(result, list):
            return [r for r in result if r.get("name") and not r["name"].startswith("<")]
        return []

    def _get_header_funcs_regex(self, header_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        func_decl_re = re.compile(
            r"^\s*(?:extern\s+)?(?:\w+[\s*]+)+(\w+)\s*\([^)]*\)\s*;", re.MULTILINE
        )
        results = []
        globs = [f"*{h}" for h in header_files] if header_files else ["*.h", "*.hpp"]
        for pattern in globs:
            for fp in self.source_root.rglob(pattern):
                try:
                    content = fp.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for m in func_decl_re.finditer(content):
                    name = m.group(1)
                    if name in self._function_index:
                        results.append({
                            "name": name,
                            "filename": str(fp),
                            "lineNumber": content[:m.start()].count("\n") + 1,
                        })
        return results

    # ── Macro and path helpers ──

    def _find_macro_definition(
        self, macro_name: str, max_lines: int = 500
    ) -> Optional[Dict[str, Any]]:
        """Find a macro definition using regex scanning."""
        macro_pattern = re.compile(rf"^\s*#\s*define\s+{re.escape(macro_name)}\b")
        signature_pattern = re.compile(
            rf"^\s*#\s*define\s+{re.escape(macro_name)}(?P<params>\s*\([^)]*\))?"
        )
        for ext in ["*.h", "*.hpp", "*.ph", "*.inc", "*.c", "*.cpp", "*.cc"]:
            for file_path in self.source_root.rglob(ext):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue
                for idx, line in enumerate(lines):
                    if not macro_pattern.match(line):
                        continue
                    start_idx = idx
                    end_idx = idx
                    while lines[end_idx].rstrip().endswith("\\") and end_idx + 1 < len(lines):
                        end_idx += 1
                    code_lines = lines[start_idx : end_idx + 1]
                    if len(code_lines) > max_lines:
                        code_lines = code_lines[:max_lines]
                        end_idx = start_idx + max_lines - 1
                    signature_match = signature_pattern.match(lines[start_idx])
                    params = signature_match.group("params") if signature_match else None
                    code = "".join(code_lines)
                    callees = list(set(extract_function_calls(code)))
                    return {
                        "func_name": macro_name,
                        "file": normalize_path(file_path, self.source_root),
                        "start_line": start_idx + 1,
                        "end_line": end_idx + 1,
                        "code": code,
                        "callees": callees,
                        "signature": f"#define {macro_name}{params or ''}",
                        "truncated": len(lines[start_idx : end_idx + 1]) > max_lines,
                        "is_macro": True,
                    }
        return None

    def _resolve_file_path(self, file_path: str) -> Path:
        """Resolve file path against source_root first, then project_root."""
        path = Path(file_path)
        if path.is_absolute() and path.exists():
            return path
        source_candidate = self.source_root / file_path
        if source_candidate.exists():
            return source_candidate
        project_candidate = self.project_root / file_path
        if project_candidate.exists():
            return project_candidate
        return project_candidate

    def resolve_existing_file(self, file_path: str) -> Optional[Path]:
        """Resolve a file path and ensure it exists as a file."""
        resolved = self._resolve_file_path(file_path)
        if resolved.exists() and resolved.is_file():
            return resolved
        return None

    def _normalize_path(self, file_path: Path) -> str:
        """Normalize a path relative to source_root when possible."""
        try:
            return str(file_path.resolve().relative_to(self.source_root))
        except ValueError:
            return normalize_path(file_path, self.project_root)

    def get_function_location(self, func_name: str) -> Optional[str]:
        """Get function location string (file:line-line)."""
        if func_name not in self._function_index:
            return None
        info = self._function_index[func_name]
        resolved = self._resolve_file_path(info["file"])
        file_path = normalize_path(resolved, self.project_root)
        return f"{file_path}:{info['start_line']}-{info['end_line']}"

    def close(self):
        """Close Joern client."""
        if self._joern:
            self._joern.stop_server()
