"""
Code indexing and function locator for C projects.
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, unquote

from ..common.utils import extract_function_calls, normalize_path
from ..common.lsp_client import LSPClient

logger = logging.getLogger(__name__)


class CodeIndex:
    """
    Indexes C project to locate function implementations.
    Supports clangd via LSP or fallback regex parsing.
    """

    def __init__(
        self, 
        project_root: Path, 
        compile_commands_path: Optional[Path] = None, 
        backend: str = "clangd",
        source_root: Optional[Path] = None,
        indexing_config: Optional[Any] = None,
        priority_functions: Optional[List[str]] = None
    ):
        """Initialize code index."""
        self.project_root = Path(project_root).resolve()
        self.source_root = Path(source_root).resolve() if source_root else self.project_root
        self.compile_commands_path = compile_commands_path
        self._backend = backend
        self._indexing_config = indexing_config
        self._priority_functions = priority_functions or []
        self._function_index: Dict[str, Dict[str, Any]] = {}
        self._lsp_client: Optional[LSPClient] = None
        self._compile_commands_files: Optional[set[Path]] = self._load_compile_commands_files()

        if self._backend == "clangd" and compile_commands_path and compile_commands_path.exists():
            # Pointer to the directory containing compile_commands.json
            cdb_dir = compile_commands_path.parent
            clangd_path = self._indexing_config.clangd_path if self._indexing_config else "clangd"
            self._lsp_client = LSPClient(
                self.project_root, 
                clangd_path=clangd_path, 
                compile_commands_path=cdb_dir
            )
            if self._lsp_client.start():
                logger.info("Using clangd LSP for code indexing")
                
                # Prime the LSP: open subset of files to force indexing without OOM
                if not self._indexing_config or self._indexing_config.auto_prime:
                    prime_start = time.monotonic()
                    self._prime_lsp(self._priority_functions)
                    # Wait for initial indexing before building index
                    self._lsp_client.wait_for_indexing(timeout=900)
                    prime_duration = time.monotonic() - prime_start
                    logger.info("LSP priming completed in %.2f seconds.", prime_duration)
                else:
                    # Still wait for indexing to settle before building index
                    self._lsp_client.wait_for_indexing(timeout=900)
            else:
                logger.warning("Failed to start clangd, falling back to regex")
                self._backend = "regex"
        else:
            self._backend = "regex"

        self._build_index()

    def _load_compile_commands_files(self) -> Optional[set[Path]]:
        """Load compile_commands.json file paths for disambiguation."""
        if not self.compile_commands_path or not self.compile_commands_path.exists():
            return None
        try:
            raw_json = self.compile_commands_path.read_text(encoding="utf-8")
            data = json.loads(raw_json)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed to read compile commands file %s: %s", self.compile_commands_path, exc)
            return None

        if not isinstance(data, list):
            logger.warning("Unexpected compile commands format in %s", self.compile_commands_path)
            return None

        files: set[Path] = set()
        for entry in data:
            if not isinstance(entry, dict):
                continue
            file_value = entry.get("file")
            if not file_value:
                continue
            entry_path = Path(file_value)
            if not entry_path.is_absolute():
                directory = entry.get("directory")
                if directory:
                    entry_path = Path(directory) / entry_path
            try:
                files.add(entry_path.resolve())
            except OSError:
                continue
        return files or None

    def _prime_lsp(self, priority_funcs: Optional[List[str]] = None) -> None:
        """Send didOpen for a subset of project files to trigger indexing safely."""
        if not self._lsp_client:
            return
        
        limit = 100
        only_priority = False
        if self._indexing_config:
            limit = self._indexing_config.max_prime_files
            only_priority = getattr(self._indexing_config, 'only_prime_priority', False)

        c_files = list(self.source_root.rglob("*.c"))
        h_files = list(self.source_root.rglob("*.h"))
        all_files = c_files + h_files
        
        # Prioritize files containing entry functions
        if priority_funcs:
            priority_files = []
            other_files = []
            
            # Optimization: Use one big regex for all functions
            # Escaping function names just in case
            safe_funcs = [re.escape(f) for f in priority_funcs]
            combined_pattern = re.compile(rf"\b({'|'.join(safe_funcs)})\b\s*\(")
            
            logger.info(f"Scanning for {len(priority_funcs)} priority functions in {len(all_files)} files...")
            for f_path in all_files:
                found = False
                try:
                    with open(f_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        if combined_pattern.search(content):
                            priority_files.append(f_path)
                            found = True
                except:
                    pass
                if not found:
                    other_files.append(f_path)
            
            logger.info(f"Found {len(priority_files)} priority files.")
            
            if only_priority:
                all_files = priority_files
            else:
                all_files = priority_files + other_files

        if len(all_files) > limit:
            logger.info(f"Project too large ({len(all_files)} files), limiting LSP priming to {limit} files to prevent OOM.")
            all_files = all_files[:limit]
            
        logger.info(f"Priming LSP with {len(all_files)} files...")
        for file_path in all_files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                self._lsp_client.open_document(
                    file_path,
                    language_id="c" if file_path.suffix == ".c" else "cpp",
                    text=content,
                )
            except Exception as e:
                logger.debug(f"Failed to prime {file_path}: {e}")

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
            
            # Retry loop: clangd might take a few seconds to load the CDB even after 'settling'
            symbols = []
            for attempt in range(3):
                symbols = self._lsp_client.get_workspace_symbols("")
                if symbols:
                    break
                logger.debug(f"LSP workspace/symbol returned 0 results, retry {attempt+1}/3...")
                time.sleep(2)
            
            for sym in symbols:
                if sym.get("kind") == 12:  # Function
                    name = sym.get("name")
                    location = sym.get("location")
                    if location:
                        uri = location.get("uri")
                        file_path = self._uri_to_path(uri)
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
        # Regex fallback scanning using source_root
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

    def get_function_impl(
        self, func_name: str, max_lines: int = 500
    ) -> Optional[Dict[str, Any]]:
        """Get function implementation."""
        macro_result: Optional[Dict[str, Any]] = None
        # If not in index, try LSP workspace search if available
        if func_name not in self._function_index and self._backend == "clangd" and self._lsp_client:
            symbols = []
            # First attempt: standard workspace/symbol
            symbols = self._lsp_client.get_workspace_symbols(func_name)
            
            # If not found, try to find the file via regex and prime it on-demand
            if not symbols:
                logger.debug(f"Symbol '{func_name}' not found in LSP, trying regex fallback...")
                macro_result = self._find_macro_definition(func_name)
                if macro_result:
                    logger.info(f"Macro '{func_name}' found via regex, skipping LSP priming.")
                    return macro_result
                found_files = self._find_function_definition_files(func_name)
                
                if found_files:
                    logger.info(f"Found '{func_name}' in {len(found_files)} files via regex, priming on-demand...")
                    for f_path in found_files:
                        self._lsp_client.send_notification("textDocument/didOpen", {
                            "textDocument": {
                                "uri": f_path.as_uri(),
                                "languageId": "c",
                                "version": 1,
                                "text": f_path.read_text(errors="ignore")
                            }
                        })
                    # Give it a tiny bit of time to parse and retry
                    time.sleep(1)
                    symbols = self._lsp_client.get_workspace_symbols(func_name)

            for sym in symbols:
                if sym.get("name") == func_name and sym.get("kind") == 12:
                    location = sym.get("location")
                    if location:
                        file_path = self._uri_to_path(location["uri"])
                        range_data = location.get("range")
                        self._function_index[func_name] = {
                            "file": str(file_path),
                            "start_line": range_data["start"]["line"] + 1,
                            "end_line": range_data["end"]["line"] + 1,
                            "signature": func_name + "(...)",
                        }
                        break
        
        if func_name not in self._function_index:
            if not macro_result:
                macro_result = self._find_macro_definition(func_name)
            if macro_result:
                return macro_result
            logger.warning(f"Function '{func_name}' not found in index")
            return None

        func_info = self._function_index[func_name]
        file_path = Path(func_info["file"])

        # Refine range using documentSymbol if it's too short (common with workspace/symbol)
        if self._backend == "clangd" and self._lsp_client and func_info["start_line"] == func_info["end_line"]:
            try:
                doc_symbols = self._lsp_client.get_document_symbols(file_path)
                # Flat search and recursive search in children
                queue = list(doc_symbols)
                while queue:
                    sym = queue.pop(0)
                    if sym.get("name") == func_name and sym.get("kind") == 12:
                        range_data = sym.get("range")
                        if range_data:
                            func_info["start_line"] = range_data["start"]["line"] + 1
                            func_info["end_line"] = range_data["end"]["line"] + 1
                            break
                    if "children" in sym:
                        queue.extend(sym["children"])
            except Exception as e:
                logger.debug(f"Failed to refine range for {func_name}: {e}")

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
                "file": normalize_path(file_path, self.source_root),
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

    def _find_function_definition_files(self, func_name: str) -> List[Path]:
        """Find files containing a likely function implementation (not just a call)."""
        found_files = []
        func_pattern = re.compile(
            rf"^\s*(?:static\s+|inline\s+|extern\s+)?"
            rf"(?:[\w\s\*]+\s+)?{re.escape(func_name)}\s*\([^;{{}}]*\)\s*\{{",
            re.MULTILINE,
        )
        for ext in ["*.c", "*.cpp", "*.cc", "*.h", "*.hpp"]:
            for f_path in self.source_root.rglob(ext):
                try:
                    with open(f_path, "r", encoding="utf-8", errors="ignore") as f:
                        if func_pattern.search(f.read()):
                            found_files.append(f_path)
                except Exception:
                    continue
        return found_files

    def _find_macro_definition(self, macro_name: str, max_lines: int = 500) -> Optional[Dict[str, Any]]:
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
                    total_lines = len(code_lines)
                    if total_lines > max_lines:
                        logger.warning(
                            f"Macro '{macro_name}' has {total_lines} lines, truncating to {max_lines}"
                        )
                        code_lines = code_lines[:max_lines]
                        end_idx = start_idx + max_lines - 1

                    signature_match = signature_pattern.match(lines[start_idx])
                    params = signature_match.group("params") if signature_match else None
                    signature = f"#define {macro_name}{params or ''}"
                    code = "".join(code_lines)
                    callees = list(set(extract_function_calls(code)))

                    return {
                        "func_name": macro_name,
                        "file": normalize_path(file_path, self.source_root),
                        "start_line": start_idx + 1,
                        "end_line": end_idx + 1,
                        "code": code,
                        "callees": callees,
                        "signature": signature,
                        "truncated": total_lines > max_lines,
                        "is_macro": True,
                    }
        return None

    def get_definition(self, file_path: str, line: int, character: int) -> List[Dict[str, Any]]:
        """Find definition using LSP."""
        if self._backend != "clangd" or not self._lsp_client:
            return []
        
        full_path = self._resolve_file_path(file_path)
        defs = self._lsp_client.get_definition(full_path, line, character)
        results = []
        for d in defs:
            # Handle Location or LocationLink
            target_uri = d.get("uri") or d.get("targetUri")
            target_range = d.get("range") or d.get("targetRange")
            if target_uri and target_range:
                target_path = self._uri_to_path(target_uri)
                results.append({
                    "file": normalize_path(target_path, self.project_root),
                    "start_line": target_range["start"]["line"] + 1,
                    "start_char": target_range["start"]["character"],
                    "end_line": target_range["end"]["line"] + 1,
                    "end_char": target_range["end"]["character"],
                })
        return results

    def get_type_definition(self, file_path: str, line: int, character: int) -> List[Dict[str, Any]]:
        """Find type definition using LSP."""
        if self._backend != "clangd" or not self._lsp_client:
            return []

        full_path = self._resolve_file_path(file_path)
        defs = self._lsp_client.get_type_definition(full_path, line, character)
        results = []
        for d in defs:
            target_uri = d.get("uri") or d.get("targetUri")
            target_range = d.get("range") or d.get("targetRange")
            if target_uri and target_range:
                target_path = self._uri_to_path(target_uri)
                results.append({
                    "file": normalize_path(target_path, self.project_root),
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
        
        full_path = self._resolve_file_path(file_path)
        refs = self._lsp_client.get_references(full_path, line, character)
        results = []
        for r in refs:
            uri = r.get("uri")
            range_data = r.get("range")
            if uri and range_data:
                ref_path = self._uri_to_path(uri)
                results.append({
                    "file": normalize_path(ref_path, self.project_root),
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
        self, file_path: str, start_line: Optional[int], end_line: Optional[int]
    ) -> Optional[Dict[str, Any]]:
        """Get a snippet from a file."""
        full_path = self._resolve_file_path(file_path)

        if not full_path.exists():
            logger.warning(f"File not found: {file_path}")
            return None

        if full_path.is_dir():
            logger.warning(f"File path is a directory, not a file: {full_path}")
            return None

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            total_lines = len(lines)
            if total_lines == 0:
                return {
                    "file": self._normalize_path(full_path),
                    "start_line": 1,
                    "end_line": 0,
                    "code": "",
                }

            if start_line is None or start_line < 1:
                start_line = 1
            if end_line is None or end_line < 1:
                end_line = min(total_lines, start_line + 199)
            if end_line < start_line:
                end_line = min(total_lines, start_line + 199)

            start = max(0, start_line - 1)
            end = min(total_lines, end_line)
            code_lines = lines[start:end]
            code = "".join(code_lines)

            return {
                "file": self._normalize_path(full_path),
                "start_line": start_line,
                "end_line": end_line,
                "code": code,
            }
        except Exception as e:
            logger.error(f"Failed to read file snippet: {e}")
            return None

    def _uri_to_path(self, uri: str) -> Path:
        """Convert file URI (or path-like string) to Path safely."""
        parsed_uri = urlparse(uri)
        if parsed_uri.scheme == "file":
            path_str = unquote(parsed_uri.path)
        else:
            path_str = unquote(uri)

        if os.name == "nt":
            if path_str.startswith("/") and len(path_str) > 2 and path_str[2] == ":":
                path_str = path_str[1:]
            path_str = path_str.replace("/", "\\")

        return Path(path_str)

    def _resolve_file_path(self, file_path: str) -> Path:
        """Resolve file path against source_root first, then project_root."""
        path = Path(file_path)
        if path.is_absolute():
            if path.exists():
                return path
            resolved = self._find_alternative_file(path)
            return resolved or path

        source_candidate = self.source_root / file_path
        if source_candidate.exists():
            return source_candidate

        project_candidate = self.project_root / file_path
        if project_candidate.exists():
            return project_candidate

        resolved = self._find_alternative_file(path)
        return resolved or project_candidate

    def resolve_existing_file(self, file_path: str) -> Optional[Path]:
        """Resolve a file path and ensure it exists as a file."""
        resolved = self._resolve_file_path(file_path)
        if resolved.exists() and resolved.is_file():
            return resolved
        return None

    def _find_alternative_file(self, path: Path) -> Optional[Path]:
        """Attempt to resolve a missing file by searching the source tree."""
        roots = [self.source_root]
        if self.project_root not in roots:
            roots.append(self.project_root)

        matches: List[Path] = []
        for root in roots:
            matches.extend(root.rglob(path.name))
        matches = self._filter_matches_by_compile_commands(matches, path)
        if len(matches) == 1:
            logger.info(f"Resolved missing file '{path}' to '{matches[0]}'")
            return matches[0]
        if len(matches) > 1:
            logger.warning(f"Multiple matches for missing file '{path}': {len(matches)}")
            return None

        alt_matches: List[Path] = []
        stem = path.stem
        for ext in [".c", ".h", ".cpp", ".hpp", ".cc"]:
            for root in roots:
                alt_matches.extend(root.rglob(f"{stem}{ext}"))
        alt_matches = self._filter_matches_by_compile_commands(alt_matches, path)
        if len(alt_matches) == 1:
            logger.info(f"Resolved missing file '{path}' to '{alt_matches[0]}'")
            return alt_matches[0]
        if len(alt_matches) > 1:
            logger.warning(f"Multiple matches for missing file '{path}': {len(alt_matches)}")
        return None

    def _filter_matches_by_compile_commands(self, matches: List[Path], path: Path) -> List[Path]:
        """Filter candidate matches using compile_commands.json when available."""
        if not matches or not self._compile_commands_files:
            return matches
        filtered = []
        for candidate in matches:
            try:
                if candidate.resolve() in self._compile_commands_files:
                    filtered.append(candidate)
            except OSError:
                continue
        if filtered and len(filtered) != len(matches):
            logger.info(
                "Disambiguated '%s' via compile_commands.json: %d -> %d matches",
                path,
                len(matches),
                len(filtered),
            )
            return filtered
        return matches

    def _normalize_path(self, file_path: Path) -> str:
        """Normalize a path relative to source_root when possible."""
        try:
            return str(file_path.resolve().relative_to(self.source_root))
        except ValueError:
            return normalize_path(file_path, self.project_root)

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
