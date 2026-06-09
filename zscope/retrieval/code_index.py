"""
Code indexing and function locator for C projects.
Supports pluggable backends (Joern / Clang-SQLite / regex fallback).
"""

import logging
import os
import re
import threading
from pathlib import Path
from typing import Optional, Dict, Any, Iterable, List, Sequence, Union, Tuple

from ..common.utils import (
    extract_function_calls,
    is_likely_function_call_identifier,
    normalize_path,
)
from .backend_base import CodeBackend

logger = logging.getLogger(__name__)

DECLARATION_LINE_RE = re.compile(
    r"^[ \t]*(?!(?:return|if|while|for|switch)\b)"
    r"(?:[A-Za-z_]\w*[\s*]+)+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;"
)


class CodeIndex:
    """
    Indexes C project to locate function implementations.
    Delegates backend-specific queries to a pluggable CodeBackend.
    """

    def __init__(
        self,
        project_root: Path,
        compile_commands_path: Optional[Path] = None,
        source_root: Optional[Path] = None,
        indexing_config: Optional[Any] = None,
        priority_functions: Optional[List[str]] = None,
        wait_for_cpg: bool = True,
        backend: Optional[CodeBackend] = None,
        # 向后兼容：仍接受 joern_client 参数
        joern_client: Optional[Any] = None,
        include_paths: Optional[Sequence[Union[str, Path]]] = None,
        exclude_paths: Optional[Sequence[Union[str, Path]]] = None,
        svf_entry_functions: Optional[Sequence[Any]] = None,
        defer_svf: bool = False,
        svf_parallel_workers: int = 1,
    ):
        self.project_root = Path(project_root).absolute()
        self.source_root = Path(source_root).absolute() if source_root else self.project_root
        self.compile_commands_path = compile_commands_path
        self.include_paths = [Path(p).absolute() for p in (include_paths or [])]
        self.exclude_paths = [Path(p).absolute() for p in (exclude_paths or [])]
        self.backend_name = indexing_config.backend if indexing_config else "joern"
        self._function_index: Dict[str, Dict[str, Any]] = {}
        self._function_alias_index: Dict[str, str] = {}
        self._ambiguous_function_aliases: set[str] = set()
        self._function_file_index: Dict[str, set[str]] = {}
        self._function_file_resolution_cache: Dict[Tuple[str, str], str] = {}
        self._declaration_comment_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._backend: Optional[CodeBackend] = backend
        self._svf_entry_functions = list(svf_entry_functions or [])
        self._defer_svf = defer_svf
        self._svf_parallel_workers = max(1, int(svf_parallel_workers or 1))
        self._index_ready = False
        self._cache_lock = threading.RLock()
        self._declaration_comment_index_lock = threading.Lock()
        self._macro_definition_index_lock = threading.Lock()
        self._file_lines_cache: Dict[str, Tuple[str, ...]] = {}
        self._function_impl_cache: Dict[Tuple[str, int, bool], Dict[str, Any]] = {}
        self._macro_definition_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._macro_definition_miss_cache: set[str] = set()

        # 向后兼容：如果传入了 joern_client，包装为 JoernBackend
        if self._backend is None and joern_client is not None:
            from .joern_backend import JoernBackend
            self._backend = JoernBackend(joern_client=joern_client)
            self._backend._status = "ready"

        # 根据配置自动创建后端
        if self._backend is None:
            self._backend = self._create_backend(indexing_config, wait_for_cpg)

        if wait_for_cpg:
            self._build_index()
            self._index_ready = True

    def _create_backend(self, indexing_config, wait_for_cpg: bool) -> Optional[CodeBackend]:
        """根据 indexing_config 创建对应的后端实例。"""
        backend_name = indexing_config.backend if indexing_config else "joern"

        if backend_name == "joern":
            from .joern_backend import JoernBackend
            cfg = indexing_config
            jb = JoernBackend(
                joern_path=cfg.joern_path if cfg else "joern",
                host=cfg.joern_server_host if cfg else "127.0.0.1",
                port=cfg.joern_server_port if cfg else 8080,
                heap_size=cfg.joern_heap_size if cfg else "8g",
            )
            cc_path = str(self.compile_commands_path) if self.compile_commands_path else None
            ok = jb.initialize(
                str(self.source_root),
                project_root=self.project_root,
                compile_commands_path=cc_path,
                wait=wait_for_cpg,
                include_paths=self.include_paths,
                exclude_paths=self.exclude_paths,
            )
            if not ok and wait_for_cpg:
                logger.warning("Backend initialization failed, falling back to regex")
                return None
            return jb

        if backend_name == "clang":
            from .clang_backend import ClangBackend
            cfg = indexing_config
            cb = ClangBackend(
                clangd_path=cfg.clangd_path if cfg else "clangd",
                db_path=cfg.knowledge_db_path if cfg else ".zscope_knowledge/code_knowledge.db",
                batch_size=cfg.batch_size if cfg else 50,
                max_threads=cfg.max_clangd_threads if cfg else 8,
            )
            cc_path = str(self.compile_commands_path) if self.compile_commands_path else None
            ok = cb.initialize(
                str(self.source_root),
                project_root=self.project_root,
                compile_commands_path=cc_path,
                wait=wait_for_cpg,
                include_paths=self.include_paths,
                exclude_paths=self.exclude_paths,
            )
            if not ok and wait_for_cpg:
                logger.warning("Clang backend initialization failed, falling back to regex")
                return None
            return cb

        if backend_name == "unified":
            from .unified_backend import UnifiedBackend
            cfg = indexing_config
            ub = UnifiedBackend(
                clangd_path=cfg.clangd_path if cfg else "clangd",
                db_path=cfg.knowledge_db_path if cfg else ".zscope_knowledge/code_knowledge.db",
                batch_size=cfg.batch_size if cfg else 50,
                max_threads=cfg.max_clangd_threads if cfg else 8,
                svf_bin_dir=cfg.svf_bin_dir if cfg else "",
                gclang_path=cfg.gclang_path if cfg else "gclang",
                get_bc_path=cfg.get_bc_path if cfg else "get-bc",
                llvm_link_path=cfg.llvm_link_path if cfg else "llvm-link",
                svf_heap_limit_mb=cfg.svf_heap_limit_mb if cfg else 32768,
                svf_timeout=cfg.svf_timeout if cfg else 1800,
                svf_groups_config=cfg.svf_groups_config if cfg else "",
                svf_scope=cfg.svf_scope if cfg else "auto",
                svf_entry_depth=cfg.svf_entry_depth if cfg else 4,
                svf_max_selected_tus=cfg.svf_max_selected_tus if cfg else 200,
                svf_fallback=cfg.svf_fallback if cfg else "full",
                svf_always_include=cfg.svf_always_include if cfg else [],
                svf_symbol_closure=cfg.svf_symbol_closure if cfg else True,
                svf_exclusive_pools=cfg.svf_exclusive_pools if cfg else [],
                svf_shared_pools=cfg.svf_shared_pools if cfg else [],
                svf_parallel_workers=self._svf_parallel_workers,
            )
            cc_path = str(self.compile_commands_path) if self.compile_commands_path else None
            ok = ub.initialize(
                str(self.source_root),
                project_root=self.project_root,
                compile_commands_path=cc_path,
                wait=wait_for_cpg,
                include_paths=self.include_paths,
                exclude_paths=self.exclude_paths,
                svf_entry_functions=self._svf_entry_functions,
                defer_svf=self._defer_svf,
            )
            if not ok and wait_for_cpg:
                logger.warning("Unified backend init failed, falling back to regex")
                return None
            return ub

        # regex 模式不需要后端
        return None

    def ensure_index_ready(self, timeout: Optional[int] = None) -> bool:
        """Wait for backend and build index. For non-blocking mode."""
        if self._index_ready:
            return True
        if self._backend and hasattr(self._backend, "wait_for_ready"):
            if not self._backend.wait_for_ready(timeout=timeout):
                logger.warning("Backend build failed or timed out, falling back to regex")
                self._backend.close()
                self._backend = None
        self._build_index()
        self._index_ready = True
        return True

    def run_svf(self, entry_functions: Optional[Sequence[Any]] = None) -> bool:
        """Run deferred SVF enrichment when the active backend supports it."""
        if not self._backend or not hasattr(self._backend, "run_svf"):
            return False
        entries = list(entry_functions or self._svf_entry_functions)
        self._svf_entry_functions = entries
        ok = bool(getattr(self._backend, "run_svf")(entry_functions=entries))
        if ok:
            self._clear_function_impl_cache()
        return ok

    @property
    def backend(self) -> Optional[CodeBackend]:
        """当前活跃的后端实例。"""
        return self._backend

    @property
    def joern_client(self) -> Optional[Any]:
        """向后兼容：返回 JoernClient（仅 Joern 后端可用）。"""
        from .joern_backend import JoernBackend
        if isinstance(self._backend, JoernBackend):
            return self._backend.joern_client
        return None

    def _build_index(self) -> None:
        """Build function index from project."""
        with self._cache_lock:
            self._function_index.clear()
            self._function_alias_index.clear()
            self._ambiguous_function_aliases.clear()
            self._function_file_index.clear()
            self._function_file_resolution_cache.clear()

        if self._backend:
            backend_index = self._backend.build_function_index()
            if backend_index:
                for raw_name, raw_info in backend_index.items():
                    self._add_function_index_entry(str(raw_name), dict(raw_info or {}))
            else:
                logger.warning("Backend index returned empty, falling back to regex")
                self._build_index_regex()
        else:
            self._build_index_regex()
        self._clear_function_impl_cache()
        logger.info(f"Indexed {len(self._function_index)} functions")

    def _add_function_index_entry(
        self,
        name: str,
        info: Dict[str, Any],
        aliases: Optional[Iterable[str]] = None,
    ) -> str:
        """Store one function record under a stable canonical key plus safe aliases."""
        raw_name = str(info.get("name") or name or "").strip()
        canonical_name = self._normalize_cpp_function_name(raw_name)
        if not canonical_name:
            return ""

        record = dict(info)
        record["name"] = raw_name
        record["qualified_name"] = canonical_name

        signature = str(record.get("signature") or f"{canonical_name}(...)")
        record["signature"] = signature
        params = record.get("params")
        if params is None:
            params = self._extract_signature_params(signature)
        if params is not None:
            record["params"] = str(params)

        with self._cache_lock:
            index_key = self._unique_function_index_key(canonical_name, record)
            record["index_name"] = index_key
            self._function_index[index_key] = record
            self._register_function_file_index(index_key, record)
            self._function_file_resolution_cache.clear()

            alias_candidates: set[str] = {raw_name, canonical_name, index_key}
            alias_candidates.update(str(alias or "") for alias in (aliases or []))

            stripped_canonical = self._strip_cpp_template_args(canonical_name)
            if stripped_canonical and stripped_canonical != canonical_name:
                alias_candidates.add(stripped_canonical)

            if "::" in canonical_name:
                simple_name = self._cpp_simple_name(canonical_name)
                tail_name = self._cpp_tail_name(canonical_name, 2)
                alias_candidates.update({simple_name, tail_name})

            if params is not None:
                for alias in list(alias_candidates):
                    sig_alias = self._function_signature_key(alias, str(params))
                    if sig_alias:
                        alias_candidates.add(sig_alias)

            for alias in alias_candidates:
                self._register_function_alias(alias, index_key)

            return index_key

    def _unique_function_index_key(self, canonical_name: str, record: Dict[str, Any]) -> str:
        existing = self._function_index.get(canonical_name)
        if not existing or self._same_function_location(existing, record):
            return canonical_name

        params = record.get("params")
        signature_key = (
            self._function_signature_key(canonical_name, str(params))
            if params is not None
            else ""
        )
        if signature_key:
            existing_sig = self._function_index.get(signature_key)
            if not existing_sig or self._same_function_location(existing_sig, record):
                return signature_key

        file_part = str(record.get("file") or record.get("filename") or "").replace("\\", "/")
        line_part = str(record.get("start_line") or record.get("lineNumber") or "0")
        fallback = f"{canonical_name}@{file_part}:{line_part}"
        key = fallback
        suffix = 2
        while key in self._function_index and not self._same_function_location(
            self._function_index[key],
            record,
        ):
            key = f"{fallback}#{suffix}"
            suffix += 1
        return key

    @staticmethod
    def _same_function_location(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
        left_file = str(left.get("file") or left.get("filename") or "").replace("\\", "/")
        right_file = str(right.get("file") or right.get("filename") or "").replace("\\", "/")
        return (
            left_file == right_file
            and int(left.get("start_line") or left.get("lineNumber") or 0)
            == int(right.get("start_line") or right.get("lineNumber") or 0)
        )

    def _register_function_alias(self, alias: str, index_key: str) -> None:
        normalized = self._normalize_function_query(alias)
        if not normalized or normalized in self._function_index:
            return
        if normalized in self._ambiguous_function_aliases:
            return
        existing = self._function_alias_index.get(normalized)
        if existing and existing != index_key:
            self._function_alias_index.pop(normalized, None)
            self._ambiguous_function_aliases.add(normalized)
            return
        self._function_alias_index[normalized] = index_key

    def _resolve_function_name(self, func_name: str, file_path: str = "") -> str:
        if file_path:
            scoped_name = self._resolve_function_name_by_file(func_name, file_path)
            if scoped_name:
                return scoped_name
        for variant in self._function_query_variants(func_name):
            with self._cache_lock:
                if variant in self._function_index:
                    return variant
                alias = self._function_alias_index.get(variant)
                if alias:
                    return alias
        return func_name

    def _resolve_function_name_by_file(self, func_name: str, file_path: str) -> str:
        query_variants = set(self._function_query_variants(func_name))
        if not query_variants:
            return ""
        cache_key = self._function_file_resolution_cache_key(func_name, file_path)
        with self._cache_lock:
            if cache_key in self._function_file_resolution_cache:
                return self._function_file_resolution_cache[cache_key]

        records = self._function_records_for_file_hint(file_path)
        if not records:
            with self._cache_lock:
                records = [(key, dict(info)) for key, info in self._function_index.items()]

        result = self._resolve_function_match_from_records(query_variants, file_path, records)
        with self._cache_lock:
            self._function_file_resolution_cache[cache_key] = result
        return result

    def _resolve_function_match_from_records(
        self,
        query_variants: set[str],
        file_path: str,
        records: Sequence[Tuple[str, Dict[str, Any]]],
    ) -> str:
        matches: List[Tuple[str, Dict[str, Any]]] = []
        for key, info in records:
            if not self._record_matches_file_hint(info, file_path):
                continue
            record_variants = self._function_record_query_variants(key, info)
            if query_variants.intersection(record_variants):
                matches.append((key, info))
        if not matches:
            return ""
        matches.sort(
            key=lambda item: (
                0 if item[0] in query_variants else 1,
                str(item[1].get("file") or item[1].get("filename") or ""),
                int(item[1].get("start_line") or item[1].get("lineNumber") or 0),
                item[0],
            )
        )
        return matches[0][0]

    def _register_function_file_index(self, index_key: str, record: Dict[str, Any]) -> None:
        file_path = str(record.get("file") or record.get("filename") or "")
        for key in self._function_file_index_keys(file_path):
            self._function_file_index.setdefault(key, set()).add(index_key)

    def _function_records_for_file_hint(self, file_path: str) -> List[Tuple[str, Dict[str, Any]]]:
        candidate_keys: set[str] = set()
        with self._cache_lock:
            for key in self._function_file_index_keys(file_path):
                candidate_keys.update(self._function_file_index.get(key, set()))
            return [
                (key, dict(self._function_index[key]))
                for key in sorted(candidate_keys)
                if key in self._function_index
            ]

    def _function_file_resolution_cache_key(self, func_name: str, file_path: str) -> Tuple[str, str]:
        return (
            self._normalize_function_query(func_name),
            self._normalize_path_hint(file_path),
        )

    def _function_file_index_keys(self, file_path: str) -> List[str]:
        normalized = self._normalize_path_hint(file_path)
        if not normalized:
            return []
        keys = [f"path:{normalized}"]
        basename = normalized.rsplit("/", 1)[-1]
        if basename:
            keys.append(f"basename:{basename}")
        return keys

    @staticmethod
    def _normalize_path_hint(file_path: str) -> str:
        normalized = str(file_path or "").replace("\\", "/").strip().lstrip("./")
        normalized = re.sub(r"/+", "/", normalized)
        return normalized.lower() if os.name == "nt" else normalized

    def _function_record_query_variants(self, index_key: str, info: Dict[str, Any]) -> set[str]:
        values = {
            index_key,
            str(info.get("index_name") or ""),
            str(info.get("name") or ""),
            str(info.get("qualified_name") or ""),
        }
        params = info.get("params")
        if params is not None:
            for name in list(values):
                signature_key = self._function_signature_key(name, str(params))
                if signature_key:
                    values.add(signature_key)
        variants: set[str] = set()
        for value in values:
            variants.update(self._function_query_variants(value))
        return {variant for variant in variants if variant}

    def _record_matches_file_hint(self, info: Dict[str, Any], file_path: str) -> bool:
        indexed_file = str(info.get("file") or info.get("filename") or "")
        return self._paths_match_hint(indexed_file, file_path)

    @staticmethod
    def _paths_match_hint(stored_path: str, hint_path: str) -> bool:
        stored = str(stored_path or "").replace("\\", "/").strip()
        hint = str(hint_path or "").replace("\\", "/").strip()
        if not stored or not hint:
            return False
        stored = stored.lstrip("./")
        hint = hint.lstrip("./")
        return (
            stored == hint
            or stored.endswith(f"/{hint}")
            or hint.endswith(f"/{stored}")
        )

    def _is_path_allowed(self, p: Path) -> bool:
        """Check if a path passes include/exclude filters."""
        def is_subpath(child: Path, parent: Path) -> bool:
            try:
                # Use absolute() instead of resolve() to avoid symlink physical path jumping out of bounds
                c_str = str(child.absolute())
                p_str = str(parent.absolute())
                
                # Case-insensitive ONLY on Windows
                if os.name == 'nt':
                    c_str = c_str.lower()
                    p_str = p_str.lower()
                    
                sep = os.sep
                if not p_str.endswith(sep):
                    p_str += sep
                return c_str.startswith(p_str) or c_str == p_str.rstrip(sep)
            except Exception:
                return False

        if self.exclude_paths:
            for ex in self.exclude_paths:
                if is_subpath(p, ex):
                    return False
                    
        if self.include_paths:
            in_include = False
            for inc in self.include_paths:
                if is_subpath(p, inc):
                    in_include = True
                    break
            if not in_include:
                return False
                
        return True

    def _normalize_cpp_function_name(self, name: str) -> str:
        """Normalize C++ qualified names without dropping namespace/class context."""
        normalized = str(name or "").strip()
        if not normalized:
            return ""
        if "(" in normalized:
            normalized = normalized.split("(", 1)[0].strip()
        # If a full signature slipped in, keep the final token before the parameter list.
        if " " in normalized:
            normalized = normalized.split()[-1]
        normalized = normalized.strip("*&")
        normalized = re.sub(r"\s*::\s*", "::", normalized)
        normalized = re.sub(r"\s+", "", normalized)
        return normalized

    def _normalize_function_query(self, name: str) -> str:
        query = str(name or "").strip()
        if not query:
            return ""
        query = re.sub(r"\s*::\s*", "::", query)
        signature_query = self._normalize_signature_query(query)
        if signature_query:
            return signature_query
        return self._normalize_cpp_function_name(query)

    def _function_query_variants(self, func_name: str) -> List[str]:
        raw = str(func_name or "").strip()
        variants = []
        for candidate in (
            raw,
            self._normalize_function_query(raw),
            self._strip_cpp_template_args(self._normalize_function_query(raw)),
        ):
            if candidate and candidate not in variants:
                variants.append(candidate)
        signature_query = self._normalize_signature_query(raw)
        if signature_query and signature_query not in variants:
            variants.append(signature_query)
        return variants

    def _normalize_signature_query(self, query: str) -> str:
        if "(" not in query or not query.rstrip().endswith(")"):
            return ""
        name_part, params = query.rsplit("(", 1)
        params = params[:-1]
        name = self._normalize_cpp_function_name(name_part)
        return self._function_signature_key(name, params)

    def _function_signature_key(self, name: str, params: str) -> str:
        normalized_name = self._normalize_cpp_function_name(name)
        if not normalized_name:
            return ""
        params_norm = re.sub(r"\s+", " ", str(params or "").strip())
        params_norm = re.sub(r"\s*([*&<>,])\s*", r"\1", params_norm)
        return f"{normalized_name}({params_norm})"

    def _extract_signature_params(self, signature: str) -> Optional[str]:
        text = str(signature or "")
        if "(" not in text or ")" not in text:
            return None
        start = text.find("(")
        depth = 0
        for idx in range(start, len(text)):
            ch = text[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return text[start + 1 : idx].strip()
        return None

    def _strip_cpp_template_args(self, name: str) -> str:
        out = []
        depth = 0
        for ch in str(name or ""):
            if ch == "<":
                depth += 1
                continue
            if ch == ">" and depth:
                depth -= 1
                continue
            if depth == 0:
                out.append(ch)
        return "".join(out)

    @staticmethod
    def _cpp_simple_name(name: str) -> str:
        return str(name or "").split("::")[-1]

    @staticmethod
    def _cpp_tail_name(name: str, segments: int) -> str:
        parts = [part for part in str(name or "").split("::") if part]
        return "::".join(parts[-segments:]) if parts else ""

    def _find_all_files(self) -> List[str]:
        """Find all relevant source files using ripgrep or fallback to glob."""
        files = []
        extensions = (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ph", ".inc", ".inl")

        bases_to_search = self.include_paths if self.include_paths else [self.source_root]

        for base in bases_to_search:
            for ext in extensions:
                for file_path in base.rglob(f"*{ext}"):
                    if self._is_path_allowed(file_path):
                        files.append(str(file_path))

        return list(set(files))

    def _build_index_regex(self) -> None:
        """Build index using regex pattern matching (fallback)."""
        all_files = self._find_all_files()
        logger.info(f"Scanning {len(all_files)} C/H files with regex")
        for file_path in all_files:
            try:
                content = self._read_file_text(file_path)
                self._extract_functions_regex(file_path, content)
            except Exception as e:
                logger.debug(f"Failed to read {file_path}: {e}")

    def _parse_cpp_function_signature(
        self,
        signature_text: str,
        lines: Optional[Sequence[str]] = None,
        start_line: int = 1,
    ) -> Optional[Dict[str, str]]:
        """Best-effort parser for C/C++ function, method, constructor, and destructor heads."""
        original = str(signature_text or "").strip()
        if not original:
            return None

        collapsed = re.sub(r"\s+", " ", original).strip()
        if not collapsed or re.match(r"^(?:if|while|for|switch|return|catch)\b", collapsed):
            return None
        if collapsed.startswith(("typedef ", "using ", "namespace ", "class ", "struct ", "enum ")):
            return None

        match = re.search(
            r"(?P<name>(?:[A-Za-z_]\w*(?:\s*<[^;{}()]*>)?\s*::\s*)*~?[A-Za-z_]\w*)"
            r"\s*\((?P<params>[^;{}]*)\)\s*"
            r"(?P<tail>(?:const\b|volatile\b|noexcept\b|override\b|final\b|"
            r"requires\b|throw\s*\([^)]*\)|->[^:]+|[&:\w\s,<>()*~=.+\-])*)$",
            collapsed,
        )
        if not match:
            return None

        raw_name = match.group("name")
        prefix = collapsed[: match.start("name")].strip()
        params = match.group("params").strip()
        canonical_name = self._normalize_cpp_function_name(raw_name)
        if not canonical_name:
            return None

        class_scope = self._enclosing_cpp_type_name(lines or (), start_line)
        simple_name = self._cpp_simple_name(self._strip_cpp_template_args(canonical_name))
        parent_name = ""
        if "::" in canonical_name:
            parent_name = self._cpp_tail_name(
                self._strip_cpp_template_args(canonical_name),
                2,
            ).split("::")[0]
        class_simple = self._cpp_simple_name(class_scope) if class_scope else ""
        is_destructor = simple_name.startswith("~")
        destructor_target = simple_name[1:] if is_destructor else ""
        is_constructor = bool(parent_name and simple_name == parent_name)

        if not prefix:
            if "::" not in canonical_name and class_scope:
                if simple_name == class_simple or destructor_target == class_simple:
                    canonical_name = f"{class_scope}::{simple_name}"
                    is_constructor = simple_name == class_simple
                else:
                    return None
            elif not (is_constructor or (parent_name and destructor_target == parent_name)):
                return None
        elif class_scope and "::" not in canonical_name:
            canonical_name = f"{class_scope}::{simple_name}"

        signature = collapsed
        return {"name": canonical_name, "params": params, "signature": signature}

    def _parse_function_declaration_line(
        self,
        line: str,
        lines: Sequence[str],
        line_no: int,
    ) -> Optional[Dict[str, str]]:
        stripped = str(line or "").strip()
        if not stripped.endswith(";") or "(" not in stripped or "{" in stripped:
            return None
        if stripped.startswith(("#", "typedef ", "using ")):
            return None
        return self._parse_cpp_function_signature(stripped[:-1], lines, line_no)

    def _enclosing_cpp_type_name(self, lines: Sequence[str], start_line: int) -> str:
        """Return the innermost class/struct name active before start_line."""
        if not lines or start_line <= 1:
            return ""

        stack: List[Tuple[str, int]] = []
        brace_depth = 0
        pending_type = ""
        in_block_comment = False

        for raw_line in lines[: max(0, start_line - 1)]:
            line = raw_line
            if in_block_comment:
                if "*/" in line:
                    line = line.split("*/", 1)[1]
                    in_block_comment = False
                else:
                    continue
            while "/*" in line:
                before, after = line.split("/*", 1)
                if "*/" in after:
                    line = before + after.split("*/", 1)[1]
                else:
                    line = before
                    in_block_comment = True
                    break
            line = re.sub(r"//.*$", "", line)
            line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
            line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)

            type_match = re.search(r"\b(?:class|struct)\s+([A-Za-z_]\w*)\b", line)
            if type_match:
                pending_type = type_match.group(1)

            if pending_type and "{" in line:
                stack.append((pending_type, brace_depth + 1))
                pending_type = ""

            brace_depth += line.count("{")
            brace_depth -= line.count("}")
            while stack and brace_depth < stack[-1][1]:
                stack.pop()

        return "::".join(item[0] for item in stack)

    def _extract_functions_regex(self, file_path: Union[str, Path], content: str) -> None:
        """Extract function definitions using regex."""
        lines = content.split("\n")
        pending_signature: List[str] = []
        pending_start = 0
        in_block_comment = False
        line_no = 1
        while line_no <= len(lines):
            raw_line = lines[line_no - 1]
            clean_line = raw_line
            if in_block_comment:
                if "*/" in clean_line:
                    clean_line = clean_line.split("*/", 1)[1]
                    in_block_comment = False
                else:
                    line_no += 1
                    continue
            while "/*" in clean_line:
                before, after = clean_line.split("/*", 1)
                if "*/" in after:
                    clean_line = before + after.split("*/", 1)[1]
                else:
                    clean_line = before
                    in_block_comment = True
                    break
            clean_line = re.sub(r"//.*$", "", clean_line)

            stripped = clean_line.strip()
            if not pending_signature:
                if (
                    not stripped
                    or stripped.startswith("#")
                    or stripped.startswith("typedef")
                    or re.match(r"^(?:public|private|protected)\s*:\s*$", stripped)
                    or re.match(r"^(?:if|while|for|switch|return)\b", stripped)
                ):
                    line_no += 1
                    continue
                pending_start = line_no
            pending_signature.append(clean_line)
            signature_text = "\n".join(pending_signature)

            if ";" in signature_text and "{" not in signature_text:
                pending_signature = []
                line_no += 1
                continue
            if "{" not in signature_text:
                if len(pending_signature) > 12:
                    pending_signature = []
                line_no += 1
                continue

            before_brace = signature_text.split("{", 1)[0]
            parsed = self._parse_cpp_function_signature(before_brace, lines, pending_start)
            if not parsed:
                pending_signature = []
                line_no += 1
                continue

            func_name = parsed["name"]
            brace_count = 0
            started = False
            end_line = line_no
            scan_line = line_no
            while scan_line <= len(lines):
                scan_raw = lines[scan_line - 1]
                for char in scan_raw:
                    if char == "{":
                        brace_count += 1
                        started = True
                    elif char == "}":
                        brace_count -= 1
                if started and brace_count == 0:
                    end_line = scan_line
                    break
                scan_line += 1

            path = Path(file_path)
            self._add_function_index_entry(
                func_name,
                {
                    "file": str(path),
                    "start_line": pending_start,
                    "end_line": end_line,
                    "signature": parsed.get("signature") or f"{func_name}(...)",
                    "params": parsed.get("params", ""),
                },
            )
            pending_signature = []
            line_no = end_line + 1

    def _numbered_code(self, lines: Sequence[str], start_idx: int) -> str:
        """Format source lines with the line-number prefix used by tool outputs."""
        return "".join(f"{start_idx + i + 1} | {line}" for i, line in enumerate(lines))

    @classmethod
    def _code_range_has_function_body(cls, code_lines: Sequence[str]) -> bool:
        masked = cls._mask_c_comments_and_literals("".join(code_lines))
        for match in re.finditer(r"\{", masked):
            brace_pos = match.start()
            paren_pos = masked.rfind(")", 0, brace_pos)
            if paren_pos == -1:
                continue
            if ";" in masked[paren_pos + 1 : brace_pos]:
                continue
            return True
        return False

    @staticmethod
    def _mask_c_comments_and_literals(text: str) -> str:
        chars = list(text)
        i = 0
        state = "code"
        while i < len(chars):
            ch = chars[i]
            nxt = chars[i + 1] if i + 1 < len(chars) else ""

            if state == "code":
                if ch == "/" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    state = "line_comment"
                    continue
                if ch == "/" and nxt == "*":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    state = "block_comment"
                    continue
                if ch == '"':
                    chars[i] = " "
                    i += 1
                    state = "string"
                    continue
                if ch == "'":
                    chars[i] = " "
                    i += 1
                    state = "char"
                    continue
            elif state == "line_comment":
                if ch == "\n":
                    state = "code"
                else:
                    chars[i] = " "
            elif state == "block_comment":
                if ch == "*" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    state = "code"
                    continue
                if ch != "\n":
                    chars[i] = " "
            elif state in ("string", "char"):
                quote = '"' if state == "string" else "'"
                if ch == "\\":
                    chars[i] = " "
                    if i + 1 < len(chars) and chars[i + 1] != "\n":
                        chars[i + 1] = " "
                        i += 2
                        continue
                if ch == quote:
                    chars[i] = " "
                    state = "code"
                elif ch != "\n":
                    chars[i] = " "

            i += 1
        return "".join(chars)

    def _file_cache_key(self, file_path: Union[str, Path]) -> str:
        """Return a stable per-run key for cached source file contents."""
        path = Path(file_path)
        key = str(path.absolute())
        return key.lower() if os.name == "nt" else key

    def _read_file_lines(self, file_path: Union[str, Path]) -> List[str]:
        """Read source file lines through the per-run cache."""
        cache_key = self._file_cache_key(file_path)
        with self._cache_lock:
            cached = self._file_lines_cache.get(cache_key)
            if cached is not None:
                return list(cached)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = tuple(f.readlines())

        with self._cache_lock:
            cached = self._file_lines_cache.setdefault(cache_key, lines)
            return list(cached)

    def _read_file_text(self, file_path: Union[str, Path]) -> str:
        """Read source file text through the per-run line cache."""
        return "".join(self._read_file_lines(file_path))

    def _clone_function_impl(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Copy function implementation payloads before exposing cached data."""
        return {
            str(key): self._clone_function_impl_value(value)
            for key, value in result.items()
        }

    @classmethod
    def _clone_function_impl_value(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: cls._clone_function_impl_value(val) for key, val in value.items()}
        if isinstance(value, list):
            return [cls._clone_function_impl_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(cls._clone_function_impl_value(item) for item in value)
        return value

    def _get_cached_function_impl(
        self,
        cache_key: Tuple[str, int, bool],
    ) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            cached = self._function_impl_cache.get(cache_key)
            if cached is None:
                return None
            return self._clone_function_impl(cached)

    def _store_function_impl_cache(
        self,
        cache_key: Tuple[str, int, bool],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        with self._cache_lock:
            self._function_impl_cache[cache_key] = self._clone_function_impl(result)
            return self._clone_function_impl(self._function_impl_cache[cache_key])

    def _clear_function_impl_cache(self) -> None:
        with self._cache_lock:
            self._function_impl_cache.clear()
            self._function_file_resolution_cache.clear()
            self._macro_definition_index = None
            self._macro_definition_miss_cache.clear()

    def _find_leading_c_comment_block(
        self,
        lines: Sequence[str],
        start_line: int,
    ) -> Optional[Tuple[int, int]]:
        """Find the closest C/C++ comment block immediately above a source line."""
        idx = start_line - 2
        while idx >= 0 and not lines[idx].strip():
            idx -= 1
        if idx < 0:
            return None

        stripped = lines[idx].strip()
        if stripped.startswith("//"):
            end_idx = idx
            while idx >= 0 and lines[idx].strip().startswith("//"):
                idx -= 1
            return (idx + 2, end_idx + 1)

        if stripped.endswith("*/"):
            end_idx = idx
            while idx >= 0:
                current = lines[idx].strip()
                if current.startswith("/*"):
                    return (idx + 1, end_idx + 1)
                if not (current.startswith("*") or current == ""):
                    break
                idx -= 1

        return None

    def _comment_block_payload(
        self,
        *,
        kind: str,
        file_path: Path,
        lines: Sequence[str],
        block: Tuple[int, int],
    ) -> Dict[str, Any]:
        start_line, end_line = block
        raw_lines = list(lines[start_line - 1 : end_line])
        return {
            "kind": kind,
            "file": normalize_path(file_path, self.source_root),
            "start_line": start_line,
            "end_line": end_line,
            "text": "".join(raw_lines),
            "code": self._numbered_code(raw_lines, start_line - 1),
        }

    def _find_function_declaration_comments(
        self,
        func_name: str,
        implementation_file: Path,
        max_blocks: int = 3,
    ) -> List[Dict[str, Any]]:
        """Find leading comments above C function declarations/prototypes."""
        func_name = self._resolve_function_name(func_name)
        index = self._get_declaration_comment_index()
        results = []
        with self._cache_lock:
            impl_info = dict(self._function_index.get(func_name) or {})
        for block in index.get(func_name, []):
            block_file = self._resolve_file_path(str(block.get("file") or ""))
            if block_file == implementation_file and block.get("start_line") == impl_info.get(
                "start_line"
            ):
                continue
            results.append(dict(block))
            if len(results) >= max_blocks:
                break
        return results

    def _get_declaration_comment_index(self) -> Dict[str, List[Dict[str, Any]]]:
        """Build a cached map of function declaration comments keyed by function name."""
        with self._cache_lock:
            if self._declaration_comment_index is not None:
                return self._declaration_comment_index

        with self._declaration_comment_index_lock:
            with self._cache_lock:
                if self._declaration_comment_index is not None:
                    return self._declaration_comment_index

            index: Dict[str, List[Dict[str, Any]]] = {}
            seen: set[Tuple[str, int, int]] = set()
            for file_name in sorted(self._find_all_files()):
                file_path = self._resolve_file_path(file_name)
                if not file_path.exists() or file_path.is_dir():
                    continue
                try:
                    lines = self._read_file_lines(file_path)
                except Exception:
                    continue
                if not lines:
                    continue

                for line_no, line in enumerate(lines, start=1):
                    parsed = self._parse_function_declaration_line(line, lines, line_no)
                    if not parsed:
                        continue
                    block = self._find_leading_c_comment_block(lines, line_no)
                    if not block:
                        continue
                    key = (str(file_path), block[0], block[1])
                    if key in seen:
                        continue
                    seen.add(key)
                    func_name = parsed["name"]
                    index.setdefault(func_name, []).append(
                        self._comment_block_payload(
                            kind="declaration",
                            file_path=file_path,
                            lines=lines,
                            block=block,
                        )
                    )

            with self._cache_lock:
                self._declaration_comment_index = index
                return self._declaration_comment_index

    # ── Core retrieval methods ──

    def get_function_impl(
        self,
        func_name: str,
        max_lines: int = 500,
        warn_missing: bool = True,
        include_context: bool = True,
        file_path: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Get function implementation."""
        if not is_likely_function_call_identifier(func_name):
            logger.debug("Identifier '%s' is not a function call target", func_name)
            return None

        lookup_name = self._resolve_function_name(func_name, file_path=file_path)
        cache_key = (lookup_name, max_lines, bool(include_context))
        cached_result = self._get_cached_function_impl(cache_key)
        if cached_result is not None:
            return cached_result

        # Try backend lookup if not in index
        with self._cache_lock:
            func_info = self._function_index.get(lookup_name)
        if func_info is None and self._backend:
            for candidate in self._function_query_variants(func_name):
                m = self._backend.get_method(candidate)
                if m and m.get("filename"):
                    self._add_function_index_entry(
                        str(m.get("name") or candidate),
                        {
                            "file": m["filename"],
                            "start_line": m.get("lineNumber", -1),
                            "end_line": m.get("lineNumberEnd", -1),
                            "signature": m.get("signature", f"{candidate}(...)"),
                        },
                    )
                    lookup_name = self._resolve_function_name(candidate, file_path=file_path)
                    break

        with self._cache_lock:
            func_info = dict(self._function_index.get(lookup_name) or {})

        indexed_file = func_info.get("file", "")
        if not indexed_file or indexed_file.startswith("<"):
            macro_result = self._find_backend_macro_definition(func_name, max_lines=max_lines)
            if not macro_result:
                macro_result = self._find_macro_definition(func_name, max_lines=max_lines)
            if macro_result:
                return self._store_function_impl_cache(cache_key, macro_result)
            if warn_missing:
                logger.warning(f"Function '{func_name}' not found in index")
            return None

        file_path = self._resolve_file_path(func_info["file"])
        try:
            lines = self._read_file_lines(file_path)
            start = func_info["start_line"] - 1
            end = func_info["end_line"]
            if end - start > max_lines:
                end = start + max_lines
            code_lines = lines[start:end]
            if not self._code_range_has_function_body(code_lines):
                if warn_missing:
                    logger.warning(
                        "Function '%s' matched a declaration without a body at %s",
                        func_name,
                        func_info["file"],
                    )
                return None
            comment_blocks: List[Dict[str, Any]] = []
            if include_context:
                comment_blocks = self._find_function_declaration_comments(
                    lookup_name,
                    file_path,
                )
                impl_comment = self._find_leading_c_comment_block(lines, func_info["start_line"])
                if impl_comment:
                    comment_blocks.append(
                        self._comment_block_payload(
                            kind="implementation",
                            file_path=file_path,
                            lines=lines,
                            block=impl_comment,
                        )
                    )

            code_parts: List[str] = []
            for block in comment_blocks:
                code_parts.append(
                    f"/* {block['kind']} comment from "
                    f"{block['file']}:{block['start_line']}-{block['end_line']} */\n"
                )
                code_parts.append(str(block["code"]))
            code_parts.append(self._numbered_code(code_lines, start))
            code = "".join(code_parts)

            # Get callees from backend if available, else regex
            if not include_context:
                callees = []
            elif self._backend:
                backend_lookup = str(func_info.get("qualified_name") or lookup_name)
                callee_data = self._backend.get_method_callees(backend_lookup)
                callees = self._filter_callee_names(
                    c["name"] for c in callee_data if c.get("name")
                )
            else:
                callees = self._filter_callee_names(extract_function_calls(code))

            result = {
                "func_name": lookup_name,
                "file": normalize_path(file_path, self.source_root),
                "index_name": lookup_name,
                "start_line": func_info["start_line"],
                "end_line": min(func_info["end_line"], start + max_lines + 1),
                "code": code,
                "callees": callees,
                "signature": func_info.get("signature", f"{func_name}(...)"),
                "truncated": (func_info["end_line"] - func_info["start_line"] + 1) > max_lines,
                "comment_blocks": comment_blocks,
            }
            return self._store_function_impl_cache(cache_key, result)
        except Exception as e:
            logger.exception("Failed to read function '%s': %s", func_name, e)
            return None

    def get_file_snippet(
        self, file_path: str, start_line: Optional[int], end_line: Optional[int]
    ) -> Optional[Dict[str, Any]]:
        """Get a snippet from a file."""
        full_path = self._resolve_file_path(file_path)
        if not full_path.exists() or full_path.is_dir():
            return None
        try:
            lines = self._read_file_lines(full_path)
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
            code_lines = lines[start:end]
            code = "".join(f"{start + i + 1} | {line}" for i, line in enumerate(code_lines))
            return {"file": self._normalize_path(full_path), "start_line": start_line, "end_line": end_line, "code": code}
        except Exception as e:
            logger.error(f"Failed to read file snippet: {e}")
            return None

    def list_functions(
        self,
        pattern: Optional[str] = None,
        limit: int = 50,
        file_root: Optional[Union[str, Path]] = None,
    ) -> List[str]:
        """List known functions, optionally filtered by regex pattern and source directory."""
        funcs = list(self._function_index.keys())
        if file_root:
            root = Path(file_root)
            if not root.is_absolute():
                root = self.source_root / root
            root = root.resolve()

            scoped_funcs = []
            for name in funcs:
                info = self._function_index.get(name) or {}
                indexed_file = str(info.get("file") or "")
                if not indexed_file or indexed_file.startswith("<"):
                    continue
                try:
                    resolved_file = self._resolve_file_path(indexed_file).resolve()
                    resolved_file.relative_to(root)
                except (OSError, ValueError):
                    continue
                scoped_funcs.append(name)
            funcs = scoped_funcs

        if pattern:
            try:
                pat = re.compile(pattern)
                funcs = [f for f in funcs if pat.search(f)]
            except re.error:
                funcs = [f for f in funcs if f.startswith(pattern)]
        return sorted(funcs)[:limit]

    # ── New Joern-powered methods ──

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        """Get functions that call the given function."""
        if not self._backend:
            return []
        lookup_name = self._resolve_function_name(func_name, file_path=callee_file)
        with self._cache_lock:
            info = self._function_index.get(lookup_name) or {}
        backend_lookup = str(info.get("qualified_name") or lookup_name)
        backend_callee_file = str(info.get("file") or callee_file or "")
        try:
            return self._backend.get_callers(
                backend_lookup,
                limit=limit,
                callee_file=backend_callee_file,
            )
        except TypeError:
            return self._backend.get_callers(backend_lookup, limit=limit)

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        """Get functions called by the given function."""
        if not self._backend:
            return []
        lookup_name = self._resolve_function_name(func_name)
        with self._cache_lock:
            info = self._function_index.get(lookup_name) or {}
        backend_lookup = str(info.get("qualified_name") or lookup_name)
        return self._filter_callee_records(
            self._backend.get_callees(backend_lookup, limit=limit)
        )

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        """Get struct/union/enum definition and members."""
        if not self._backend:
            return None
        return self._backend.get_type_info(type_name)

    def get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        """Trace data flow from source parameter to sink."""
        if not self._backend:
            return []
        return self._backend.get_data_flow(source_func, source_param, sink_pattern)

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """Find function pointer assignments/callback registrations."""
        if not self._backend:
            return []
        return self._backend.find_function_pointers(func_name)

    def get_header_declared_functions(self, header_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get functions declared in header files (public API)."""
        results: List[Dict[str, Any]] = []
        if self._backend:
            try:
                results.extend(self._backend.get_header_declared_functions(header_files))
            except Exception as exc:
                logger.debug("Backend header declaration lookup failed: %s", exc)
        results.extend(self._get_header_funcs_regex(header_files))

        deduped: Dict[tuple[str, str], Dict[str, Any]] = {}
        for item in results:
            name = str(item.get("name") or "")
            filename = str(item.get("filename") or "").replace("\\", "/")
            try:
                line_no = int(item.get("lineNumber") or 0)
            except (TypeError, ValueError):
                line_no = 0
            if not name:
                continue
            key = (name, filename)
            previous = deduped.get(key)
            if previous and int(previous.get("lineNumber") or 0) > 0:
                continue
            deduped[key] = {"name": name, "filename": filename, "lineNumber": line_no}
        return list(deduped.values())

    def _get_header_funcs_regex(self, header_files: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        func_decl_re = re.compile(
            r"^\s*(?:extern\s+)?"
            r"(?:(?:const|volatile|struct|enum|union|unsigned|signed|long|short)\s+)*"
            r"[A-Za-z_]\w*(?:\s*\*)*\s+"
            r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;",
            re.MULTILINE | re.DOTALL,
        )
        results = []
        globs = self._header_globs(header_files)
        for pattern in globs:
            for fp in self.source_root.rglob(pattern):
                try:
                    content = self._read_file_text(fp)
                except Exception:
                    continue
                lines = content.splitlines()
                for line_no, line in enumerate(lines, start=1):
                    parsed = self._parse_function_declaration_line(line, lines, line_no)
                    if not parsed:
                        continue
                    name = parsed["name"]
                    if self._resolve_function_name(name) in self._function_index:
                        results.append({
                            "name": name,
                            "filename": normalize_path(fp, self.source_root),
                            "lineNumber": line_no,
                        })
                for m in func_decl_re.finditer(content):
                    name = m.group("name")
                    line_no = content[:m.start()].count("\n") + 1
                    if self._enclosing_cpp_type_name(lines, line_no):
                        continue
                    if self._resolve_function_name(name) in self._function_index:
                        results.append({
                            "name": name,
                            "filename": normalize_path(fp, self.source_root),
                            "lineNumber": line_no,
                        })
        return results

    @staticmethod
    def _header_globs(header_files: Optional[List[str]]) -> List[str]:
        if not header_files:
            return ["*.h", "*.hpp"]
        globs = []
        for header in header_files:
            pattern = str(header or "").strip().replace("\\", "/")
            if not pattern:
                continue
            if any(ch in pattern for ch in "*?["):
                globs.append(pattern)
            elif "/" in pattern:
                globs.append(pattern)
            else:
                globs.append(f"*{pattern}")
        return globs or ["*.h", "*.hpp"]

    # ── Macro and path helpers ──

    def _find_macro_definition(
        self, macro_name: str, max_lines: int = 500
    ) -> Optional[Dict[str, Any]]:
        """Find a macro definition using regex scanning."""
        clean_name = str(macro_name or "").strip()
        if not clean_name:
            return None
        with self._cache_lock:
            if clean_name in self._macro_definition_miss_cache:
                return None

        records = self._get_macro_definition_index().get(clean_name, [])
        if not records:
            with self._cache_lock:
                self._macro_definition_miss_cache.add(clean_name)
            return None
        return self._macro_definition_payload(
            clean_name,
            records[0],
            max_lines=max_lines,
            macro_alternates_count=max(0, len(records) - 1),
        )

    def _find_backend_macro_definition(
        self, macro_name: str, max_lines: int = 500
    ) -> Optional[Dict[str, Any]]:
        if not self._backend:
            return None
        getter = getattr(self._backend, "get_macro_definitions", None)
        if not callable(getter):
            return None
        for candidate in self._function_query_variants(macro_name):
            try:
                records = getter(candidate, limit=20)
            except Exception as exc:
                logger.debug("Backend macro lookup failed for %s: %s", candidate, exc)
                return None
            if not records:
                continue
            return self._macro_definition_payload(
                candidate,
                records[0],
                max_lines=max_lines,
                macro_alternates_count=max(0, len(records) - 1),
            )
        return None

    def _get_macro_definition_index(self) -> Dict[str, List[Dict[str, Any]]]:
        with self._cache_lock:
            if self._macro_definition_index is not None:
                return self._macro_definition_index

        with self._macro_definition_index_lock:
            with self._cache_lock:
                if self._macro_definition_index is not None:
                    return self._macro_definition_index

            index: Dict[str, List[Dict[str, Any]]] = {}
            for file_name in sorted(self._find_all_files()):
                file_path = self._resolve_file_path(file_name)
                if not file_path.exists() or file_path.is_dir():
                    continue
                try:
                    lines = self._read_file_lines(file_path)
                except Exception:
                    continue
                idx = 0
                while idx < len(lines):
                    parsed = self._parse_macro_definition_line(lines[idx])
                    if not parsed:
                        idx += 1
                        continue
                    start_idx = idx
                    definition_lines = [lines[idx]]
                    while definition_lines[-1].rstrip().endswith("\\") and idx + 1 < len(lines):
                        idx += 1
                        definition_lines.append(lines[idx])
                    index.setdefault(parsed["name"], []).append(
                        {
                            "name": parsed["name"],
                            "file_path": normalize_path(file_path, self.project_root),
                            "line": start_idx + 1,
                            "definition": "".join(definition_lines),
                            "is_function_like": int(parsed["is_function_like"]),
                        }
                    )
                    idx += 1

            for records in index.values():
                records.sort(
                    key=lambda row: (
                        -int(row.get("is_function_like") or 0),
                        str(row.get("file_path") or ""),
                        int(row.get("line") or 0),
                    )
                )
            with self._cache_lock:
                self._macro_definition_index = index
                return self._macro_definition_index

    @staticmethod
    def _parse_macro_definition_line(line: str) -> Optional[Dict[str, Any]]:
        match = re.match(r"^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)(?P<tail>.*)$", line)
        if not match:
            return None
        tail = str(match.group("tail") or "")
        return {
            "name": match.group("name"),
            "is_function_like": tail.startswith("("),
        }

    def _macro_definition_payload(
        self,
        macro_name: str,
        record: Dict[str, Any],
        *,
        max_lines: int = 500,
        macro_alternates_count: int = 0,
    ) -> Dict[str, Any]:
        definition = str(record.get("definition") or "")
        definition_lines = definition.splitlines(True)
        if not definition_lines:
            definition_lines = [definition]
        start_line = int(record.get("line") or record.get("start_line") or 1)
        full_line_count = max(1, len(definition_lines))
        code_lines = definition_lines[: max(0, int(max_lines or 500))]
        end_line = start_line + len(code_lines) - 1 if code_lines else start_line - 1
        code = self._numbered_code(code_lines, start_line - 1)
        file_value = str(record.get("file_path") or record.get("file") or "")
        resolved_file = self._resolve_file_path(file_value) if file_value else self.project_root
        result = {
            "func_name": macro_name,
            "file": normalize_path(resolved_file, self.project_root),
            "start_line": start_line,
            "end_line": end_line,
            "code": code,
            "callees": self._filter_callee_names(extract_function_calls(code)),
            "signature": self._macro_signature(
                macro_name,
                definition_lines[0] if definition_lines else "",
                bool(record.get("is_function_like")),
            ),
            "truncated": full_line_count > len(code_lines),
            "is_macro": True,
        }
        if macro_alternates_count:
            result["macro_alternates_count"] = macro_alternates_count
        return result

    @staticmethod
    def _macro_signature(macro_name: str, first_line: str, is_function_like: bool) -> str:
        if is_function_like:
            match = re.match(
                rf"^\s*#\s*define\s+{re.escape(macro_name)}(?P<params>\([^)]*\))?",
                str(first_line or ""),
            )
            params = match.group("params") if match else None
            return f"#define {macro_name}{params or ''}"
        return f"#define {macro_name}"

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
        func_name = self._resolve_function_name(func_name)
        if func_name not in self._function_index:
            return None
        info = self._function_index[func_name]
        resolved = self._resolve_file_path(info["file"])
        file_path = normalize_path(resolved, self.project_root)
        return f"{file_path}:{info['start_line']}-{info['end_line']}"

    def _filter_callee_names(self, names: Iterable[str]) -> List[str]:
        """Filter obvious C pseudo-callees while preserving order."""
        filtered = []
        seen = set()
        for name in names:
            if not is_likely_function_call_identifier(name) or name in seen:
                continue
            seen.add(name)
            filtered.append(name)
        return filtered

    def _filter_callee_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        filtered = []
        seen = set()
        for record in records:
            name = record.get("name")
            if not is_likely_function_call_identifier(name) or name in seen:
                continue
            seen.add(name)
            filtered.append(record)
        return filtered

    def close(self):
        """Close backend resources."""
        with self._cache_lock:
            self._file_lines_cache.clear()
            self._function_impl_cache.clear()
            self._function_file_resolution_cache.clear()
            self._declaration_comment_index = None
            self._function_alias_index.clear()
            self._ambiguous_function_aliases.clear()
            self._macro_definition_index = None
            self._macro_definition_miss_cache.clear()
        if self._backend:
            self._backend.close()
