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
from ..common.runtime_limits import ensure_linux_nofile_limit
from .backend_base import CodeBackend

logger = logging.getLogger(__name__)

DECLARATION_LINE_RE = re.compile(
    r"^[ \t]*(?!(?:return|if|while|for|switch)\b)"
    r"(?:[A-Za-z_]\w*[\s*]+)+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;"
)

FUNCTION_INFO_CALLEES_LIMIT = 30
FUNCTION_INFO_GLOBALS_LIMIT = 50
FUNCTION_INFO_MACROS_LIMIT = 30
FUNCTION_INFO_STORAGE_CLASSES = {
    "static",
    "extern",
    "thread_local",
    "global",
    "unknown",
}
FUNCTION_INFO_QUALIFIER_ORDER = (
    "const",
    "volatile",
    "atomic",
)
DEFAULT_FILE_SNIPPET_MAX_LINES = 50
MAX_FILE_SNIPPET_MAX_LINES = 500


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
        ensure_linux_nofile_limit()
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
        self._global_definition_index_lock = threading.Lock()
        self._file_lines_cache: Dict[str, Tuple[str, ...]] = {}
        self._function_impl_cache: Dict[
            Tuple[str, Optional[int], bool, str], Dict[str, Any]
        ] = {}
        self._macro_definition_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._global_definition_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
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
        if "is_static" in record:
            record["is_static"] = self._coerce_bool(record.get("is_static"))

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
        file_value = str(record.get("file") or record.get("filename") or "")
        file_part = self._normalize_index_file_value(file_value).replace("\\", "/")
        start_line = self._safe_int(record.get("start_line") or record.get("lineNumber"))
        end_line = self._safe_int(record.get("end_line") or record.get("lineNumberEnd"))
        if end_line < start_line:
            end_line = start_line
        return f"{canonical_name}@{file_part}:{start_line}-{end_line}"

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
            cache_key = self._function_file_resolution_cache_key(func_name, file_path)
            with self._cache_lock:
                cached = self._function_file_resolution_cache.get(cache_key)
            if cached is not None:
                return cached or func_name
        matches = self._find_function_matches(func_name, file_path=file_path)
        if matches:
            result = matches[0][0]
            if file_path:
                with self._cache_lock:
                    self._function_file_resolution_cache[cache_key] = result
            return result
        if file_path:
            with self._cache_lock:
                self._function_file_resolution_cache[cache_key] = ""
        return func_name

    def _find_function_matches(
        self,
        func_name: str,
        file_path: str = "",
        *,
        allow_simple_fallback: bool = False,
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """Return all strict function matches, with optional structured name fallback."""
        strict_matches = self._match_function_records(func_name, file_path=file_path)
        if file_path:
            cache_key = self._function_file_resolution_cache_key(func_name, file_path)
            with self._cache_lock:
                self._function_file_resolution_cache[cache_key] = (
                    strict_matches[0][0] if strict_matches else ""
                )
        if strict_matches or not allow_simple_fallback:
            return strict_matches

        fallback_name = self._fallback_function_name(func_name)
        if not fallback_name or fallback_name == str(func_name or "").strip():
            return []
        _, inferred_file, _, _ = self._function_location_query_parts(func_name)
        fallback_file = str(file_path or inferred_file or "")
        return self._match_function_records(fallback_name, file_path=fallback_file)

    def _match_function_records(
        self,
        func_name: str,
        *,
        file_path: str = "",
    ) -> List[Tuple[str, Dict[str, Any]]]:
        query_variants = set(self._function_query_variants(func_name))
        if not query_variants:
            return []

        if not file_path:
            ordered_variants = self._function_query_variants(func_name)
            with self._cache_lock:
                for variant in ordered_variants:
                    info = self._function_index.get(variant)
                    if info is not None:
                        return [(variant, dict(info))]
                for variant in ordered_variants:
                    alias = self._function_alias_index.get(variant)
                    if alias and alias in self._function_index:
                        return [(alias, dict(self._function_index[alias]))]

        records: List[Tuple[str, Dict[str, Any]]] = []
        if file_path:
            records = self._function_records_for_file_hint(file_path)
        if not records:
            with self._cache_lock:
                records = [(key, dict(info)) for key, info in self._function_index.items()]

        matches: List[Tuple[str, Dict[str, Any]]] = []
        for index_key, info in records:
            if file_path and not self._record_matches_file_hint(info, file_path):
                continue
            record_variants = self._function_record_query_variants(index_key, info)
            if query_variants.intersection(record_variants):
                matches.append((index_key, info))

        matches.sort(
            key=lambda item: (
                self._function_info_match_rank(query_variants, item[0], item[1]),
                str(item[1].get("file") or item[1].get("filename") or ""),
                int(item[1].get("start_line") or item[1].get("lineNumber") or 0),
                item[0],
            )
        )
        return matches

    def _try_backend_function_lookup(self, func_name: str, *, file_path: str = "") -> bool:
        if not self._backend:
            return False
        for candidate in self._function_query_variants(func_name):
            try:
                method = self._backend.get_method(candidate)
            except Exception as exc:
                logger.debug("Backend function lookup failed for %s: %s", candidate, exc)
                return False
            if not method or not method.get("filename"):
                continue
            method_file = str(method.get("filename") or "")
            if file_path and not self._paths_match_hint(method_file, file_path):
                continue
            method_record = {
                "file": method_file,
                "start_line": method.get("lineNumber", -1),
                "end_line": method.get("lineNumberEnd", -1),
                "signature": method.get("signature", f"{candidate}(...)"),
            }
            if "is_static" in method:
                method_record["is_static"] = method.get("is_static")
            self._add_function_index_entry(
                str(method.get("name") or candidate),
                method_record,
            )
            return True
        return False

    def fallback_function_name(self, query: str) -> str:
        """Return a conservative simple or qualified name for final lookup fallback."""
        return self._fallback_function_name(query)

    def _fallback_function_name(self, query: str) -> str:
        raw = str(query or "").strip()
        if not raw or raw.startswith("#define"):
            return ""

        location_name, _, _, _ = self._function_location_query_parts(raw)
        if location_name:
            return self._validated_fallback_function_name(location_name)

        if "(" not in raw or re.search(r"\(\s*[*&]\s*[A-Za-z_]\w*\s*\)", raw):
            return ""
        before_params = raw.split("(", 1)[0].strip()
        candidate = self._normalize_cpp_function_name(before_params)
        candidate = self._strip_cpp_template_args(candidate)
        return self._validated_fallback_function_name(candidate)

    @staticmethod
    def _validated_fallback_function_name(candidate: str) -> str:
        normalized = re.sub(r"\s*::\s*", "::", str(candidate or "").strip())
        if not normalized:
            return ""
        segment = r"~?[A-Za-z_]\w*"
        if not re.fullmatch(rf"{segment}(?:::{segment})*", normalized):
            return ""
        return normalized

    @staticmethod
    def _function_location_query_parts(query: str) -> Tuple[str, str, int, int]:
        match = re.match(
            r"^(?P<name>.+?)@(?P<file>.+):(?P<start>\d+)-(?P<end>\d+)$",
            str(query or "").strip(),
        )
        if not match:
            return "", "", 0, 0
        return (
            match.group("name"),
            match.group("file"),
            int(match.group("start")),
            int(match.group("end")),
        )

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
        for value in list(values):
            normalized = self._normalize_cpp_function_name(value)
            if "::" in normalized:
                values.add(self._cpp_simple_name(normalized))
                values.add(self._cpp_tail_name(normalized, 2))
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
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ph", ".inc", ".inl"}
        seen = set()

        bases_to_search = self.include_paths if self.include_paths else [self.source_root]

        for base in bases_to_search:
            for file_path in base.rglob("*"):
                if file_path.suffix.lower() not in extensions:
                    continue
                if not self._is_path_allowed(file_path):
                    continue
                cache_key = self._file_cache_key(file_path)
                if cache_key in seen:
                    continue
                seen.add(cache_key)
                files.append(str(file_path))

        return sorted(files)

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
                    "is_static": bool(
                        re.search(r"\bstatic\b", before_brace.split("(", 1)[0])
                    ),
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

    def get_file_line_count(self, file_path: Union[str, Path]) -> Optional[int]:
        """Return source file line count through the per-run line cache."""
        resolved = self._resolve_file_path(str(file_path))
        if not resolved.exists() or resolved.is_dir():
            return None
        try:
            return len(self._read_file_lines(resolved))
        except Exception as e:
            logger.debug("Failed to count lines in %s: %s", file_path, e)
            return None

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
        cache_key: Tuple[str, Optional[int], bool, str],
    ) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            cached = self._function_impl_cache.get(cache_key)
            if cached is None:
                return None
            return self._clone_function_impl(cached)

    def _store_function_impl_cache(
        self,
        cache_key: Tuple[str, Optional[int], bool, str],
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
            self._global_definition_index = None
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
        index_key = self._resolve_function_name(func_name)
        index = self._get_declaration_comment_index()
        results = []
        with self._cache_lock:
            impl_info = dict(self._function_index.get(index_key) or {})
        lookup_name = str(
            impl_info.get("qualified_name") or impl_info.get("name") or func_name
        )
        for block in index.get(lookup_name, []):
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
        max_lines: Optional[int] = 500,
        warn_missing: bool = True,
        include_context: bool = True,
        file_path: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Get function implementation; ``max_lines=None`` returns the full body."""
        raw_query = str(func_name or "").strip()
        if not is_likely_function_call_identifier(raw_query):
            logger.debug("Identifier '%s' is not a function call target", raw_query)
            return None

        macro_results: List[Dict[str, Any]] = []
        selected_match: Optional[Tuple[str, Dict[str, Any]]] = None
        if raw_query.startswith("#define"):
            macro_results = self._find_macro_impls(
                raw_query,
                file_path=file_path,
                max_lines=max_lines,
            )
        else:
            strict_matches = self._find_function_matches(raw_query, file_path=file_path)
            if not strict_matches and self._try_backend_function_lookup(
                raw_query,
                file_path=file_path,
            ):
                strict_matches = self._find_function_matches(raw_query, file_path=file_path)
            if strict_matches:
                selected_match = strict_matches[0]
            else:
                location_name, inferred_file, _, _ = self._function_location_query_parts(
                    raw_query
                )
                if location_name:
                    macro_results = self._find_macro_impls(
                        raw_query,
                        file_path=file_path,
                        max_lines=max_lines,
                        exact_location_only=True,
                    )

                if not macro_results:
                    fallback_name = self._fallback_function_name(raw_query)
                    fallback_matches = self._find_function_matches(
                        raw_query,
                        file_path=file_path,
                        allow_simple_fallback=True,
                    )
                    fallback_file = str(file_path or inferred_file or "")
                    if not fallback_matches and fallback_name:
                        if self._try_backend_function_lookup(
                            fallback_name,
                            file_path=fallback_file,
                        ):
                            fallback_matches = self._match_function_records(
                                fallback_name,
                                file_path=fallback_file,
                            )
                    if len(fallback_matches) > 1:
                        logger.warning(
                            "Function fallback for %r is ambiguous across %d matches",
                            raw_query,
                            len(fallback_matches),
                        )
                        return None
                    if fallback_matches:
                        selected_match = fallback_matches[0]
                    else:
                        macro_results = self._find_macro_impls(
                            raw_query,
                            file_path=file_path,
                            max_lines=max_lines,
                        )

        if macro_results:
            macro_result = dict(macro_results[0])
            if len(macro_results) > 1:
                macro_result["macro_alternates_count"] = len(macro_results) - 1
            macro_cache_key = (
                self._macro_impl_index_name(macro_result),
                max_lines,
                bool(include_context),
                "",
            )
            cached_result = self._get_cached_function_impl(macro_cache_key)
            if cached_result is not None:
                return cached_result
            return self._store_function_impl_cache(macro_cache_key, macro_result)

        if selected_match is None:
            if warn_missing:
                logger.warning("Function '%s' not found in index", raw_query)
            return None

        lookup_name, selected_info = selected_match
        cache_key = (lookup_name, max_lines, bool(include_context), "")
        cached_result = self._get_cached_function_impl(cache_key)
        if cached_result is not None:
            return cached_result

        func_info = dict(selected_info)
        indexed_file = str(func_info.get("file") or func_info.get("filename") or "")
        if not indexed_file or indexed_file.startswith("<"):
            if warn_missing:
                logger.warning("Function '%s' has no indexed source file", raw_query)
            return None

        file_path = self._resolve_file_path(func_info["file"])
        try:
            lines = self._read_file_lines(file_path)
            start = func_info["start_line"] - 1
            end = func_info["end_line"]
            if max_lines is not None and end - start > max_lines:
                end = start + max_lines
            code_lines = lines[start:end]
            if not self._code_range_has_function_body(code_lines):
                if warn_missing:
                    logger.warning(
                        "Function '%s' matched a declaration without a body at %s",
                        raw_query,
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
                "func_name": str(
                    func_info.get("qualified_name") or func_info.get("name") or raw_query
                ),
                "file": normalize_path(file_path, self.source_root),
                "index_name": lookup_name,
                "start_line": func_info["start_line"],
                "end_line": (
                    func_info["end_line"]
                    if max_lines is None
                    else min(func_info["end_line"], start + max_lines + 1)
                ),
                "code": code,
                "callees": callees,
                "signature": func_info.get("signature", f"{raw_query}(...)"),
                "is_static": self._function_record_is_static(func_info),
                "truncated": (
                    max_lines is not None
                    and (func_info["end_line"] - func_info["start_line"] + 1)
                    > max_lines
                ),
                "comment_blocks": comment_blocks,
            }
            return self._store_function_impl_cache(cache_key, result)
        except Exception as e:
            logger.exception("Failed to read function '%s': %s", raw_query, e)
            return None

    def get_file_snippet(
        self,
        file_path: str,
        start_line: Optional[int],
        end_line: Optional[int],
        max_lines: int = MAX_FILE_SNIPPET_MAX_LINES,
        default_max_lines: int = DEFAULT_FILE_SNIPPET_MAX_LINES,
    ) -> Optional[Dict[str, Any]]:
        """Get a snippet with separate explicit and implicit range limits."""
        full_path = self._resolve_file_path(file_path)
        if not full_path.exists() or full_path.is_dir():
            return None
        try:
            max_lines = max(1, int(max_lines))
            default_max_lines = max(1, int(default_max_lines))
            lines = self._read_file_lines(full_path)
            total_lines = len(lines)
            if total_lines == 0:
                return {"file": self._normalize_path(full_path), "start_line": 1, "end_line": 0, "code": ""}
            if start_line is None or start_line < 1:
                start_line = 1
            try:
                requested_end_line = int(end_line) if end_line is not None else None
            except (TypeError, ValueError):
                requested_end_line = None
            if (
                requested_end_line is None
                or requested_end_line < start_line
                or requested_end_line > total_lines
            ):
                end_line = min(total_lines, start_line + default_max_lines - 1)
            else:
                end_line = min(requested_end_line, start_line + max_lines - 1)
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

    def find_function_infos(
        self,
        func_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Return structured function metadata for every matching function record."""
        raw_query = str(func_name or "").strip()
        if raw_query.startswith("#define"):
            macro_impls = self._find_macro_impls(
                raw_query,
                file_path=file_path,
                max_lines=None,
                function_like_only=True,
                include_callees=False,
            )
            return [self._macro_function_info_payload(impl) for impl in macro_impls]

        strict_matches = self._find_function_matches(raw_query, file_path=file_path)
        if strict_matches:
            return [
                self._function_info_payload(index_key, info)
                for index_key, info in strict_matches
            ]

        location_name, _, _, _ = self._function_location_query_parts(raw_query)
        if location_name:
            exact_macro_impls = self._find_macro_impls(
                raw_query,
                file_path=file_path,
                max_lines=None,
                function_like_only=True,
                include_callees=False,
                exact_location_only=True,
            )
            if exact_macro_impls:
                return [
                    self._macro_function_info_payload(impl)
                    for impl in exact_macro_impls
                ]

        fallback_matches = self._find_function_matches(
            raw_query,
            file_path=file_path,
            allow_simple_fallback=True,
        )
        if fallback_matches:
            return [
                self._function_info_payload(index_key, info)
                for index_key, info in fallback_matches
            ]

        macro_impls = self._find_macro_impls(
            raw_query,
            file_path=file_path,
            max_lines=None,
            function_like_only=True,
            include_callees=False,
        )
        return [self._macro_function_info_payload(impl) for impl in macro_impls]

    def find_function_callers(
        self,
        func_name: str,
        file_path: str = "",
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Return canonical caller records when the target function is unique."""
        raw_query = str(func_name or "").strip()
        matches = self._find_function_matches(raw_query, file_path=file_path)
        if not matches:
            matches = self._find_function_matches(
                raw_query,
                file_path=file_path,
                allow_simple_fallback=True,
            )
        if len(matches) != 1:
            return {"match_count": len(matches), "callers": []}

        index_key, info = matches[0]
        callers = self._function_info_callers(
            index_key,
            str(info.get("file") or info.get("filename") or ""),
            limit=max(0, int(limit)),
        )
        return {"match_count": 1, "callers": callers}

    def _macro_function_info_payload(self, impl: Dict[str, Any]) -> Dict[str, Any]:
        function_name = str(impl.get("func_name") or "")
        file_path = self._normalize_index_file_value(str(impl.get("file") or ""))
        start_line = self._safe_int(impl.get("start_line"))
        end_line = self._safe_int(impl.get("end_line"))
        if end_line < start_line:
            end_line = start_line
        symbol_context = self._macro_function_info_symbol_context(function_name, impl)
        return {
            "function_name": function_name,
            "file_path": file_path,
            "index_name": f"{function_name}@{file_path}:{start_line}-{end_line}",
            "start_line": start_line,
            "end_line": end_line,
            "signature": str(impl.get("signature") or f"#define {function_name}"),
            "is_static": False,
            "is_macro": True,
            "code": str(impl.get("code") or ""),
            "callees": self._macro_function_info_callees(function_name, impl),
            "referenced_globals": symbol_context["referenced_globals"],
            "referenced_macros": symbol_context["referenced_macros"],
        }

    def _macro_function_info_callees(
        self,
        macro_name: str,
        impl: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}
        for raw_line in str(impl.get("code") or "").splitlines():
            match = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", raw_line)
            line_no = self._safe_int(match.group(1)) if match else 0
            source_line = match.group(2) if match else raw_line
            for callee_name in self._filter_callee_names(extract_function_calls(source_line)):
                if callee_name == macro_name:
                    continue
                entry = groups.setdefault(
                    callee_name,
                    {
                        "callee_index_name": self._function_info_callee_index_name(
                            callee_name,
                            self._function_file_for_query(callee_name),
                        ),
                        "callsite_lines": [],
                        "call_type": ["direct"],
                    },
                )
                if line_no > 0 and line_no not in entry["callsite_lines"]:
                    entry["callsite_lines"].append(line_no)
        return sorted(
            groups.values(),
            key=lambda item: str(item.get("callee_index_name") or ""),
        )[:FUNCTION_INFO_CALLEES_LIMIT]

    def _macro_function_info_symbol_context(
        self,
        macro_name: str,
        impl: Dict[str, Any],
    ) -> Dict[str, List[Dict[str, Any]]]:
        globals_index = {} if self._backend else self._get_global_definition_index()
        macros_index = {} if self._backend else self._get_macro_definition_index()
        file_path = str(impl.get("file") or "")
        signature = str(impl.get("signature") or "")
        parameters_match = re.search(r"\(([^)]*)\)", signature)
        parameters = {
            value.strip()
            for value in str(parameters_match.group(1) if parameters_match else "").split(",")
            if value.strip()
        }
        global_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        macro_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for raw_line in str(impl.get("code") or "").splitlines():
            match = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", raw_line)
            line_no = self._safe_int(match.group(1)) if match else 0
            source_line = match.group(2) if match else raw_line
            masked_line = self._mask_function_info_source_line(source_line)
            for token in re.finditer(r"\b[A-Za-z_]\w*\b", masked_line):
                name = token.group(0)
                if name == macro_name or name in parameters:
                    continue
                if name in globals_index and not self._function_info_field_access(
                    masked_line,
                    token.start(),
                ):
                    record = self._preferred_function_info_record(globals_index[name], file_path)
                    key = (name, str(record.get("file_path") or ""))
                    entry = global_groups.setdefault(
                        key,
                        {
                            **record,
                            "type": str(record.get("type") or record.get("type_str") or ""),
                            "access": "unknown",
                            "reference_lines": [],
                        },
                    )
                    entry["access"] = self._merge_function_info_access(
                        str(entry.get("access") or "unknown"),
                        self._function_info_regex_access(
                            masked_line,
                            token.start(),
                            token.end(),
                        ),
                    )
                    if line_no > 0 and line_no not in entry["reference_lines"]:
                        entry["reference_lines"].append(line_no)
                if name in macros_index:
                    record = self._preferred_function_info_record(macros_index[name], file_path)
                    key = (name, str(record.get("file_path") or ""))
                    entry = macro_groups.setdefault(
                        key,
                        {**record, "reference_lines": []},
                    )
                    if line_no > 0 and line_no not in entry["reference_lines"]:
                        entry["reference_lines"].append(line_no)

        referenced_globals = [
            self._normalize_function_info_global(item)
            for item in global_groups.values()
        ]
        referenced_macros = [
            self._normalize_function_info_macro(item)
            for item in macro_groups.values()
        ]
        referenced_globals.sort(key=lambda item: (item["name"], item["file_path"], item["line"]))
        referenced_macros.sort(key=lambda item: (item["name"], item["file_path"], item["line"]))
        return {
            "referenced_globals": referenced_globals[:FUNCTION_INFO_GLOBALS_LIMIT],
            "referenced_macros": referenced_macros[:FUNCTION_INFO_MACROS_LIMIT],
        }

    def _macro_impl_index_name(self, impl: Dict[str, Any]) -> str:
        function_name = str(impl.get("func_name") or "")
        file_path = self._normalize_index_file_value(str(impl.get("file") or ""))
        start_line = self._safe_int(impl.get("start_line"))
        end_line = self._safe_int(impl.get("end_line"))
        if end_line < start_line:
            end_line = start_line
        return f"{function_name}@{file_path}:{start_line}-{end_line}"

    def _function_info_match_rank(
        self,
        query_variants: set[str],
        index_key: str,
        info: Dict[str, Any],
    ) -> int:
        if index_key in query_variants or str(info.get("index_name") or "") in query_variants:
            return 0
        if str(info.get("qualified_name") or "") in query_variants:
            return 1
        if str(info.get("name") or "") in query_variants:
            return 2
        return 3

    def _function_info_payload(
        self,
        index_key: str,
        info: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw_file = str(info.get("file") or info.get("filename") or "")
        function_name = str(
            info.get("name")
            or info.get("qualified_name")
            or index_key
        )
        payload = {
            "function_name": function_name,
            "file_path": self._normalize_index_file_value(raw_file),
            "index_name": str(info.get("index_name") or index_key),
            "start_line": self._safe_int(info.get("start_line") or info.get("lineNumber")),
            "end_line": self._safe_int(info.get("end_line") or info.get("lineNumberEnd")),
            "signature": str(info.get("signature") or f"{function_name}(...)"),
            "is_static": self._function_record_is_static(info),
            "is_macro": False,
        }
        callees, callee_total = self._function_info_callees(index_key)
        payload["callees"] = callees
        if callee_total > len(callees):
            payload["callees_truncation"] = self._truncation_payload(
                len(callees),
                callee_total,
            )
        payload.update(self._function_info_symbol_context(index_key, raw_file))
        return payload

    def _function_info_callers(
        self,
        index_key: str,
        raw_file: str,
        *,
        limit: int,
    ) -> List[Dict[str, Any]]:
        if limit <= 0 or not self._backend:
            return []
        try:
            with self._cache_lock:
                info = self._function_index.get(index_key) or {}
            backend_lookup = str(
                info.get("qualified_name") or info.get("name") or index_key
            )
            getter = getattr(self._backend, "get_function_info_callers", None)
            if callable(getter):
                try:
                    callers = getter(backend_lookup, raw_file)
                except TypeError:
                    callers = getter(backend_lookup)
            else:
                callers = self.get_callers(
                    index_key,
                    limit=self._function_info_raw_edge_limit(limit),
                    callee_file=raw_file,
                )
            target_matches = self._find_function_matches(backend_lookup)
            if len(target_matches) > 1:
                callers = [
                    row
                    for row in callers
                    if self._function_info_call_type(row) != "indirect"
                ]
        except Exception as exc:
            logger.debug("Caller lookup failed for %s: %s", index_key, exc)
            return []
        return self._aggregate_function_info_callers(callers)[:limit]

    def _function_info_callees(
        self,
        index_key: str,
    ) -> Tuple[List[Dict[str, Any]], int]:
        if not self._backend:
            return self._function_info_callees_regex(index_key)
        try:
            with self._cache_lock:
                info = self._function_index.get(index_key) or {}
            backend_lookup = str(
                info.get("qualified_name") or info.get("name") or index_key
            )
            getter = getattr(self._backend, "get_function_info_callees", None)
            if callable(getter):
                try:
                    callees = getter(backend_lookup, str(info.get("file") or ""))
                except TypeError:
                    callees = getter(backend_lookup)
            else:
                callees = self._backend.get_callees(backend_lookup, limit=1_000_000)
        except Exception as exc:
            logger.debug("Callee lookup failed for %s: %s", index_key, exc)
            return [], 0
        aggregated = self._aggregate_function_info_callees(callees)
        aggregated.sort(
            key=lambda item: str(item.get("callee_index_name") or "")
        )
        return aggregated[:FUNCTION_INFO_CALLEES_LIMIT], len(aggregated)

    def _function_info_callees_regex(
        self,
        index_key: str,
    ) -> Tuple[List[Dict[str, Any]], int]:
        with self._cache_lock:
            info = dict(self._function_index.get(index_key) or {})
        file_value = str(info.get("file") or info.get("filename") or "")
        try:
            lines = self._read_file_lines(self._resolve_file_path(file_value))
        except Exception:
            return [], 0
        start_line = max(1, self._safe_int(info.get("start_line") or info.get("lineNumber")))
        end_line = min(
            len(lines),
            max(start_line, self._safe_int(info.get("end_line") or info.get("lineNumberEnd"))),
        )
        groups: Dict[str, Dict[str, Any]] = {}
        function_name = str(info.get("name") or info.get("qualified_name") or index_key)
        for offset, raw_line in enumerate(lines[start_line - 1:end_line]):
            absolute_line = start_line + offset
            for name in self._filter_callee_names(extract_function_calls(raw_line)):
                if name == function_name:
                    continue
                entry = groups.setdefault(
                    name,
                    {
                        "callee_index_name": self._function_info_callee_index_name(
                            name,
                            self._function_file_for_query(name),
                        ),
                        "callsite_lines": [],
                        "call_type": ["direct"],
                    },
                )
                if absolute_line not in entry["callsite_lines"]:
                    entry["callsite_lines"].append(absolute_line)
        result = sorted(
            groups.values(),
            key=lambda item: item["callee_index_name"],
        )
        return result[:FUNCTION_INFO_CALLEES_LIMIT], len(result)

    def _function_info_callee_index_name(
        self,
        callee_name: str,
        callee_file: str = "",
    ) -> str:
        resolved = self._resolve_function_name(callee_name, file_path=callee_file)
        with self._cache_lock:
            if resolved in self._function_index:
                return resolved
        return str(callee_name or "")

    def _function_info_caller_index_name(
        self,
        caller_name: str,
        caller_file: str = "",
    ) -> str:
        matches = self._find_function_matches(
            caller_name,
            file_path=caller_file,
            allow_simple_fallback=True,
        )
        if len(matches) == 1:
            return matches[0][0]
        return str(caller_name or "")

    def _function_info_symbol_context(
        self,
        index_key: str,
        raw_file: str,
    ) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "referenced_globals": [],
            "referenced_macros": [],
        }
        if not self._backend:
            raw_context = self._function_info_symbol_context_regex(index_key, raw_file)
        else:
            try:
                with self._cache_lock:
                    info = self._function_index.get(index_key) or {}
                backend_lookup = str(
                    info.get("qualified_name") or info.get("name") or index_key
                )
                getter = getattr(self._backend, "get_function_symbol_context", None)
                if not callable(getter):
                    return context
                raw_context = getter(backend_lookup, raw_file)
            except Exception as exc:
                logger.debug("Symbol context lookup failed for %s: %s", index_key, exc)
                return context

        globals_result = [
            self._normalize_function_info_global(item)
            for item in list((raw_context or {}).get("referenced_globals") or [])
            if isinstance(item, dict) and str(item.get("name") or "")
        ]
        macros_result = [
            self._normalize_function_info_macro(item)
            for item in list((raw_context or {}).get("referenced_macros") or [])
            if isinstance(item, dict) and str(item.get("name") or "")
        ]
        globals_result.sort(
            key=lambda item: (item["name"], item["file_path"], item["line"])
        )
        macros_result.sort(
            key=lambda item: (item["name"], item["file_path"], item["line"])
        )

        context["referenced_globals"] = globals_result[:FUNCTION_INFO_GLOBALS_LIMIT]
        context["referenced_macros"] = macros_result[:FUNCTION_INFO_MACROS_LIMIT]
        if len(globals_result) > FUNCTION_INFO_GLOBALS_LIMIT:
            context["referenced_globals_truncation"] = self._truncation_payload(
                FUNCTION_INFO_GLOBALS_LIMIT,
                len(globals_result),
            )
        if len(macros_result) > FUNCTION_INFO_MACROS_LIMIT:
            context["referenced_macros_truncation"] = self._truncation_payload(
                FUNCTION_INFO_MACROS_LIMIT,
                len(macros_result),
            )
        return context

    def _normalize_function_info_global(self, item: Dict[str, Any]) -> Dict[str, Any]:
        access = str(item.get("access") or "unknown")
        if access not in {"read", "write", "read_write", "unknown"}:
            access = "unknown"
        storage_class = str(item.get("storage_class") or "unknown")
        if storage_class not in FUNCTION_INFO_STORAGE_CLASSES:
            storage_class = "unknown"
        return {
            "name": str(item.get("name") or ""),
            "type": str(item.get("type") or item.get("type_str") or ""),
            "file_path": self._normalize_index_file_value(str(item.get("file_path") or "")),
            "line": self._safe_int(item.get("line")),
            "storage_class": storage_class,
            "qualifiers": self._normalize_function_info_qualifiers(
                item.get("qualifiers")
            ),
            "initializer": str(item.get("initializer") or ""),
            "access": access,
            "reference_lines": self._normalized_line_list(item.get("reference_lines")),
        }

    @staticmethod
    def _normalize_function_info_qualifiers(value: Any) -> List[str]:
        if isinstance(value, str):
            raw_values = [part.strip() for part in value.split(",")]
        elif isinstance(value, (list, tuple, set)):
            raw_values = [str(part).strip() for part in value]
        else:
            raw_values = []
        selected = {part for part in raw_values if part}
        return [
            qualifier
            for qualifier in FUNCTION_INFO_QUALIFIER_ORDER
            if qualifier in selected
        ]

    def _normalize_function_info_macro(self, item: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "name": str(item.get("name") or ""),
            "file_path": self._normalize_index_file_value(str(item.get("file_path") or "")),
            "line": self._safe_int(item.get("line")),
            "definition": str(item.get("definition") or ""),
            "is_function_like": bool(item.get("is_function_like")),
            "reference_lines": self._normalized_line_list(item.get("reference_lines")),
        }

    def _normalized_line_list(self, value: Any) -> List[int]:
        if not isinstance(value, (list, tuple, set)):
            return []
        return sorted({self._safe_int(line) for line in value if self._safe_int(line) > 0})

    @staticmethod
    def _truncation_payload(returned: int, total: int) -> Dict[str, Any]:
        return {
            "truncated": True,
            "returned": int(returned),
            "total": int(total),
        }

    def _function_info_symbol_context_regex(
        self,
        index_key: str,
        raw_file: str,
    ) -> Dict[str, List[Dict[str, Any]]]:
        with self._cache_lock:
            info = dict(self._function_index.get(index_key) or {})
        file_path = self._resolve_file_path(raw_file)
        try:
            lines = self._read_file_lines(file_path)
        except Exception:
            return {"referenced_globals": [], "referenced_macros": []}
        start_line = max(1, self._safe_int(info.get("start_line") or info.get("lineNumber")))
        end_line = min(
            len(lines),
            max(start_line, self._safe_int(info.get("end_line") or info.get("lineNumberEnd"))),
        )
        body_lines = lines[start_line - 1:end_line]
        local_names = self._function_info_regex_local_names(
            "".join(body_lines),
            str(info.get("signature") or ""),
        )
        globals_index = self._get_global_definition_index()
        macros_index = self._get_macro_definition_index()
        global_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        macro_groups: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for offset, raw_line in enumerate(body_lines):
            absolute_line = start_line + offset
            if raw_line.lstrip().startswith("#"):
                continue
            masked_line = self._mask_function_info_source_line(raw_line)
            for match in re.finditer(r"\b[A-Za-z_]\w*\b", masked_line):
                name = match.group(0)
                if name in globals_index and name not in local_names and not self._function_info_field_access(
                    masked_line,
                    match.start(),
                ):
                    record = self._preferred_function_info_record(globals_index[name], raw_file)
                    key = (name, str(record.get("file_path") or ""))
                    entry = global_groups.get(key)
                    if entry is None:
                        entry = {
                            **record,
                            "type": str(record.get("type") or record.get("type_str") or ""),
                            "access": "unknown",
                            "reference_lines": [],
                        }
                        global_groups[key] = entry
                    entry["access"] = self._merge_function_info_access(
                        str(entry.get("access") or "unknown"),
                        self._function_info_regex_access(masked_line, match.start(), match.end()),
                    )
                    if absolute_line not in entry["reference_lines"]:
                        entry["reference_lines"].append(absolute_line)

                if name in macros_index:
                    record = self._preferred_function_info_record(macros_index[name], raw_file)
                    if bool(record.get("is_function_like")) and not re.match(
                        r"\s*\(", masked_line[match.end():]
                    ):
                        continue
                    key = (name, str(record.get("file_path") or ""))
                    entry = macro_groups.get(key)
                    if entry is None:
                        entry = {**record, "reference_lines": []}
                        macro_groups[key] = entry
                    if absolute_line not in entry["reference_lines"]:
                        entry["reference_lines"].append(absolute_line)

        return {
            "referenced_globals": list(global_groups.values()),
            "referenced_macros": list(macro_groups.values()),
        }

    @staticmethod
    def _preferred_function_info_record(
        records: List[Dict[str, Any]],
        function_file: str,
    ) -> Dict[str, Any]:
        normalized_file = str(function_file or "").replace("\\", "/").lstrip("./")
        ranked = sorted(
            records,
            key=lambda record: (
                0
                if str(record.get("file_path") or "").replace("\\", "/").lstrip("./")
                == normalized_file
                else 1,
                str(record.get("file_path") or ""),
                int(record.get("line") or 0),
            ),
        )
        return dict(ranked[0])

    @staticmethod
    def _function_info_regex_local_names(body: str, signature: str) -> set[str]:
        names: set[str] = set()
        if "(" in signature and ")" in signature:
            params = signature[signature.find("(") + 1:signature.rfind(")")]
            for parameter in params.split(","):
                identifiers = re.findall(r"\b[A-Za-z_]\w*\b", parameter)
                if identifiers and identifiers[-1] not in {"void", "const", "volatile"}:
                    names.add(identifiers[-1])
        declaration_pattern = re.compile(
            r"(?:^|[;{}])\s*(?:const\s+|volatile\s+|static\s+|register\s+|auto\s+|"
            r"signed\s+|unsigned\s+|short\s+|long\s+|_Atomic\s+)*"
            r"(?:void|char|int|float|double|size_t|ssize_t|bool|_Bool|"
            r"struct\s+[A-Za-z_]\w*|union\s+[A-Za-z_]\w*|enum\s+[A-Za-z_]\w*)"
            r"(?:\s+|\s*\*+\s*)(?P<name>[A-Za-z_]\w*)\s*(?=[=;,\[])"
        )
        names.update(match.group("name") for match in declaration_pattern.finditer(body))
        return names

    @staticmethod
    def _function_info_field_access(line: str, start: int) -> bool:
        prefix = line[:start].rstrip()
        return prefix.endswith(".") or prefix.endswith("->")

    @staticmethod
    def _function_info_regex_access(line: str, start: int, end: int) -> str:
        prefix = line[:start].rstrip()
        suffix = line[end:]
        if prefix.endswith("++") or prefix.endswith("--"):
            return "read_write"
        operation = re.match(
            r"\s*(?:\[[^\]]*\]|\.\s*[A-Za-z_]\w*|->\s*[A-Za-z_]\w*)*\s*"
            r"(?P<op>\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|=(?!=))",
            suffix,
        )
        if not operation:
            return "read"
        return "write" if operation.group("op") == "=" else "read_write"

    @staticmethod
    def _merge_function_info_access(left: str, right: str) -> str:
        values = {left or "unknown", right or "unknown"}
        if "read_write" in values or {"read", "write"}.issubset(values):
            return "read_write"
        if "write" in values:
            return "write"
        if "read" in values:
            return "read"
        return "unknown"

    @staticmethod
    def _mask_function_info_source_line(line: str) -> str:
        masked = re.sub(r"//.*$", "", str(line or ""))
        masked = re.sub(r"/\*.*?\*/", " ", masked)
        masked = re.sub(r'"(?:\\.|[^"\\])*"', " ", masked)
        masked = re.sub(r"'(?:\\.|[^'\\])*'", " ", masked)
        return masked

    @staticmethod
    def _function_info_raw_edge_limit(limit: int) -> int:
        # Fetch enough raw edges to group multiple callsites before slicing.
        return max(int(limit) * 100, 1000)

    def _aggregate_function_info_callers(
        self,
        rows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        groups: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            caller_name = str(row.get("name") or row.get("caller_name") or "")
            caller_file = self._normalize_index_file_value(
                str(
                    row.get("filename")
                    or row.get("caller_file")
                    or row.get("call_file")
                    or row.get("file")
                    or ""
                )
            )
            caller_index_name = self._function_info_caller_index_name(
                caller_name,
                caller_file,
            )
            if not caller_index_name:
                continue
            call_type = self._function_info_call_type(row)
            entry = groups.get(caller_index_name)
            if entry is None:
                entry = {
                    "caller_index_name": caller_index_name,
                    "callsite_lines": [],
                    "call_type": [],
                }
                groups[caller_index_name] = entry
            if call_type not in entry["call_type"]:
                entry["call_type"].append(call_type)
            self._append_callsite_line(entry, row)
        for entry in groups.values():
            entry["callsite_lines"] = sorted(entry["callsite_lines"])
            entry["call_type"] = [
                call_type
                for call_type in ("direct", "indirect")
                if call_type in entry["call_type"]
            ]
        return list(groups.values())

    def _aggregate_function_info_callees(
        self,
        rows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for row in rows:
            callee_name = str(row.get("name") or row.get("callee_name") or "")
            callee_file = str(row.get("filename") or row.get("callee_file") or row.get("file") or "")
            if not callee_file and callee_name:
                callee_file = self._function_file_for_query(callee_name)
            callee_index_name = self._function_info_callee_index_name(
                callee_name,
                callee_file,
            )
            call_type = self._function_info_call_type(row)
            entry = groups.get(callee_index_name)
            if entry is None:
                entry = {
                    "callee_index_name": callee_index_name,
                    "callsite_lines": [],
                    "call_type": [],
                }
                groups[callee_index_name] = entry
            if call_type not in entry["call_type"]:
                entry["call_type"].append(call_type)
            self._append_callsite_line(entry, row)
        for entry in groups.values():
            entry["callsite_lines"] = sorted(entry["callsite_lines"])
            entry["call_type"] = [
                call_type
                for call_type in ("direct", "indirect")
                if call_type in entry["call_type"]
            ]
        return list(groups.values())

    def _normalize_function_info_caller(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "caller_name": str(row.get("name") or row.get("caller_name") or ""),
            "caller_file": self._normalize_index_file_value(
                str(row.get("filename") or row.get("caller_file") or row.get("file") or "")
            ),
            "callsite_lines": self._callsite_lines_from_row(row),
        }

    def _normalize_function_info_callee(self, row: Dict[str, Any]) -> Dict[str, Any]:
        callee_name = str(row.get("name") or row.get("callee_name") or "")
        callee_file = str(row.get("filename") or row.get("callee_file") or row.get("file") or "")
        if not callee_file and callee_name:
            callee_file = self._function_file_for_query(callee_name)
        return {
            "callee_index_name": self._function_info_callee_index_name(
                callee_name,
                callee_file,
            ),
            "callsite_lines": self._callsite_lines_from_row(row),
            "call_type": [self._function_info_call_type(row)],
        }

    def _append_callsite_line(self, entry: Dict[str, Any], row: Dict[str, Any]) -> None:
        line = self._callsite_line_from_row(row)
        if line > 0 and line not in entry["callsite_lines"]:
            entry["callsite_lines"].append(line)

    def _callsite_lines_from_row(self, row: Dict[str, Any]) -> List[int]:
        line = self._callsite_line_from_row(row)
        return [line] if line > 0 else []

    def _callsite_line_from_row(self, row: Dict[str, Any]) -> int:
        return self._safe_int(
            row.get("lineNumber")
            or row.get("callsite_line")
            or row.get("call_line")
            or row.get("line")
        )

    def _function_info_call_type(self, row: Dict[str, Any]) -> str:
        backend_name = str(getattr(self, "backend_name", "") or "").lower()
        if backend_name not in {"svf", "unified"}:
            return "direct"
        raw = str(row.get("call_type") or "").strip().lower()
        if raw in {"direct", "indirect"}:
            return raw
        indirect_markers = ("source", "svf_group", "svf_groups", "confidence")
        if any(row.get(marker) not in (None, "", []) for marker in indirect_markers):
            return "indirect"
        return "direct"

    def _function_file_for_query(self, func_name: str) -> str:
        lookup_name = self._resolve_function_name(func_name)
        with self._cache_lock:
            info = self._function_index.get(lookup_name) or {}
        return str(info.get("file") or info.get("filename") or "")

    def _normalize_index_file_value(self, file_value: str) -> str:
        normalized = str(file_value or "").replace("\\", "/").strip()
        if not normalized or normalized.startswith("[") or normalized.startswith("<"):
            return normalized
        try:
            return self._normalize_path(self._resolve_file_path(normalized))
        except Exception:
            return normalized

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _coerce_bool(value: Any) -> bool:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"", "0", "false", "no", "off"}:
                return False
            if normalized in {"1", "true", "yes", "on"}:
                return True
        return bool(value)

    def _function_record_is_static(self, info: Dict[str, Any]) -> bool:
        if "is_static" in info:
            return self._coerce_bool(info.get("is_static"))

        function_name = str(info.get("qualified_name") or info.get("name") or "")
        signature = str(info.get("signature") or "")
        if self._function_header_has_static(signature, function_name):
            return True

        file_value = str(info.get("file") or info.get("filename") or "")
        start_line = self._safe_int(info.get("start_line") or info.get("lineNumber"))
        if not file_value or start_line <= 0:
            return False
        try:
            lines = self._read_file_lines(self._resolve_file_path(file_value))
        except Exception:
            return False
        if start_line > len(lines):
            return False

        indexed_end = self._safe_int(
            info.get("end_line") or info.get("lineNumberEnd"),
            start_line,
        )
        scan_end = min(len(lines), max(start_line, indexed_end, start_line + 20))
        header = "".join(lines[start_line - 1 : scan_end]).split("{", 1)[0]
        return self._function_header_has_static(header, function_name)

    def _function_header_has_static(self, text: str, function_name: str) -> bool:
        masked = self._mask_c_comments_and_literals(str(text or ""))
        simple_name = self._cpp_simple_name(self._strip_cpp_template_args(function_name))
        simple_name = simple_name.lstrip("~")
        prefix = masked.split("(", 1)[0]
        if simple_name:
            matches = list(re.finditer(rf"\b{re.escape(simple_name)}\s*\(", masked))
            if matches:
                prefix = masked[: matches[-1].start()]
        return bool(re.search(r"\bstatic\b", prefix))

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

    def find_type_infos(
        self,
        type_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Return normalized public type records for every matching definition."""
        if not self._backend:
            return []
        getter = getattr(self._backend, "find_type_infos", None)
        if callable(getter):
            try:
                raw_matches = getter(type_name, file_path=file_path)
            except TypeError:
                raw_matches = getter(type_name, file_path)
        else:
            info = self._backend.get_type_info(type_name)
            raw_matches = [info] if info else []

        matches: List[Dict[str, Any]] = []
        for raw_match in raw_matches or []:
            if not isinstance(raw_match, dict):
                continue
            item = dict(raw_match)
            raw_file = str(item.get("file_path") or item.get("filename") or "")
            if file_path and not self._paths_match_hint(raw_file, file_path):
                continue
            item["file_path"] = self._normalize_index_file_value(raw_file)
            item.pop("filename", None)
            if "start_line" not in item and "lineNumber" in item:
                item["start_line"] = self._safe_int(item.get("lineNumber"))
            if "end_line" not in item and "lineNumberEnd" in item:
                item["end_line"] = self._safe_int(item.get("lineNumberEnd"))
            item.pop("lineNumber", None)
            item.pop("lineNumberEnd", None)
            item.pop("id", None)
            item.pop("tu_id", None)
            item.pop("members", None)
            matches.append(item)
        matches.sort(
            key=lambda item: (
                str(item.get("file_path") or ""),
                self._safe_int(item.get("start_line")),
                str(item.get("kind") or ""),
                str(item.get("name") or ""),
            )
        )
        return matches

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

    def _find_macro_impls(
        self,
        macro_name: str,
        *,
        file_path: str = "",
        max_lines: Optional[int] = 500,
        function_like_only: bool = False,
        include_callees: bool = True,
        exact_location_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Return stable macro implementation candidates from backend or regex facts."""
        clean_name, inferred_file = self._macro_query_parts(macro_name)
        file_hint = str(file_path or inferred_file or "")
        if not clean_name:
            return []

        records: List[Dict[str, Any]] = []
        getter = (
            getattr(self._backend, "get_macro_definitions", None)
            if self._backend
            else None
        )
        if callable(getter):
            try:
                records = [
                    dict(record)
                    for record in list(getter(clean_name, limit=1_000_000) or [])
                    if isinstance(record, dict)
                ]
                for record in records:
                    record.setdefault("name", clean_name)
            except Exception as exc:
                logger.debug("Backend macro lookup failed for %s: %s", clean_name, exc)

        records = self._filter_macro_definition_records(
            records,
            file_path=file_hint,
            function_like_only=function_like_only,
        )
        if not records:
            with self._cache_lock:
                known_missing = clean_name in self._macro_definition_miss_cache
            regex_records = [] if known_missing else list(
                self._get_macro_definition_index().get(clean_name, [])
            )
            if not regex_records and not known_missing:
                with self._cache_lock:
                    self._macro_definition_miss_cache.add(clean_name)
            records = self._filter_macro_definition_records(
                regex_records,
                file_path=file_hint,
                function_like_only=function_like_only,
            )

        if exact_location_only:
            _, _, query_start, query_end = self._function_location_query_parts(macro_name)
            if query_start <= 0:
                return []
            records = [
                record
                for record in records
                if self._safe_int(record.get("line") or record.get("start_line"), 1)
                == query_start
                and self._macro_record_end_line(record) == query_end
            ]

        payloads = [
            self._macro_definition_payload(
                clean_name,
                record,
                max_lines=max_lines,
                include_callees=include_callees,
            )
            for record in records
        ]
        return payloads

    def _filter_macro_definition_records(
        self,
        records: Iterable[Dict[str, Any]],
        *,
        file_path: str,
        function_like_only: bool,
    ) -> List[Dict[str, Any]]:
        filtered: Dict[Tuple[str, str, int], Dict[str, Any]] = {}
        for raw_record in records:
            record = dict(raw_record or {})
            record_file = str(record.get("file_path") or record.get("file") or "")
            if file_path and not self._paths_match_hint(record_file, file_path):
                continue
            if function_like_only and not self._macro_record_is_function_like(record):
                continue
            normalized_file = self._normalize_index_file_value(record_file)
            line = self._safe_int(record.get("line") or record.get("start_line"), 1)
            key = (str(record.get("name") or ""), normalized_file, line)
            filtered.setdefault(key, record)
        return sorted(
            filtered.values(),
            key=lambda record: (
                self._normalize_index_file_value(
                    str(record.get("file_path") or record.get("file") or "")
                ),
                self._safe_int(record.get("line") or record.get("start_line"), 1),
            ),
        )

    @staticmethod
    def _macro_record_is_function_like(record: Dict[str, Any]) -> bool:
        if "is_function_like" in record:
            return bool(record.get("is_function_like"))
        first_line = str(record.get("definition") or "").splitlines()[0:1]
        if not first_line:
            return False
        parsed = CodeIndex._parse_macro_definition_line(first_line[0])
        return bool(parsed and parsed.get("is_function_like"))

    @staticmethod
    def _macro_record_end_line(record: Dict[str, Any]) -> int:
        start_line = int(record.get("line") or record.get("start_line") or 1)
        definition_lines = str(record.get("definition") or "").splitlines()
        return start_line + max(1, len(definition_lines)) - 1

    @staticmethod
    def _macro_query_parts(query: str) -> Tuple[str, str]:
        raw = str(query or "").strip()
        if raw.startswith("#define"):
            raw = raw[len("#define") :].strip()
        index_match = re.match(
            r"^(?P<name>[A-Za-z_]\w*)@(?P<file>.+):\d+-\d+$",
            raw,
        )
        if index_match:
            return index_match.group("name"), index_match.group("file")
        name_match = re.match(r"^(?P<name>[A-Za-z_]\w*)(?:\s*\(|$)", raw)
        if not name_match:
            return "", ""
        return name_match.group("name"), ""

    def _get_global_definition_index(self) -> Dict[str, List[Dict[str, Any]]]:
        with self._cache_lock:
            if self._global_definition_index is not None:
                return self._global_definition_index

        with self._global_definition_index_lock:
            with self._cache_lock:
                if self._global_definition_index is not None:
                    return self._global_definition_index

            declaration_re = re.compile(
                r"^\s*(?P<prefix>(?:(?:extern|static|const|volatile|register|signed|unsigned|"
                r"short|long|_Atomic)\s+)*(?:struct\s+[A-Za-z_]\w*|union\s+[A-Za-z_]\w*|"
                r"enum\s+[A-Za-z_]\w*|[A-Za-z_]\w*)(?:\s+|\s*\*+\s*))"
                r"(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*"
                r"(?:=(?P<initializer>.*?))?;\s*$"
            )
            index: Dict[str, List[Dict[str, Any]]] = {}
            for file_name in sorted(self._find_all_files()):
                file_path = self._resolve_file_path(file_name)
                try:
                    lines = self._read_file_lines(file_path)
                except Exception:
                    continue
                brace_depth = 0
                for line_no, raw_line in enumerate(lines, start=1):
                    masked_line = self._mask_function_info_source_line(raw_line)
                    if brace_depth == 0 and not masked_line.lstrip().startswith("#"):
                        match = declaration_re.match(masked_line)
                        if match and "(" not in str(match.group("prefix") or ""):
                            prefix = str(match.group("prefix") or "").strip()
                            initializer = str(match.group("initializer") or "").strip()
                            is_extern = bool(re.search(r"\bextern\b", prefix))
                            if re.search(r"\bstatic\b", prefix):
                                storage_class = "static"
                            elif is_extern:
                                storage_class = "extern"
                            else:
                                storage_class = "global"
                            qualifiers = ",".join(
                                qualifier
                                for qualifier in ("const", "volatile", "atomic")
                                if (
                                    re.search(rf"\b{qualifier}\b", prefix)
                                    if qualifier != "atomic"
                                    else re.search(r"\b_Atomic\b", prefix)
                                )
                            )
                            name = match.group("name")
                            index.setdefault(name, []).append(
                                {
                                    "name": name,
                                    "type": prefix,
                                    "file_path": normalize_path(file_path, self.project_root),
                                    "line": line_no,
                                    "is_extern": is_extern,
                                    "storage_class": storage_class,
                                    "qualifiers": qualifiers,
                                    "initializer": initializer[:500],
                                    "definition_kind": (
                                        "declaration"
                                        if is_extern and not initializer
                                        else "definition"
                                    ),
                                }
                            )
                    brace_depth += masked_line.count("{") - masked_line.count("}")
                    brace_depth = max(0, brace_depth)

            for records in index.values():
                records.sort(
                    key=lambda row: (
                        str(row.get("file_path") or ""),
                        int(row.get("line") or 0),
                    )
                )
            with self._cache_lock:
                self._global_definition_index = index
                return self._global_definition_index

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
        max_lines: Optional[int] = 500,
        macro_alternates_count: int = 0,
        include_callees: bool = True,
    ) -> Dict[str, Any]:
        definition = str(record.get("definition") or "")
        definition_lines = definition.splitlines(True)
        if not definition_lines:
            definition_lines = [definition]
        start_line = int(record.get("line") or record.get("start_line") or 1)
        full_line_count = max(1, len(definition_lines))
        if max_lines is None:
            code_lines = definition_lines
        else:
            code_lines = definition_lines[: max(0, int(max_lines or 500))]
        end_line = start_line + len(code_lines) - 1 if code_lines else start_line - 1
        code = self._numbered_code(code_lines, start_line - 1)
        file_value = str(record.get("file_path") or record.get("file") or "")
        resolved_file = self._resolve_file_path(file_value) if file_value else self.project_root
        callees: List[str] = []
        if include_callees:
            replacement_body = self._macro_replacement_body(
                macro_name,
                code_lines,
            )
            callees = self._filter_callee_names(extract_function_calls(replacement_body))
        result = {
            "func_name": macro_name,
            "file": normalize_path(resolved_file, self.project_root),
            "start_line": start_line,
            "end_line": end_line,
            "code": code,
            "callees": callees,
            "signature": self._macro_signature(
                macro_name,
                definition_lines[0] if definition_lines else "",
                bool(record.get("is_function_like")),
            ),
            "truncated": full_line_count > len(code_lines),
            "is_macro": True,
        }
        result["index_name"] = self._macro_impl_index_name(result)
        if macro_alternates_count:
            result["macro_alternates_count"] = macro_alternates_count
        return result

    @staticmethod
    def _macro_replacement_body(macro_name: str, definition_lines: Sequence[str]) -> str:
        if not definition_lines:
            return ""
        first_line = str(definition_lines[0] or "")
        match = re.match(
            rf"^\s*#\s*define\s+{re.escape(macro_name)}(?P<tail>(?:\s.*|\(.*|$))$",
            first_line,
        )
        if not match:
            return "".join(definition_lines)

        tail = str(match.group("tail") or "")
        if tail.startswith("("):
            depth = 0
            body_start = len(tail)
            for idx, char in enumerate(tail):
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        body_start = idx + 1
                        break
            first_body = tail[body_start:]
        else:
            first_body = tail

        return first_body + "".join(definition_lines[1:])

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
            self._global_definition_index = None
            self._macro_definition_miss_cache.clear()
        if self._backend:
            self._backend.close()
