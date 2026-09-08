"""
Code indexing and function locator for C projects.
Supports pluggable backends (Joern / Clang-SQLite / regex fallback).
"""

import logging
import os
import re
import threading
import time
from bisect import bisect_right
from collections import OrderedDict
from pathlib import Path
from typing import Optional, Dict, Any, Iterable, List, Sequence, Union, Tuple

from ..common.utils import (
    extract_function_calls,
    is_likely_function_call_identifier,
    normalize_path,
)
from ..common.runtime_limits import ensure_linux_nofile_limit
from .backend_base import CodeBackend
from .indexing_runtime import observed

logger = logging.getLogger(__name__)

DECLARATION_LINE_RE = re.compile(
    r"^[ \t]*(?!(?:return|if|while|for|switch)\b)"
    r"(?:[A-Za-z_]\w*[\s*]+)+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;"
)

FUNCTION_INFO_CALLEES_LIMIT = 30
FUNCTION_INFO_EXTERNAL_CALLEES_LIMIT = 20
FUNCTION_INFO_UNRESOLVED_CALLEES_LIMIT = 20
FUNCTION_INFO_GLOBALS_LIMIT = 50
FUNCTION_INFO_MACROS_LIMIT = 50
REFERENCED_TYPES_LIMIT = 30
REFERENCED_TYPE_DEFINITION_BYTES_LIMIT = 8 * 1024
REFERENCED_TYPES_DEFINITION_BYTES_LIMIT = 32 * 1024
REFERENCED_TYPE_KIND_ORDER = (
    "return",
    "parameter",
    "function_pointer",
    "local",
    "cast",
    "sizeof",
    "alignof",
    "offsetof",
    "compound_literal",
    "member_access",
)
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
        self.backend_name = indexing_config.backend if indexing_config else "regex"
        self._require_configured_backend = bool(
            indexing_config is not None
            and backend is None
            and str(self.backend_name or "regex").lower() != "regex"
        )
        self.language = (
            "java"
            if str(self.backend_name or "").lower() in {"java_source", "java_unified", "joern"}
            else "c_cpp"
        )
        self._capability_lock = threading.RLock()
        self._engine_capabilities: Dict[str, Dict[str, Any]] = {
            "index": {
                "configured": str(self.backend_name or "regex").lower(),
                "active": "initializing",
                "status": "pending",
                "reason": "",
            }
        }
        self._function_index: Dict[str, Dict[str, Any]] = {}
        self._function_alias_index: Dict[str, str] = {}
        self._ambiguous_function_aliases: set[str] = set()
        self._function_query_index: Dict[str, set[str]] = {}
        self._function_record_variants: Dict[str, set[str]] = {}
        self._function_file_index: Dict[str, set[str]] = {}
        self._function_file_resolution_cache: Dict[Tuple[str, str], str] = {}
        self._declaration_comment_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._regex_type_definition_cache: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._backend: Optional[CodeBackend] = backend
        self._backend_index_fallback = False
        self._svf_entry_functions = list(svf_entry_functions or [])
        self._defer_svf = defer_svf
        self._svf_parallel_workers = max(1, int(svf_parallel_workers or 1))
        self._index_ready = False
        self._index_epoch = 0
        self._cache_lock = threading.RLock()
        self._declaration_comment_index_lock = threading.Lock()
        self._macro_definition_index_lock = threading.Lock()
        self._global_definition_index_lock = threading.Lock()
        self._file_lines_cache: Dict[str, Tuple[str, ...]] = {}
        self._function_impl_cache: Dict[Tuple[str, Optional[int], bool, str], Dict[str, Any]] = {}
        self._macro_definition_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._global_definition_index: Optional[Dict[str, List[Dict[str, Any]]]] = None
        self._macro_definition_miss_cache: set[str] = set()
        self._shared_cache_budget_bytes = max(
            1,
            int(
                getattr(indexing_config, "shared_cache_max_bytes", 512 * 1024 * 1024)
                if indexing_config is not None
                else 512 * 1024 * 1024
            ),
        )
        self._shared_cache_bytes = 0
        self._shared_cache_lru: "OrderedDict[Tuple[str, Any], int]" = OrderedDict()

        # 向后兼容：如果传入了 joern_client，包装为 JoernBackend
        if self._backend is None and joern_client is not None:
            from .joern_backend import JoernBackend

            self._backend = JoernBackend(joern_client=joern_client)
            self._backend._status = "ready"

        # 根据配置自动创建后端
        if self._backend is None:
            self._backend = self._create_backend(indexing_config, wait_for_cpg)
        elif "java" in type(self._backend).__name__.lower():
            self.language = "java"
            self.backend_name = (
                "java_unified"
                if "unified" in type(self._backend).__name__.lower()
                else "java_source"
            )
        elif indexing_config is None:
            # Historical callers inject the C/C++ Joern-compatible backend directly.
            # Preserve that configured identity so fallback health remains truthful.
            self.backend_name = "joern"
        self._refresh_capability_status(initial=True)

        if wait_for_cpg:
            self._initialize_supplied_backend_if_needed()
            self._build_index()
            self._index_ready = True
            self._refresh_capability_status()

    def _initialize_supplied_backend_if_needed(self) -> None:
        """Initialize externally supplied real backends while leaving test stubs alone."""

        if not self._backend:
            return
        initialize = getattr(self._backend, "initialize", None)
        status = getattr(self._backend, "status", None)
        if not callable(initialize) or not callable(status):
            return
        try:
            if status() != "idle":
                return
            initialize(
                str(self.source_root),
                project_root=self.project_root,
                compile_commands_path=(
                    str(self.compile_commands_path) if self.compile_commands_path else None
                ),
                wait=True,
                include_paths=self.include_paths,
                exclude_paths=self.exclude_paths,
            )
        except Exception as exc:
            logger.debug("Externally supplied backend initialization failed: %s", exc)

    def _create_backend(self, indexing_config, wait_for_cpg: bool) -> Optional[CodeBackend]:
        """根据 indexing_config 创建对应的后端实例。"""
        backend_name = indexing_config.backend if indexing_config else "regex"

        if backend_name == "joern":
            cfg = indexing_config
            from .java_joern_backend import JavaJoernBackend

            language = "java"
            jb = JavaJoernBackend(
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
                language=language,
                include_paths=self.include_paths,
                exclude_paths=self.exclude_paths,
            )
            if not ok and wait_for_cpg:
                raise RuntimeError(f"{backend_name} backend initialization failed")
            return jb

        if backend_name == "java_source":
            from .java_source_backend import JavaSourceBackend

            cfg = indexing_config
            java_backend = JavaSourceBackend(
                frontend=getattr(cfg, "java_structure_frontend", "auto") if cfg else "auto",
                extractor_command=(
                    getattr(cfg, "java_structure_extractor_command", []) if cfg else []
                ),
                structure_db_path=self._java_structure_db_path(cfg),
            )
            ok = java_backend.initialize(
                str(self.source_root),
                project_root=self.project_root,
                wait=wait_for_cpg,
                include_paths=self.include_paths,
                exclude_paths=self.exclude_paths,
            )
            if not ok and wait_for_cpg:
                raise RuntimeError("java_source backend initialization failed")
            self.language = "java"
            return java_backend

        if backend_name == "java_unified":
            from .java_unified_backend import JavaUnifiedBackend

            cfg = indexing_config
            java_unified_backend = JavaUnifiedBackend(
                structure_frontend=(
                    getattr(cfg, "java_structure_frontend", "auto") if cfg else "auto"
                ),
                structure_extractor_command=(
                    getattr(cfg, "java_structure_extractor_command", []) if cfg else []
                ),
                structure_db_path=self._java_structure_db_path(cfg),
                signal_backends=getattr(cfg, "java_signal_backends", []) if cfg else [],
                signal_provider_commands=(
                    getattr(cfg, "java_signal_provider_commands", {}) if cfg else {}
                ),
                joern_path=getattr(cfg, "joern_path", "joern") if cfg else "joern",
                joern_host=(getattr(cfg, "joern_server_host", "127.0.0.1") if cfg else "127.0.0.1"),
                joern_port=getattr(cfg, "joern_server_port", 8080) if cfg else 8080,
                joern_heap_size=getattr(cfg, "joern_heap_size", "8g") if cfg else "8g",
            )
            ok = java_unified_backend.initialize(
                str(self.source_root),
                project_root=self.project_root,
                wait=wait_for_cpg,
                include_paths=self.include_paths,
                exclude_paths=self.exclude_paths,
            )
            if not ok and wait_for_cpg:
                raise RuntimeError("java_unified backend initialization failed")
            self.language = "java"
            return java_unified_backend

        if backend_name == "clang":
            from .clang_backend import ClangBackend

            cfg = indexing_config
            cb = ClangBackend(
                frontend=getattr(cfg, "clang_frontend", "auto"),
                clang_indexer_path=getattr(cfg, "clang_indexer_path", "zscope-clang-indexer"),
                clangd_path=cfg.clangd_path if cfg else "clangd",
                db_path=cfg.knowledge_db_path if cfg else ".zscope_knowledge/code_knowledge.db",
                batch_size=cfg.batch_size if cfg else 50,
                max_threads=cfg.max_clangd_threads if cfg else 4,
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
                raise RuntimeError("clang backend initialization failed")
            return cb

        if backend_name == "unified":
            from .unified_backend import UnifiedBackend

            cfg = indexing_config
            ub = UnifiedBackend(
                clang_frontend=getattr(cfg, "clang_frontend", "auto"),
                clang_indexer_path=getattr(cfg, "clang_indexer_path", "zscope-clang-indexer"),
                clangd_path=cfg.clangd_path if cfg else "clangd",
                db_path=cfg.knowledge_db_path if cfg else ".zscope_knowledge/code_knowledge.db",
                batch_size=cfg.batch_size if cfg else 50,
                max_threads=cfg.max_clangd_threads if cfg else 4,
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
                raise RuntimeError("unified backend initialization failed")
            return ub

        if backend_name == "regex":
            return None
        raise ValueError(f"unsupported indexing backend: {backend_name!r}")

    def _java_structure_db_path(self, indexing_config: Any) -> str:
        configured = str(getattr(indexing_config, "java_structure_db_path", "") or "").strip()
        if configured:
            path = Path(configured)
            return str(path if path.is_absolute() else (self.project_root / path).resolve())
        knowledge_db = str(getattr(indexing_config, "knowledge_db_path", "") or "")
        if knowledge_db:
            path = Path(knowledge_db)
            if not path.is_absolute():
                path = self.project_root / path
            return str(path.resolve().with_name("java_structure.db"))
        return str((self.project_root / ".zscope_knowledge" / "java_structure.db").resolve())

    def ensure_index_ready(self, timeout: Optional[int] = None) -> bool:
        """Wait for backend and build index. For non-blocking mode."""
        if self._index_ready:
            return True
        if self._backend and hasattr(self._backend, "wait_for_ready"):
            if not self._backend.wait_for_ready(timeout=timeout):
                if self._require_configured_backend:
                    raise RuntimeError(
                        f"configured {self.backend_name} backend failed or timed out"
                    )
                logger.warning("Backend build failed or timed out")
                self._set_engine_capability(
                    "index",
                    status="degraded",
                    active="regex",
                    reason="configured_backend_failed_or_timed_out",
                )
                self._backend.close()
                self._backend = None
        self._build_index()
        self._index_ready = True
        self._refresh_capability_status()
        return True

    def run_svf(self, entry_functions: Optional[Sequence[Any]] = None) -> bool:
        """Run deferred SVF enrichment when the active backend supports it."""
        if not self._backend or not hasattr(self._backend, "run_svf"):
            if str(self.backend_name or "").lower() in {"unified", "svf"}:
                self._set_engine_capability(
                    "svf",
                    configured=True,
                    active=False,
                    status="failed",
                    reason="svf_backend_unavailable",
                )
            return False
        entries = list(entry_functions or self._svf_entry_functions)
        self._svf_entry_functions = entries
        ok = bool(getattr(self._backend, "run_svf")(entry_functions=entries))
        if ok:
            self._clear_function_impl_cache()
        self._set_engine_capability(
            "svf",
            configured=True,
            active=ok,
            status="complete" if ok else "failed",
            reason="" if ok else "svf_execution_failed",
        )
        if not ok and self._require_configured_backend:
            raise RuntimeError("configured unified backend failed SVF enrichment")
        return ok

    def capability_status(self) -> Dict[str, Dict[str, Any]]:
        """Return truthful configured/active engine health for report schema v2."""
        self._refresh_capability_status()
        with self._capability_lock:
            return {name: dict(details) for name, details in self._engine_capabilities.items()}

    def _refresh_capability_status(self, *, initial: bool = False) -> None:
        configured = str(self.backend_name or "regex").lower()
        backend = self._backend
        active = type(backend).__name__ if backend is not None else "regex"
        if self._backend_index_fallback:
            status = "degraded"
            reason = "configured_backend_index_empty_regex_fallback"
            active = f"{active}+regex"
        elif backend is None and configured != "regex":
            status = "degraded"
            reason = "configured_backend_unavailable_regex_fallback"
        else:
            backend_status = str(getattr(backend, "_status", "") or "").lower()
            if backend_status in {"failed", "error", "timeout"}:
                status = "degraded"
                reason = f"backend_{backend_status}"
            elif initial and not self._index_ready:
                status = "pending"
                reason = ""
            else:
                status = "complete"
                reason = ""
        self._set_engine_capability(
            "index",
            configured=configured,
            active=active,
            status=status,
            reason=reason,
            ready=bool(self._index_ready),
        )
        if configured in {"unified", "svf"}:
            svf_available = bool(getattr(backend, "_svf_available", False))
            existing = self._engine_capabilities.get("svf", {})
            if svf_available:
                svf_status = "complete"
                svf_reason = ""
            elif existing.get("status") == "failed":
                svf_status = "failed"
                svf_reason = str(existing.get("reason") or "svf_execution_failed")
            elif not self._defer_svf:
                svf_status = "failed"
                svf_reason = "svf_not_available"
            else:
                svf_status = "pending"
                svf_reason = "svf_deferred" if self._defer_svf else "svf_not_available"
            self._set_engine_capability(
                "svf",
                configured=True,
                active=svf_available,
                status=svf_status,
                reason=svf_reason,
            )

    def _set_engine_capability(self, name: str, **values: Any) -> None:
        with self._capability_lock:
            current = dict(self._engine_capabilities.get(name, {}))
            current.update(values)
            self._engine_capabilities[name] = current

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

    @observed("function-name-index")
    def _build_index(self) -> None:
        """Build function index from project."""
        with self._cache_lock:
            self._index_epoch += 1
            self._function_index.clear()
            self._function_alias_index.clear()
            self._ambiguous_function_aliases.clear()
            self._function_query_index.clear()
            self._function_record_variants.clear()
            self._function_file_index.clear()
            self._function_file_resolution_cache.clear()

        if self._backend:
            backend_index = self._backend.build_function_index()
            if backend_index:
                self._backend_index_fallback = False
                for raw_name, raw_info in backend_index.items():
                    info = dict(raw_info or {})
                    aliases = info.get("aliases") if isinstance(info.get("aliases"), list) else None
                    self._add_function_index_entry(str(raw_name), info, aliases=aliases)
            else:
                if self._require_configured_backend:
                    raise RuntimeError(
                        f"configured {self.backend_name} backend returned an empty index"
                    )
                logger.warning("Backend index returned empty, using regex index")
                self._backend_index_fallback = True
                self._set_engine_capability(
                    "index",
                    status="degraded",
                    active=f"{type(self._backend).__name__}+regex",
                    reason="configured_backend_index_empty_regex_fallback",
                )
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
        if info.get("language") == "java" and info.get("qualified_name"):
            canonical_name = str(info.get("qualified_name") or "").strip()
            self.language = "java"
        else:
            canonical_name = self._normalize_cpp_function_name(raw_name)
        if not canonical_name:
            return ""

        record = dict(info)
        record["name"] = raw_name
        record["qualified_name"] = canonical_name
        raw_file = str(record.get("file") or record.get("filename") or "")
        if raw_file:
            canonical_file = self._normalize_index_file_value(raw_file)
            record["file"] = canonical_file
            if "filename" in record:
                record["filename"] = canonical_file
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
            if index_key in self._function_index:
                # A lazy backend may replace a signature at the same location.
                # Its old fast aliases must not outlive the old variant postings.
                for alias, target in list(self._function_alias_index.items()):
                    if target == index_key:
                        self._function_alias_index.pop(alias, None)
            self._function_index[index_key] = record
            self._register_function_query_index(index_key, record)
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
        file_part = self._normalize_index_file_value(file_value)
        start_line = self._safe_int(record.get("start_line") or record.get("lineNumber"))
        end_line = self._safe_int(record.get("end_line") or record.get("lineNumberEnd"))
        if end_line < start_line:
            end_line = start_line
        return f"{canonical_name}@{file_part}:{start_line}-{end_line}"

    @staticmethod
    def _same_function_location(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
        left_file = str(left.get("file") or left.get("filename") or "").replace("\\", "/")
        right_file = str(right.get("file") or right.get("filename") or "").replace("\\", "/")
        return left_file == right_file and int(
            left.get("start_line") or left.get("lineNumber") or 0
        ) == int(right.get("start_line") or right.get("lineNumber") or 0)

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
        ordered_variants = self._function_query_variants(func_name)
        query_variants = set(ordered_variants)
        if not query_variants:
            return []

        if not file_path:
            with self._cache_lock:
                for variant in ordered_variants:
                    info = self._function_index.get(variant)
                    if info is not None:
                        return [(variant, dict(info))]
                for variant in ordered_variants:
                    alias = self._function_alias_index.get(variant)
                    if alias and alias in self._function_index:
                        return [(alias, dict(self._function_index[alias]))]

        # Missing names and ambiguous aliases used to copy and normalize every
        # function for every query. Preserve all matches in an inverted index.
        with self._cache_lock:
            candidate_keys: set[str] = set()
            for variant in query_variants:
                candidate_keys.update(self._function_query_index.get(variant, ()))
            matches = [
                (key, dict(self._function_index[key]))
                for key in candidate_keys
                if key in self._function_index
                and (
                    not file_path
                    or self._record_matches_file_hint(self._function_index[key], file_path)
                )
            ]

        matches.sort(
            key=lambda item: (
                self._function_info_match_rank(query_variants, item[0], item[1]),
                str(item[1].get("file") or item[1].get("filename") or ""),
                int(item[1].get("start_line") or item[1].get("lineNumber") or 0),
                item[0],
            )
        )
        return matches

    def _register_function_query_index(self, index_key: str, record: Dict[str, Any]) -> None:
        """Maintain postings on insert/replace, independently of evictable query caches."""
        for variant in self._function_record_variants.pop(index_key, ()):
            keys = self._function_query_index[variant]
            keys.discard(index_key)
            if not keys:
                del self._function_query_index[variant]
        variants = self._function_record_query_variants(index_key, record)
        self._function_record_variants[index_key] = variants
        for variant in variants:
            self._function_query_index.setdefault(variant, set()).add(index_key)

    def _has_indexed_function(self, name: str) -> bool:
        """Header enumeration only needs existence, including ambiguous names."""
        variants = self._function_query_variants(name)
        with self._cache_lock:
            return any(
                variant in self._function_index
                or self._function_alias_index.get(variant) in self._function_index
                or bool(self._function_query_index.get(variant))
                for variant in variants
            )

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
            method_full_name = str(
                method.get("qualified_name")
                or method.get("method_full_name")
                or method.get("fullName")
                or method.get("name")
                or candidate
            )
            method_record = {
                "name": method.get("name") or candidate,
                "qualified_name": method_full_name,
                "method_full_name": method_full_name,
                "file": method_file,
                "start_line": method.get("lineNumber", -1),
                "end_line": method.get("lineNumberEnd", -1),
                "signature": method.get("signature", f"{candidate}(...)"),
                "declaration_code": method.get("declaration_code", method.get("code", "")),
                "annotations": method.get("annotations", []),
                "parameter_annotations": method.get(
                    "parameter_annotations", method.get("parameterAnnotations", [])
                ),
                "class_annotations": method.get(
                    "class_annotations", method.get("classAnnotations", [])
                ),
                "framework_semantics": method.get("framework_semantics", {}),
                "class_name": method.get("class_name", ""),
                "package": method.get("package", ""),
                "language": method.get("language") or self.language,
            }
            if "is_static" in method:
                method_record["is_static"] = method.get("is_static")
            self._add_function_index_entry(
                (
                    method_full_name
                    if method_record["language"] == "java"
                    else str(method.get("name") or candidate)
                ),
                method_record,
                aliases=[str(method.get("name") or ""), method_full_name.split(":", 1)[0]],
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

    def _function_file_resolution_cache_key(
        self, func_name: str, file_path: str
    ) -> Tuple[str, str]:
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
        return stored == hint or stored.endswith(f"/{hint}") or hint.endswith(f"/{stored}")

    def _is_path_allowed(self, p: Path) -> bool:
        """Check if a path passes include/exclude filters."""

        def is_subpath(child: Path, parent: Path) -> bool:
            try:
                # Use absolute() instead of resolve() to avoid symlink physical path jumping out of bounds
                c_str = str(child.absolute())
                p_str = str(parent.absolute())

                # Case-insensitive ONLY on Windows
                if os.name == "nt":
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

    @staticmethod
    def _normalize_project_language(language: object) -> str:
        text = str(language or "c_cpp").strip().lower().replace("-", "_")
        if text in {"java", "javasrc", "java_src"}:
            return "java"
        return "c_cpp"

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
        normalized = self._normalize_function_query(raw)
        variants = []
        for candidate in (
            raw,
            normalized,
            self._strip_cpp_template_args(normalized),
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
        if self.language == "java":
            extensions = {".java"}
        seen = set()

        bases_to_search = self.include_paths if self.include_paths else [self.source_root]
        # Overlapping include roots otherwise walk the same subtree once per
        # covering root; drop any base nested inside an already-kept root.
        bases_to_search = self._dedupe_contained_bases(bases_to_search)

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

    @staticmethod
    def _dedupe_contained_bases(bases: Iterable[Path]) -> List[Path]:
        """Drop include roots nested inside another root (single walk each)."""
        kept: List[Path] = []
        for base in sorted(
            {Path(value) for value in bases}, key=lambda p: len(p.parts)
        ):
            covered = False
            for parent in kept:
                try:
                    base.relative_to(parent)
                    covered = True
                    break
                except ValueError:
                    continue
            if not covered:
                kept.append(base)
        return kept

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
        *,
        class_scope: Optional[str] = None,
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

        if class_scope is None:
            class_scope = self._enclosing_cpp_type_name(lines or (), start_line)
        simple_name = self._cpp_simple_name(self._strip_cpp_template_args(canonical_name))
        parent_name = ""
        if "::" in canonical_name:
            parent_name = self._cpp_tail_name(
                self._strip_cpp_template_args(canonical_name),
                2,
            ).split(
                "::"
            )[0]
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
        *,
        class_scope: Optional[str] = None,
    ) -> Optional[Dict[str, str]]:
        stripped = str(line or "").strip()
        if not stripped.endswith(";") or "(" not in stripped or "{" in stripped:
            return None
        if stripped.startswith(("#", "typedef ", "using ")):
            return None
        return self._parse_cpp_function_signature(
            stripped[:-1], lines, line_no, class_scope=class_scope
        )

    def _enclosing_cpp_type_name(self, lines: Sequence[str], start_line: int) -> str:
        """Return the innermost class/struct name active before start_line."""
        if not lines or start_line <= 1:
            return ""
        return self._cpp_type_scopes(lines[: max(0, start_line - 1)])[-1]

    @staticmethod
    def _cpp_type_scopes(lines: Sequence[str]) -> List[str]:
        """Scope before each line, plus the final scope, in a single file pass."""
        scopes = [""]

        stack: List[Tuple[str, int]] = []
        brace_depth = 0
        pending_type = ""
        in_block_comment = False

        for raw_line in lines:
            line = raw_line
            if in_block_comment:
                if "*/" in line:
                    line = line.split("*/", 1)[1]
                    in_block_comment = False
                else:
                    scopes.append(scopes[-1])
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
            scopes.append("::".join(item[0] for item in stack))

        return scopes

    def _extract_functions_regex(self, file_path: Union[str, Path], content: str) -> None:
        """Extract function definitions using regex."""
        lines = content.split("\n")
        scopes = self._cpp_type_scopes(lines)
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
            parsed = self._parse_cpp_function_signature(
                before_brace, lines, pending_start, class_scope=scopes[pending_start - 1]
            )
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
                    "is_static": bool(re.search(r"\bstatic\b", before_brace.split("(", 1)[0])),
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
        key = key.lower() if os.name == "nt" else key
        try:
            stat = path.stat()
            return f"{key}|{stat.st_mtime_ns}|{stat.st_size}"
        except OSError:
            return f"{key}|missing"

    def _source_fingerprint(self, file_path: Union[str, Path]) -> str:
        return f"epoch={self._index_epoch}|source={self._file_cache_key(file_path)}"

    def _read_file_lines(self, file_path: Union[str, Path]) -> List[str]:
        """Read source file lines through the per-run cache."""
        cache_key = self._file_cache_key(file_path)
        with self._cache_lock:
            cached = self._file_lines_cache.get(cache_key)
            if cached is not None:
                self._touch_shared_cache("file", cache_key)
                return list(cached)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = tuple(f.readlines())

        with self._cache_lock:
            cached = self._file_lines_cache.get(cache_key)
            if cached is None:
                cached = lines
                self._file_lines_cache[cache_key] = cached
                self._record_shared_cache_value("file", cache_key, cached)
            else:
                self._touch_shared_cache("file", cache_key)
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
        return {str(key): self._clone_function_impl_value(value) for key, value in result.items()}

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
            self._touch_shared_cache("function", cache_key)
            return self._clone_function_impl(cached)

    def _store_function_impl_cache(
        self,
        cache_key: Tuple[str, Optional[int], bool, str],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        with self._cache_lock:
            stored = self._clone_function_impl(result)
            self._function_impl_cache[cache_key] = stored
            self._record_shared_cache_value(
                "function",
                cache_key,
                stored,
            )
            return self._clone_function_impl(stored)

    @staticmethod
    def _shared_cache_value_size(value: Any) -> int:
        if isinstance(value, tuple) and all(isinstance(item, str) for item in value):
            return sum(len(item.encode("utf-8", errors="ignore")) for item in value)
        try:
            import json

            return len(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=str,
                ).encode("utf-8")
            )
        except Exception:
            return len(repr(value).encode("utf-8", errors="ignore"))

    def _touch_shared_cache(self, namespace: str, key: Any) -> None:
        lru_key = (namespace, key)
        if lru_key in self._shared_cache_lru:
            self._shared_cache_lru.move_to_end(lru_key)

    def _record_shared_cache_value(
        self,
        namespace: str,
        key: Any,
        value: Any,
    ) -> None:
        lru_key = (namespace, key)
        previous = self._shared_cache_lru.pop(lru_key, 0)
        size = self._shared_cache_value_size(value)
        self._shared_cache_lru[lru_key] = size
        self._shared_cache_bytes += size - previous
        while self._shared_cache_bytes > self._shared_cache_budget_bytes and self._shared_cache_lru:
            (evict_namespace, evict_key), evict_size = self._shared_cache_lru.popitem(last=False)
            self._shared_cache_bytes = max(0, self._shared_cache_bytes - evict_size)
            if evict_namespace == "file":
                self._file_lines_cache.pop(evict_key, None)
            elif evict_namespace == "function":
                self._function_impl_cache.pop(evict_key, None)

    def _clear_function_impl_cache(self) -> None:
        with self._cache_lock:
            self._function_impl_cache.clear()
            self._shared_cache_lru = OrderedDict(
                (key, size) for key, size in self._shared_cache_lru.items() if key[0] != "function"
            )
            self._shared_cache_bytes = sum(self._shared_cache_lru.values())
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
            "file": self._normalize_path(file_path),
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
        lookup_name = str(impl_info.get("qualified_name") or impl_info.get("name") or func_name)
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

                scopes = self._cpp_type_scopes(lines)
                for line_no, line in enumerate(lines, start=1):
                    parsed = self._parse_function_declaration_line(
                        line, lines, line_no, class_scope=scopes[line_no - 1]
                    )
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

    def get_function_program_facts(self, func_name: str, file_path: str = "") -> Dict[str, Any]:
        getter = getattr(self._backend, "get_function_program_facts", None)
        if not callable(getter):
            getter = getattr(getattr(self._backend, "_clang", None), "get_function_program_facts", None)
        if not callable(getter):
            return {"complete": False, "events": [], "accesses": []}
        name = str(func_name).split("@", 1)[0]
        value = getter(name, self._normalize_path(self._resolve_file_path(file_path)) if file_path else "")
        return value if isinstance(value, dict) else {"complete": False, "events": [], "accesses": []}

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
                location_name, inferred_file, _, _ = self._function_location_query_parts(raw_query)
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
            macro_file = str(macro_result.get("file") or "")
            macro_cache_key = (
                self._macro_impl_index_name(macro_result),
                max_lines,
                bool(include_context),
                (
                    self._source_fingerprint(self._resolve_file_path(macro_file))
                    if macro_file
                    else f"epoch={self._index_epoch}"
                ),
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
        func_info = dict(selected_info)
        indexed_file = str(func_info.get("file") or func_info.get("filename") or "")
        if not indexed_file or indexed_file.startswith("<"):
            if warn_missing:
                logger.warning("Function '%s' has no indexed source file", raw_query)
            return None

        source_path = self._resolve_file_path(func_info["file"])
        cache_key = (
            lookup_name,
            max_lines,
            bool(include_context),
            self._source_fingerprint(source_path),
        )
        cached_result = self._get_cached_function_impl(cache_key)
        if cached_result is not None:
            return cached_result
        try:
            lines = self._read_file_lines(source_path)
            is_java_method = func_info.get("language") == "java" or self.language == "java"
            total_lines = len(lines)
            raw_start_line = int(func_info.get("start_line") or 0)
            raw_end_line = int(func_info.get("end_line") or 0)
            synthetic_or_generated = False
            if raw_start_line < 1 or raw_start_line > total_lines:
                synthetic_or_generated = is_java_method
                raw_start_line = min(max(raw_start_line, 1), max(total_lines, 1))
            if raw_end_line < raw_start_line or raw_end_line > total_lines:
                synthetic_or_generated = synthetic_or_generated or is_java_method
                raw_end_line = min(
                    max(raw_end_line, raw_start_line), max(total_lines, raw_start_line)
                )
            start = max(0, raw_start_line - 1)
            end = raw_end_line
            if max_lines is not None and end - start > max_lines:
                end = start + max_lines
            code_lines = lines[start:end]
            if is_java_method and (synthetic_or_generated or not code_lines):
                declaration = str(
                    func_info.get("declaration_code") or func_info.get("signature") or ""
                )
                if declaration:
                    code_lines = [declaration if declaration.endswith("\n") else declaration + "\n"]
            has_function_body = self._code_range_has_function_body(code_lines)
            if not has_function_body and not is_java_method:
                if warn_missing:
                    logger.warning(
                        "Function '%s' matched a declaration without a body at %s",
                        raw_query,
                        func_info["file"],
                    )
                return None
            comment_blocks: List[Dict[str, Any]] = []
            if include_context and not is_java_method:
                comment_blocks = self._find_function_declaration_comments(
                    lookup_name,
                    source_path,
                )
                impl_comment = self._find_leading_c_comment_block(lines, raw_start_line)
                if impl_comment:
                    comment_blocks.append(
                        self._comment_block_payload(
                            kind="implementation",
                            file_path=source_path,
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
                callees = self._filter_callee_names(c["name"] for c in callee_data if c.get("name"))
            else:
                callees = self._filter_callee_names(extract_function_calls(code))

            result = {
                "func_name": str(
                    func_info.get("qualified_name") or func_info.get("name") or raw_query
                ),
                "file": self._normalize_path(source_path),
                "index_name": lookup_name,
                "language": func_info.get("language") or self.language,
                "start_line": raw_start_line,
                "end_line": (
                    raw_end_line if max_lines is None else min(raw_end_line, start + max_lines + 1)
                ),
                "code": code,
                "callees": callees,
                "signature": func_info.get("signature", f"{raw_query}(...)"),
                "is_static": self._function_record_is_static(func_info),
                "truncated": (
                    max_lines is not None and (raw_end_line - raw_start_line + 1) > max_lines
                ),
                "comment_blocks": comment_blocks,
                "declaration_only": not has_function_body,
                "is_synthetic_or_generated": synthetic_or_generated,
            }
            for key in (
                "qualified_name",
                "method_full_name",
                "class_name",
                "package",
                "declaration_code",
                "annotations",
                "parameter_annotations",
                "class_annotations",
                "framework_semantics",
            ):
                if func_info.get(key):
                    result[key] = func_info[key]
            if result.get("language") == "java" and not result.get("framework_semantics"):
                try:
                    from ..semantics.java_frameworks import build_java_framework_semantics

                    result["framework_semantics"] = build_java_framework_semantics(result)
                except Exception:
                    logger.debug("Failed to derive Java framework semantics", exc_info=True)
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
                return {
                    "file": self._normalize_path(full_path),
                    "start_line": 1,
                    "end_line": 0,
                    "code": "",
                    "total_lines": 0,
                    "truncated": False,
                }
            if start_line is None or start_line < 1:
                start_line = 1
            try:
                requested_end_line = int(end_line) if end_line is not None else None
            except (TypeError, ValueError):
                requested_end_line = None
            if requested_end_line is None or requested_end_line < start_line:
                desired_end_line = start_line + default_max_lines - 1
            else:
                # An end_line past EOF is a "read to the end of the file"
                # request: clamp it to EOF (within the hard max_lines ceiling)
                # instead of silently falling back to the short default window.
                desired_end_line = min(requested_end_line, total_lines)
            end_line = min(desired_end_line, start_line + max_lines - 1, total_lines)
            start = max(0, start_line - 1)
            end = min(total_lines, end_line)
            code_lines = lines[start:end]
            code = "".join(f"{start + i + 1} | {line}" for i, line in enumerate(code_lines))
            return {
                "file": self._normalize_path(full_path),
                "start_line": start_line,
                "end_line": end_line,
                "code": code,
                "total_lines": total_lines,
                "truncated": end_line < desired_end_line,
            }
        except Exception as e:
            logger.error(f"Failed to read file snippet: {e}")
            return None

    def list_functions(
        self,
        pattern: Optional[str] = None,
        limit: Optional[int] = 50,
        file_root: Optional[Union[str, Path]] = None,
        offset: int = 0,
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
        ordered = sorted(funcs)
        start = max(0, int(offset or 0))
        if limit is None:
            return ordered[start:]
        parsed_limit = int(limit)
        if parsed_limit <= 0:
            return ordered[start:]
        return ordered[start : start + parsed_limit]

    def find_java_methods_by_tokens(
        self,
        tokens: Sequence[str],
        limit: int = 8,
    ) -> List[Dict[str, Any]]:
        """Return copies of Java method records ranked by normalized metadata tokens."""

        normalized_tokens = [
            self._normalize_java_method_search_token(token)
            for token in tokens
            if self._normalize_java_method_search_token(token)
        ]
        if not normalized_tokens:
            return []
        unique_tokens = list(dict.fromkeys(normalized_tokens))[:24]
        matches: List[Tuple[int, int, str, Dict[str, Any]]] = []
        with self._cache_lock:
            records = [(key, dict(info)) for key, info in self._function_index.items()]
        for key, info in records:
            if str(info.get("language") or self.language).lower() != "java":
                continue
            haystack = self._normalize_java_method_search_token(
                " ".join(
                    str(value or "")
                    for value in (
                        key,
                        info.get("name"),
                        info.get("qualified_name"),
                        info.get("method_full_name"),
                        info.get("class_name"),
                        info.get("package"),
                        info.get("file"),
                        info.get("filename"),
                        info.get("signature"),
                        info.get("declaration_code"),
                    )
                )
            )
            score = sum(1 for token in unique_tokens if token and token in haystack)
            if score <= 0:
                continue
            file_path = str(info.get("file") or info.get("filename") or "")
            java_path_bonus = int(file_path.replace("\\", "/").endswith(".java"))
            copied = dict(info)
            copied.setdefault("index_name", key)
            matches.append((score, java_path_bonus, key, copied))
        matches.sort(
            key=lambda item: (
                -item[0],
                -item[1],
                str(item[3].get("file") or item[3].get("filename") or ""),
                int(item[3].get("start_line") or item[3].get("lineNumber") or 0),
                item[2],
            )
        )
        return [item[3] for item in matches[: max(1, int(limit or 8))]]

    @staticmethod
    def _normalize_java_method_search_token(value: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())

    def find_function_identities(
        self,
        func_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        """Return lightweight, overload-safe function identities.

        Unlike ``find_function_infos``, this method deliberately avoids
        collecting callees, types, macros, and globals.  Entry discovery needs
        only enough information to enumerate same-name implementations without
        paying the full semantic-context cost.
        """
        matches = self._find_function_matches(
            str(func_name or "").strip(),
            file_path=file_path,
        )
        return [
            {
                "function_name": str(info.get("qualified_name") or info.get("name") or index_key),
                "file_path": self._normalize_index_file_value(
                    str(info.get("file") or info.get("filename") or "")
                ),
                "index_name": str(info.get("index_name") or index_key),
                "start_line": self._safe_int(info.get("start_line") or info.get("lineNumber")),
                "end_line": self._safe_int(info.get("end_line") or info.get("lineNumberEnd")),
                "signature": str(info.get("signature") or f"{info.get('name') or index_key}(...)"),
                "is_static": self._function_record_is_static(info),
            }
            for index_key, info in matches
        ]

    def find_function_metadata(self, func_name: str, file_path: str = "") -> List[Dict[str, Any]]:
        """Enumerate identities without starting type materialization."""
        return self.find_function_infos(func_name, file_path, include_type_context=False)

    def find_function_infos(
        self,
        func_name: str,
        file_path: str = "",
        *,
        include_type_context: bool = True,
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
                self._function_info_payload(index_key, info, include_type_context=include_type_context)
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
                return [self._macro_function_info_payload(impl) for impl in exact_macro_impls]

        fallback_matches = self._find_function_matches(
            raw_query,
            file_path=file_path,
            allow_simple_fallback=True,
        )
        if fallback_matches:
            return [
                self._function_info_payload(index_key, info, include_type_context=include_type_context)
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
        """Return canonical caller records for one function or function-like macro."""
        raw_query = str(func_name or "").strip()
        matches = self._find_function_matches(raw_query, file_path=file_path)
        macro_impls: List[Dict[str, Any]] = []
        location_name, _, _, _ = self._function_location_query_parts(raw_query)
        if not matches and location_name:
            macro_impls = self._find_macro_impls(
                raw_query,
                file_path=file_path,
                max_lines=None,
                function_like_only=True,
                include_callees=False,
                exact_location_only=True,
            )
        if not matches and not macro_impls:
            matches = self._find_function_matches(
                raw_query,
                file_path=file_path,
                allow_simple_fallback=True,
            )
        if matches:
            if len(matches) != 1:
                return {"match_count": len(matches), "callers": []}

            index_key, info = matches[0]
            callers = self._function_info_callers(
                index_key,
                str(info.get("file") or info.get("filename") or ""),
                limit=max(0, int(limit)),
            )
            return {"match_count": 1, "callers": callers}

        if not macro_impls:
            macro_impls = self._find_macro_impls(
                raw_query,
                file_path=file_path,
                max_lines=None,
                function_like_only=True,
                include_callees=False,
            )

        macro_targets: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for impl in macro_impls:
            macro_name = str(impl.get("func_name") or "")
            macro_file = self._normalize_index_file_value(str(impl.get("file") or ""))
            macro_targets.setdefault((macro_name, macro_file), impl)
        if len(macro_targets) != 1:
            return {"match_count": len(macro_targets), "callers": []}

        (macro_name, macro_file), _ = next(iter(macro_targets.items()))
        callers = self._macro_function_info_callers(
            macro_name,
            macro_file,
            limit=max(0, int(limit)),
        )
        return {"match_count": 1, "callers": callers}

    def _macro_function_info_callers(
        self,
        macro_name: str,
        macro_file: str,
        *,
        limit: int,
    ) -> List[Dict[str, Any]]:
        if limit <= 0 or not self._backend:
            return []
        try:
            getter = getattr(self._backend, "get_function_info_callers", None)
            if callable(getter):
                try:
                    callers = getter(macro_name, macro_file)
                except TypeError:
                    callers = getter(macro_name)
            else:
                callers = self._backend.get_callers(
                    macro_name,
                    limit=self._function_info_raw_edge_limit(limit),
                    callee_file=macro_file,
                )
        except Exception as exc:
            logger.debug("Macro caller lookup failed for %s: %s", macro_name, exc)
            return []
        return self._aggregate_function_info_callers(callers)[:limit]

    def _macro_function_info_payload(self, impl: Dict[str, Any]) -> Dict[str, Any]:
        function_name = str(impl.get("func_name") or "")
        file_path = self._normalize_index_file_value(str(impl.get("file") or ""))
        start_line = self._safe_int(impl.get("start_line"))
        end_line = self._safe_int(impl.get("end_line"))
        if end_line < start_line:
            end_line = start_line
        callee_payload, macro_edges = self._function_info_callee_context(
            self._macro_function_info_callee_rows(function_name, impl)
        )
        symbol_context = self._macro_function_info_symbol_context(
            function_name,
            impl,
            extra_macros=macro_edges,
        )
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
            **callee_payload,
            **symbol_context,
            "referenced_types": [],
        }

    def _macro_function_info_callees(
        self,
        macro_name: str,
        impl: Dict[str, Any],
    ) -> Dict[str, Any]:
        return self._function_info_callee_payload(
            self._macro_function_info_callee_rows(macro_name, impl)
        )

    def _macro_function_info_callee_rows(
        self,
        macro_name: str,
        impl: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for raw_line in str(impl.get("code") or "").splitlines():
            match = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", raw_line)
            line_no = self._safe_int(match.group(1)) if match else 0
            source_line = match.group(2) if match else raw_line
            for callee_name in self._filter_callee_names(extract_function_calls(source_line)):
                if callee_name == macro_name:
                    continue
                rows.append(
                    {
                        "name": callee_name,
                        "filename": self._function_file_for_query(callee_name),
                        "lineNumber": line_no,
                        "call_type": "direct",
                    }
                )
        return rows

    def _macro_function_info_symbol_context(
        self,
        macro_name: str,
        impl: Dict[str, Any],
        *,
        extra_macros: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        file_path = str(impl.get("file") or "")
        candidates = self._macro_symbol_reference_candidates(macro_name, impl)
        if self._backend:
            macros_index = self._backend_macro_definition_index(candidates)
        else:
            macros_index = self._get_macro_definition_index()

        referenced_macros: List[Dict[str, Any]] = []
        strict_resolution = self._backend is not None
        for name, candidate in candidates.items():
            macro_record = self._resolve_macro_symbol_definition(
                name,
                macros_index.get(name, []),
                file_path,
                strict=strict_resolution,
            )
            if macro_record is None:
                continue
            reference_lines = candidate["reference_lines"]
            if self._macro_record_is_function_like(macro_record):
                reference_lines = candidate["call_reference_lines"]
            if not reference_lines:
                continue
            referenced_macros.append(
                {
                    **macro_record,
                    "reference_lines": reference_lines,
                }
            )

        referenced_macros = self._merge_function_info_macros(
            referenced_macros,
            extra_macros or [],
        )
        payload: Dict[str, Any] = {
            "referenced_globals": [],
        }
        payload["referenced_macros"] = referenced_macros[:FUNCTION_INFO_MACROS_LIMIT]
        if len(referenced_macros) > FUNCTION_INFO_MACROS_LIMIT:
            payload["referenced_macros_truncation"] = self._truncation_payload(
                FUNCTION_INFO_MACROS_LIMIT,
                len(referenced_macros),
            )
        return payload

    def _macro_symbol_reference_candidates(
        self,
        macro_name: str,
        impl: Dict[str, Any],
    ) -> Dict[str, Dict[str, Any]]:
        """Discover identifier references in a macro body without classifying them."""
        signature = str(impl.get("signature") or "")
        parameters_match = re.search(r"\(([^)]*)\)", signature)
        parameters = set(
            re.findall(
                r"\b[A-Za-z_]\w*\b",
                str(parameters_match.group(1) if parameters_match else ""),
            )
        )
        preprocessor_tokens = {
            "define",
            "defined",
            "elif",
            "else",
            "endif",
            "error",
            "if",
            "ifdef",
            "ifndef",
            "include",
            "line",
            "pragma",
            "undef",
            "warning",
        }
        start_line = self._safe_int(impl.get("start_line"))
        candidates: Dict[str, Dict[str, Any]] = {}

        for offset, raw_line in enumerate(str(impl.get("code") or "").splitlines()):
            match = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", raw_line)
            line_no = self._safe_int(match.group(1)) if match else start_line + offset
            source_line = match.group(2) if match else raw_line
            masked_line = self._mask_function_info_source_line(source_line)
            for token in re.finditer(r"\b[A-Za-z_]\w*\b", masked_line):
                name = token.group(0)
                if name == macro_name or name in parameters or name in preprocessor_tokens:
                    continue
                if self._function_info_field_access(
                    masked_line,
                    token.start(),
                ):
                    continue
                entry = candidates.setdefault(
                    name,
                    {
                        "reference_lines": [],
                        "call_reference_lines": [],
                    },
                )
                if line_no > 0 and line_no not in entry["reference_lines"]:
                    entry["reference_lines"].append(line_no)
                if re.match(r"\s*\(", masked_line[token.end() :]):
                    if line_no > 0 and line_no not in entry["call_reference_lines"]:
                        entry["call_reference_lines"].append(line_no)
        return candidates

    def _backend_macro_definition_index(
        self,
        candidates: Dict[str, Dict[str, Any]],
    ) -> Dict[str, List[Dict[str, Any]]]:
        macros_index: Dict[str, List[Dict[str, Any]]] = {}
        getter = getattr(self._backend, "get_macro_definitions_batch", None)
        if not callable(getter) or not candidates:
            return macros_index
        try:
            definitions = getter(sorted(candidates))
        except Exception as exc:
            logger.debug("Macro definition lookup failed: %s", exc)
            return macros_index
        for record in definitions or []:
            if not isinstance(record, dict):
                continue
            name = str(record.get("name") or "")
            if name in candidates:
                macros_index.setdefault(name, []).append(dict(record))
        return macros_index

    def _resolve_macro_symbol_definition(
        self,
        symbol_name: str,
        records: List[Dict[str, Any]],
        macro_file: str,
        *,
        strict: bool,
    ) -> Optional[Dict[str, Any]]:
        if not records:
            return None
        if not strict:
            return self._preferred_function_info_record(records, macro_file)
        same_file = [
            record
            for record in records
            if self._paths_match_hint(
                str(record.get("file_path") or record.get("file") or ""),
                macro_file,
            )
        ]
        if len(same_file) == 1:
            return same_file[0]
        if not same_file and len(records) == 1:
            return records[0]
        logger.debug(
            "Macro definition is ambiguous symbol=%s macro_file=%s candidates=%d",
            symbol_name,
            macro_file,
            len(same_file or records),
        )
        return None

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
        *,
        include_type_context: bool = True,
    ) -> Dict[str, Any]:
        raw_file = str(info.get("file") or info.get("filename") or "")
        function_name = str(info.get("name") or info.get("qualified_name") or index_key)
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
        callee_payload, macro_edges = self._function_info_callee_context(
            self._function_info_callees(index_key)
        )
        payload.update(callee_payload)
        payload.update(
            self._function_info_symbol_context(
                index_key,
                raw_file,
                extra_macros=macro_edges,
            )
        )
        if include_type_context:
            payload.update(
                self._function_info_type_context(
                    index_key, raw_file,
                    self._safe_int(info.get("start_line") or info.get("lineNumber")),
                )
            )
        return payload

    def get_function_type_context(
        self,
        func_name: str,
        file_path: str = "",
        start_line: int = 0,
    ) -> Dict[str, Any]:
        """Return the budgeted direct type context for one unique function."""
        matches = self._find_function_matches(str(func_name or "").strip(), file_path=file_path)
        if not matches:
            matches = self._find_function_matches(
                str(func_name or "").strip(),
                file_path=file_path,
                allow_simple_fallback=True,
            )
        if start_line:
            matches = [(key, info) for key, info in matches
                       if self._safe_int(info.get("start_line") or info.get("lineNumber")) == start_line]
        if len(matches) != 1:
            return {"referenced_types": []}
        index_key, info = matches[0]
        raw_file = str(info.get("file") or info.get("filename") or file_path)
        resolved_start = self._safe_int(
            start_line or info.get("start_line") or info.get("lineNumber")
        )
        return self._function_info_type_context(index_key, raw_file, resolved_start)

    def _function_info_type_context(
        self,
        index_key: str,
        raw_file: str,
        start_line: int,
    ) -> Dict[str, Any]:
        if not self._backend:
            return self._function_info_type_context_regex(index_key, raw_file, start_line)
        with self._cache_lock:
            info = self._function_index.get(index_key) or {}
        backend_lookup = str(info.get("qualified_name") or info.get("name") or index_key)
        getter = getattr(self._backend, "get_function_type_context", None)
        if not callable(getter):
            return {"referenced_types": []}
        try:
            try:
                raw_context = getter(backend_lookup, raw_file, start_line)
            except TypeError:
                raw_context = getter(backend_lookup, raw_file)
        except Exception as exc:
            from .clang_type_state import TypeContextUnavailable
            if isinstance(exc, TypeContextUnavailable):
                raise
            logger.warning(
                "[type-context] query failed index_name=%s reason=backend_query_failed error=%s",
                index_key,
                exc,
            )
            raise TypeContextUnavailable("backend_query_failed", str(exc)) from exc
        result = self._normalize_and_budget_type_context(raw_context)
        logger.debug(
            "[type-context] query index_name=%s resolved=%d unresolved=%d bytes=%d truncated=%s",
            index_key,
            len(result["referenced_types"]),
            len(result.get("unresolved_referenced_types", [])),
            sum(
                len(str(item.get("full_definition") or "").encode("utf-8"))
                for item in result["referenced_types"]
            ),
            bool(result.get("referenced_types_truncation")),
        )
        return result

    def _function_info_type_context_regex(
        self,
        index_key: str,
        raw_file: str,
        start_line: int,
    ) -> Dict[str, Any]:
        with self._cache_lock:
            info = dict(self._function_index.get(index_key) or {})
        try:
            source_path = self._resolve_file_path(raw_file)
            lines = self._read_file_lines(source_path)
        except (OSError, ValueError):
            return {"referenced_types": []}
        if not lines:
            return {"referenced_types": []}

        type_index = self._get_regex_type_definition_index()
        if not type_index:
            return {"referenced_types": []}
        from .clang_extractor import ClangExtractor

        extractor = ClangExtractor(project_root=self.source_root)
        function_record = {
            "name": str(info.get("name") or info.get("qualified_name") or index_key),
            "start_line": self._safe_int(start_line or info.get("start_line")),
            "end_line": self._safe_int(info.get("end_line") or info.get("lineNumberEnd")),
            "signature": str(info.get("signature") or ""),
        }
        candidates = extractor._direct_function_type_candidates(
            function_record,
            lines,
            set(type_index),
        )
        visible_files = self._regex_transitive_include_closure(raw_file)
        resolved: Dict[str, Dict[str, Any]] = {}
        unresolved: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for candidate in candidates:
            name = str(candidate.get("name") or "")
            definitions = [
                item
                for item in type_index.get(name, [])
                if self._paths_match_hint(str(item.get("file_path") or ""), raw_file)
                or any(
                    self._paths_match_hint(str(item.get("file_path") or ""), visible)
                    for visible in visible_files
                )
            ]
            if len(definitions) != 1:
                reason = (
                    "type_definition_not_found" if not definitions else "type_definition_ambiguous"
                )
                entry = unresolved.setdefault(
                    (name, reason),
                    {
                        "name": name,
                        "reference_kinds": [],
                        "reference_lines": [],
                        "reason": reason,
                    },
                )
            else:
                definition = definitions[0]
                identity = str(definition["type_index_name"])
                entry = resolved.setdefault(
                    identity,
                    {
                        **definition,
                        "reference_kinds": [],
                        "reference_lines": [],
                    },
                )
            reference_kind = str(candidate.get("kind") or "")
            reference_line = self._safe_int(candidate.get("line"))
            if reference_kind and reference_kind not in entry["reference_kinds"]:
                entry["reference_kinds"].append(reference_kind)
            if reference_line > 0 and reference_line not in entry["reference_lines"]:
                entry["reference_lines"].append(reference_line)

        raw_context: Dict[str, Any] = {"referenced_types": list(resolved.values())}
        if unresolved:
            raw_context["unresolved_referenced_types"] = list(unresolved.values())
        return self._normalize_and_budget_type_context(raw_context)

    def _get_regex_type_definition_index(self) -> Dict[str, List[Dict[str, Any]]]:
        with self._cache_lock:
            if self._regex_type_definition_cache is not None:
                return {
                    name: [dict(item) for item in items]
                    for name, items in self._regex_type_definition_cache.items()
                }

        index: Dict[str, List[Dict[str, Any]]] = {}
        patterns = (
            re.compile(
                r"\btypedef\s+(?P<tag_kind>struct|union|enum)\s*(?P<tag>[A-Za-z_]\w*)?\s*"
                r"\{.*?\}\s*(?P<name>[A-Za-z_]\w*)\s*;",
                re.S,
            ),
            re.compile(
                r"\b(?P<kind>struct|union|enum|class)\s+(?P<name>[A-Za-z_]\w*)\s*" r"\{.*?\}\s*;",
                re.S,
            ),
            re.compile(
                r"\btypedef\s+(?!struct\b|union\b|enum\b)(?P<body>[^;{}]+?)\s+"
                r"(?P<name>[A-Za-z_]\w*)\s*;"
            ),
        )
        for file_name in self._find_all_files():
            try:
                file_path = self._resolve_file_path(file_name)
                text = self._read_file_text(file_path)
            except (OSError, ValueError):
                continue
            normalized_file = self._normalize_index_file_value(file_name)
            seen_ranges: set[Tuple[str, int, int]] = set()
            for pattern in patterns:
                for match in pattern.finditer(text):
                    name = str(match.groupdict().get("name") or "")
                    if not name:
                        continue
                    start_line = text.count("\n", 0, match.start()) + 1
                    end_line = text.count("\n", 0, match.end()) + 1
                    dedupe_key = (name, start_line, end_line)
                    if dedupe_key in seen_ranges:
                        continue
                    seen_ranges.add(dedupe_key)
                    kind = str(
                        match.groupdict().get("kind")
                        or match.groupdict().get("tag_kind")
                        or "typedef"
                    )
                    item = {
                        "type_index_name": (f"{name}@{normalized_file}:{start_line}-{end_line}"),
                        "name": name,
                        "kind": kind,
                        "file_path": normalized_file,
                        "start_line": start_line,
                        "end_line": end_line,
                        "full_definition": match.group(0),
                    }
                    index.setdefault(name, []).append(item)
        for items in index.values():
            items.sort(key=lambda item: item["type_index_name"])
        with self._cache_lock:
            self._regex_type_definition_cache = {
                name: [dict(item) for item in items] for name, items in index.items()
            }
        return index

    def _regex_transitive_include_closure(self, raw_file: str) -> List[str]:
        graph: Dict[str, List[str]] = {}
        for file_name in self._find_all_files():
            try:
                path = self._resolve_file_path(file_name)
                lines = self._read_file_lines(path)
            except (OSError, ValueError):
                continue
            source = self._normalize_index_file_value(file_name)
            for line in lines:
                match = re.match(r'\s*#\s*include\s+"(?P<path>[^"]+)"', line)
                if not match:
                    continue
                include_text = match.group("path")
                local = (path.parent / include_text).resolve()
                root = (self.source_root / include_text).resolve()
                candidates = [candidate for candidate in (local, root) if candidate.exists()]
                if not candidates:
                    suffix = Path(include_text).parts
                    candidates = [
                        candidate.resolve()
                        for candidate in self.source_root.rglob(Path(include_text).name)
                        if candidate.is_file() and tuple(candidate.parts[-len(suffix) :]) == suffix
                    ]
                unique = sorted(set(candidates))
                if len(unique) != 1:
                    continue
                graph.setdefault(source, []).append(self._normalize_path(unique[0]))

        root_file = self._normalize_index_file_value(raw_file)
        visited: set[str] = set()
        pending = [root_file]
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            pending.extend(item for item in graph.get(current, []) if item not in visited)
        return sorted(visited)

    def _normalize_and_budget_type_context(self, raw_context: Any) -> Dict[str, Any]:
        context = raw_context if isinstance(raw_context, dict) else {}
        unresolved: List[Dict[str, Any]] = []
        unresolved_seen: set[Tuple[str, str, Tuple[str, ...], Tuple[int, ...]]] = set()

        def add_unresolved(
            name: Any,
            reason: Any,
            reference_kinds: Any,
            reference_lines: Any,
        ) -> None:
            kinds = self._normalized_type_reference_kinds(reference_kinds)
            lines = self._normalized_line_list(reference_lines)
            clean_name = str(name or "").strip()
            clean_reason = str(reason or "type_not_resolved").strip() or "type_not_resolved"
            key = (clean_name, clean_reason, tuple(kinds), tuple(lines))
            if key in unresolved_seen:
                return
            unresolved_seen.add(key)
            unresolved.append(
                {
                    "name": clean_name,
                    "reference_kinds": kinds,
                    "reference_lines": lines,
                    "reason": clean_reason,
                }
            )

        for item in list(context.get("unresolved_referenced_types") or []):
            if isinstance(item, dict):
                add_unresolved(
                    item.get("name"),
                    item.get("reason"),
                    item.get("reference_kinds"),
                    item.get("reference_lines"),
                )

        normalized: Dict[str, Dict[str, Any]] = {}
        for raw_item in list(context.get("referenced_types") or []):
            if not isinstance(raw_item, dict):
                continue
            name = str(raw_item.get("name") or "").strip()
            kind = str(raw_item.get("kind") or "unknown").strip() or "unknown"
            file_path = self._normalize_index_file_value(str(raw_item.get("file_path") or ""))
            item_start = self._safe_int(raw_item.get("start_line"))
            item_end = self._safe_int(raw_item.get("end_line") or item_start)
            full_definition = self._numbered_type_definition(
                file_path,
                item_start,
                item_end,
                str(raw_item.get("full_definition") or ""),
            )
            reference_kinds = self._normalized_type_reference_kinds(raw_item.get("reference_kinds"))
            reference_lines = self._normalized_line_list(raw_item.get("reference_lines"))
            if not name or not file_path or item_start <= 0 or not full_definition:
                add_unresolved(
                    name,
                    "definition_incomplete",
                    reference_kinds,
                    reference_lines,
                )
                continue
            identity = str(raw_item.get("type_index_name") or "").strip()
            if not identity:
                identity = f"{name}@{file_path}:{item_start}-{item_end}"
            current = normalized.get(identity)
            if current is None:
                current = {
                    "_name": name,
                    "type_index_name": identity,
                    "kind": kind,
                    "full_definition": full_definition,
                    "reference_kinds": [],
                    "reference_lines": [],
                }
                normalized[identity] = current
            current["reference_kinds"] = self._normalized_type_reference_kinds(
                list(current["reference_kinds"]) + reference_kinds
            )
            current["reference_lines"] = self._normalized_line_list(
                list(current["reference_lines"]) + reference_lines
            )

        candidates = sorted(
            normalized.values(),
            key=lambda item: (
                (
                    0
                    if {"return", "parameter", "function_pointer"} & set(item["reference_kinds"])
                    else 1
                ),
                item["type_index_name"],
            ),
        )
        returned: List[Dict[str, Any]] = []
        definition_bytes = 0
        truncated = False
        for item in candidates:
            item_bytes = len(str(item["full_definition"]).encode("utf-8"))
            if item_bytes > REFERENCED_TYPE_DEFINITION_BYTES_LIMIT:
                add_unresolved(
                    item["_name"],
                    "definition_too_large",
                    item["reference_kinds"],
                    item["reference_lines"],
                )
                truncated = True
                continue
            if len(returned) >= REFERENCED_TYPES_LIMIT:
                truncated = True
                continue
            if definition_bytes + item_bytes > REFERENCED_TYPES_DEFINITION_BYTES_LIMIT:
                truncated = True
                continue
            returned.append({key: value for key, value in item.items() if key != "_name"})
            definition_bytes += item_bytes

        returned.sort(key=lambda item: item["type_index_name"])
        unresolved.sort(key=lambda item: (item["name"], item["reason"], item["reference_lines"]))
        result: Dict[str, Any] = {"referenced_types": returned}
        if unresolved:
            result["unresolved_referenced_types"] = unresolved
        if truncated:
            result["referenced_types_truncation"] = {
                "truncated": True,
                "returned": len(returned),
                "total": len(candidates),
                "definition_bytes_returned": definition_bytes,
                "definition_bytes_limit": REFERENCED_TYPES_DEFINITION_BYTES_LIMIT,
            }
        return result

    def _numbered_type_definition(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        fallback_definition: str,
    ) -> str:
        """Project a type definition through the canonical file-snippet formatter."""
        line_count = max(1, int(end_line) - int(start_line) + 1)
        snippet = self.get_file_snippet(
            file_path,
            start_line,
            end_line,
            max_lines=line_count,
            default_max_lines=line_count,
        )
        if snippet and str(snippet.get("code") or ""):
            return str(snippet["code"])
        return self._numbered_code(
            str(fallback_definition or "").splitlines(True),
            max(0, int(start_line or 1) - 1),
        )

    @staticmethod
    def _normalized_type_reference_kinds(value: Any) -> List[str]:
        allowed = set(REFERENCED_TYPE_KIND_ORDER)
        values = value if isinstance(value, list) else []
        unique = {str(item) for item in values if str(item) in allowed}
        order = {name: index for index, name in enumerate(REFERENCED_TYPE_KIND_ORDER)}
        return sorted(unique, key=lambda item: order[item])

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
            backend_lookup = str(info.get("qualified_name") or info.get("name") or index_key)
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
                    row for row in callers if self._function_info_call_type(row) != "indirect"
                ]
        except Exception as exc:
            logger.debug("Caller lookup failed for %s: %s", index_key, exc)
            return []
        return self._aggregate_function_info_callers(callers)[:limit]

    def _function_info_callees(
        self,
        index_key: str,
    ) -> List[Dict[str, Any]]:
        if not self._backend:
            return self._function_info_callees_regex(index_key)
        try:
            with self._cache_lock:
                info = self._function_index.get(index_key) or {}
            backend_lookup = str(info.get("qualified_name") or info.get("name") or index_key)
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
            return []
        aggregated = self._aggregate_function_info_callees(callees)
        return aggregated

    def _function_info_callee_payload_for_index(self, index_key: str) -> Dict[str, Any]:
        return self._function_info_callee_payload(self._function_info_callees(index_key))

    def _function_info_callee_payload(
        self,
        rows: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Classify, aggregate, and independently truncate project/external callees."""

        payload, _macro_edges = self._function_info_callee_context(rows)
        return payload

    def _function_info_callee_context(
        self,
        rows: List[Dict[str, Any]],
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Return public function call edges and canonical macro-reference edges."""

        (
            project_callees,
            external_callees,
            unresolved_callees,
            macro_edges,
        ) = self._split_function_info_callees(rows)
        payload: Dict[str, Any] = {
            "project_callees": project_callees[:FUNCTION_INFO_CALLEES_LIMIT],
            "external_callees": external_callees[:FUNCTION_INFO_EXTERNAL_CALLEES_LIMIT],
        }
        if unresolved_callees:
            payload["unresolved_callees"] = unresolved_callees[
                :FUNCTION_INFO_UNRESOLVED_CALLEES_LIMIT
            ]
        if len(project_callees) > len(payload["project_callees"]):
            payload["project_callees_truncation"] = self._truncation_payload(
                len(payload["project_callees"]), len(project_callees)
            )
        if len(external_callees) > len(payload["external_callees"]):
            payload["external_callees_truncation"] = self._truncation_payload(
                len(payload["external_callees"]), len(external_callees)
            )
        if len(unresolved_callees) > FUNCTION_INFO_UNRESOLVED_CALLEES_LIMIT:
            payload["unresolved_callees_truncation"] = self._truncation_payload(
                len(payload["unresolved_callees"]), len(unresolved_callees)
            )
        return payload, macro_edges

    def _function_info_callees_regex(
        self,
        index_key: str,
    ) -> List[Dict[str, Any]]:
        with self._cache_lock:
            info = dict(self._function_index.get(index_key) or {})
        file_value = str(info.get("file") or info.get("filename") or "")
        try:
            lines = self._read_file_lines(self._resolve_file_path(file_value))
        except Exception:
            return []
        start_line = max(1, self._safe_int(info.get("start_line") or info.get("lineNumber")))
        end_line = min(
            len(lines),
            max(start_line, self._safe_int(info.get("end_line") or info.get("lineNumberEnd"))),
        )
        rows: List[Dict[str, Any]] = []
        function_name = str(info.get("name") or info.get("qualified_name") or index_key)
        for offset, raw_line in enumerate(lines[start_line - 1 : end_line]):
            absolute_line = start_line + offset
            for name in self._filter_callee_names(extract_function_calls(raw_line)):
                if name == function_name:
                    continue
                rows.append(
                    {
                        "name": name,
                        "filename": self._function_file_for_query(name),
                        "lineNumber": absolute_line,
                        "call_type": "direct",
                    }
                )
        return self._aggregate_function_info_callees(rows)

    def _function_info_callee_index_name(
        self,
        callee_name: str,
        callee_file: str = "",
    ) -> str:
        return str(
            self._function_info_callee_descriptor(callee_name, callee_file)[1].get(
                "callee_index_name"
            )
            or ""
        )

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
        *,
        extra_macros: Optional[List[Dict[str, Any]]] = None,
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
                backend_lookup = str(info.get("qualified_name") or info.get("name") or index_key)
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
        raw_macros = [
            item
            for item in list((raw_context or {}).get("referenced_macros") or [])
            if isinstance(item, dict)
            and str(item.get("macro_index_name") or item.get("name") or "")
        ]
        macros_result = self._merge_function_info_macros(
            raw_macros,
            extra_macros or [],
        )
        globals_result.sort(key=lambda item: (item["name"], item["file_path"], item["line"]))

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
            "qualifiers": self._normalize_function_info_qualifiers(item.get("qualifiers")),
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
        return [qualifier for qualifier in FUNCTION_INFO_QUALIFIER_ORDER if qualifier in selected]

    def _normalize_function_info_macro(self, item: Dict[str, Any]) -> Dict[str, Any]:
        macro_index_name = self._macro_index_name_from_record(item)
        if not macro_index_name:
            raise ValueError("macro_definition_unavailable: missing canonical macro identity")
        definition = self._numbered_macro_definition(macro_index_name)
        return {
            "macro_index_name": macro_index_name,
            "definition": definition,
            "is_function_like": bool(item.get("is_function_like")),
            "reference_lines": self._normalized_line_list(item.get("reference_lines")),
        }

    def _merge_function_info_macros(
        self,
        *groups: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for group in groups:
            for raw_item in group:
                item = self._normalize_function_info_macro(raw_item)
                macro_index_name = item["macro_index_name"]
                entry = merged.setdefault(
                    macro_index_name,
                    {
                        "macro_index_name": macro_index_name,
                        "definition": item["definition"],
                        "is_function_like": bool(item["is_function_like"]),
                        "reference_lines": [],
                    },
                )
                entry["is_function_like"] = bool(
                    entry["is_function_like"] or item["is_function_like"]
                )
                entry["reference_lines"] = sorted(
                    set(entry["reference_lines"]) | set(item["reference_lines"])
                )
        return [merged[key] for key in sorted(merged)]

    def _macro_index_name_from_record(self, item: Dict[str, Any]) -> str:
        existing = str(item.get("macro_index_name") or item.get("index_name") or "").strip()
        if existing:
            match = re.match(r"^[A-Za-z_]\w*@.+:\d+-\d+$", existing)
            return existing if match else ""
        name = str(item.get("name") or item.get("func_name") or "").strip()
        file_path = self._normalize_index_file_value(
            str(item.get("file_path") or item.get("file") or "")
        )
        start_line = self._safe_int(item.get("start_line") or item.get("line"))
        end_line = self._safe_int(item.get("end_line")) or self._macro_record_end_line(item)
        if not name or not file_path or start_line <= 0 or end_line < start_line:
            return ""
        return f"{name}@{file_path}:{start_line}-{end_line}"

    def _numbered_macro_definition(self, macro_index_name: str) -> str:
        match = re.match(
            r"^(?P<name>[A-Za-z_]\w*)@(?P<file>.+):(?P<start>\d+)-(?P<end>\d+)$",
            str(macro_index_name or ""),
        )
        if not match:
            raise ValueError(
                f"macro_definition_unavailable: invalid macro_index_name={macro_index_name}"
            )
        file_path = match.group("file")
        start_line = int(match.group("start"))
        end_line = int(match.group("end"))
        snippet = self.get_file_snippet(
            file_path,
            start_line,
            end_line,
            max_lines=max(1, end_line - start_line + 1),
        )
        if (
            not isinstance(snippet, dict)
            or int(snippet.get("start_line") or 0) != start_line
            or int(snippet.get("end_line") or 0) != end_line
            or not self._paths_match_hint(str(snippet.get("file") or ""), file_path)
        ):
            raise ValueError(
                "macro_definition_unavailable: "
                f"unable to read canonical range {macro_index_name}"
            )
        return str(snippet.get("code") or "")

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
        body_lines = lines[start_line - 1 : end_line]
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
                if (
                    name in globals_index
                    and name not in local_names
                    and not self._function_info_field_access(
                        masked_line,
                        match.start(),
                    )
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
                        r"\s*\(", masked_line[match.end() :]
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
                (
                    0
                    if str(record.get("file_path") or "").replace("\\", "/").lstrip("./")
                    == normalized_file
                    else 1
                ),
                str(record.get("file_path") or ""),
                int(record.get("line") or 0),
            ),
        )
        return dict(ranked[0])

    @staticmethod
    def _function_info_regex_local_names(body: str, signature: str) -> set[str]:
        names: set[str] = set()
        if "(" in signature and ")" in signature:
            params = signature[signature.find("(") + 1 : signature.rfind(")")]
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
                call_type for call_type in ("direct", "indirect") if call_type in entry["call_type"]
            ]
        return list(groups.values())

    def _aggregate_function_info_callees(
        self,
        rows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Preserve raw call edges until project/external classification and grouping."""
        return [dict(row) for row in rows if isinstance(row, dict)]

    def _split_function_info_callees(
        self,
        rows: List[Dict[str, Any]],
    ) -> Tuple[
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
    ]:
        project_groups: Dict[str, Dict[str, Any]] = {}
        external_groups: Dict[str, Dict[str, Any]] = {}
        unresolved_groups: Dict[str, Dict[str, Any]] = {}
        macro_groups: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            callee_name = str(row.get("name") or row.get("callee_name") or "")
            if not callee_name or self._is_llvm_intrinsic_callee(callee_name):
                continue
            # A field/local pointer is callsite evidence, not a callable identity. It must
            # never be projected as a guessed external or unresolved function.
            if str(row.get("callee_kind") or "").strip().lower() in {
                "function_pointer_field",
                "function_pointer_variable",
            }:
                continue
            call_type = self._function_info_call_type(row)
            indirect_callsite = None
            if call_type == "indirect":
                indirect_callsite = self._function_info_indirect_callsite(row)
                if indirect_callsite is None:
                    # An SVF function-level target without a source-mapped pointer callsite
                    # remains a diagnostic fact only; exposing it would fabricate LLM evidence.
                    continue
            callee_file = str(
                row.get("filename") or row.get("callee_file") or row.get("file") or ""
            )
            if not callee_file and callee_name:
                callee_file = self._function_file_for_query(callee_name)
            kind, descriptor = self._function_info_callee_descriptor(
                callee_name,
                callee_file,
                callee_signature=str(row.get("callee_signature") or ""),
            )
            if kind == "project_macro":
                macro_index_name = str(descriptor.get("macro_index_name") or "")
                if not macro_index_name:
                    continue
                entry = macro_groups.setdefault(
                    macro_index_name,
                    {
                        "macro_index_name": macro_index_name,
                        "definition": str(descriptor.get("definition") or ""),
                        "is_function_like": True,
                        "reference_lines": [],
                    },
                )
                self._append_reference_line(entry["reference_lines"], row)
                continue
            if kind == "project_function":
                group_key = str(descriptor["callee_index_name"])
                groups = project_groups
            else:
                group_key = str(descriptor["callee_name"])
                groups = external_groups if kind == "external" else unresolved_groups
            group_entry = groups.get(group_key)
            if group_entry is None:
                group_entry = {
                    **descriptor,
                    "direct_callsite_lines": [],
                    "indirect_callsites": [],
                }
                groups[group_key] = group_entry
            if call_type == "direct":
                self._append_direct_callsite_line(group_entry, row)
            elif (
                indirect_callsite is not None
                and indirect_callsite not in group_entry["indirect_callsites"]
            ):
                group_entry["indirect_callsites"].append(indirect_callsite)
        for groups in (project_groups, external_groups, unresolved_groups):
            for entry in groups.values():
                entry["direct_callsite_lines"] = sorted(entry["direct_callsite_lines"])
                entry["indirect_callsites"].sort(
                    key=lambda item: (
                        int(item["callsite_line"]),
                        str(item["function_pointer"]),
                    )
                )
        return (
            [project_groups[key] for key in sorted(project_groups)],
            [external_groups[key] for key in sorted(external_groups)],
            [unresolved_groups[key] for key in sorted(unresolved_groups)],
            [macro_groups[key] for key in sorted(macro_groups)],
        )

    def _append_direct_callsite_line(self, entry: Dict[str, Any], row: Dict[str, Any]) -> None:
        line = self._callsite_line_from_row(row)
        if line > 0 and line not in entry["direct_callsite_lines"]:
            entry["direct_callsite_lines"].append(line)

    def _function_info_indirect_callsite(
        self,
        row: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        line = self._callsite_line_from_row(row)
        function_pointer = str(row.get("pointer_symbol") or "").strip()
        pointer_kind = str(row.get("pointer_kind") or "").strip().lower()
        pointer_type = str(row.get("pointer_type") or "").strip()
        pointer_signature = str(row.get("pointer_signature") or "").strip()
        expression = str(row.get("callsite_expression") or "").strip()
        if (
            line <= 0
            or not function_pointer
            or pointer_kind not in {"field", "local", "parameter", "global", "unknown"}
            or not pointer_type
            or not pointer_signature
            or not expression
        ):
            return None
        result: Dict[str, Any] = {
            "callsite_line": line,
            "function_pointer": function_pointer,
            "function_pointer_kind": pointer_kind,
            "function_pointer_type": pointer_type,
            "function_pointer_signature": pointer_signature,
            "callsite_expression": expression,
        }
        guard = str(row.get("guard") or "").strip()
        if guard:
            result["guard"] = guard
        return result

    def _append_reference_line(self, lines: List[int], row: Dict[str, Any]) -> None:
        line = self._callsite_line_from_row(row)
        if line > 0 and line not in lines:
            lines.append(line)
            lines.sort()

    def _function_info_callee_descriptor(
        self,
        callee_name: str,
        callee_file: str = "",
        *,
        callee_signature: str = "",
    ) -> Tuple[str, Dict[str, Any]]:
        """Classify one raw edge as a project function, macro, external, or unresolved."""
        clean_name = str(callee_name or "").strip()
        matches = self._find_function_matches(clean_name, file_path=callee_file)
        if len(matches) == 1:
            index_name, info = matches[0]
            return "project_function", {
                "callee_index_name": index_name,
                "callee_signature": str(info.get("signature") or ""),
                "is_static": self._function_record_is_static(info),
                "callee_summary": "unknown",
            }

        macro_matches = self._function_info_project_macro_matches(clean_name, callee_file)
        if len(macro_matches) == 1:
            macro_impl = macro_matches[0]
            return "project_macro", {
                "macro_index_name": self._macro_impl_index_name(macro_impl),
                "definition": str(macro_impl.get("code") or ""),
                "is_function_like": True,
            }
        # Signature is accepted only when a backend explicitly marks it as the callee's
        # declaration. The projection must not infer it from a bare function name.
        external_signature = str(callee_signature or "").strip()
        if external_signature:
            return "external", {
                "callee_name": clean_name,
                "callee_signature": external_signature,
            }
        return "unresolved", {"callee_name": clean_name}

    def _function_info_project_macro_matches(
        self,
        macro_name: str,
        file_path: str,
    ) -> List[Dict[str, Any]]:
        """Resolve function-like macros without treating backend-missing facts as source facts."""
        getter = getattr(self._backend, "get_macro_definitions", None) if self._backend else None
        if callable(getter):
            try:
                records = [
                    dict(record)
                    for record in list(getter(macro_name, limit=1_000_000) or [])
                    if isinstance(record, dict)
                ]
            except Exception as exc:
                logger.debug("Backend macro callee lookup failed for %s: %s", macro_name, exc)
                records = []
            records = self._filter_macro_definition_records(
                records,
                file_path=file_path,
                function_like_only=True,
            )
            return [
                self._macro_definition_payload(
                    macro_name,
                    record,
                    max_lines=None,
                    include_callees=False,
                )
                for record in records
            ]
        return self._find_macro_impls(
            macro_name,
            file_path=file_path,
            max_lines=None,
            function_like_only=True,
            include_callees=False,
        )

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
        requested_limit = max(0, int(limit))
        if requested_limit == 0:
            return []
        lookup_name = self._resolve_function_name(func_name)
        with self._cache_lock:
            info = self._function_index.get(lookup_name) or {}
        backend_lookup = str(info.get("qualified_name") or lookup_name)
        raw_limit = requested_limit
        max_raw_limit = 1_000_000
        while True:
            records = list(self._backend.get_callees(backend_lookup, limit=raw_limit) or [])
            filtered = self._filter_callee_records(records)
            if (
                len(filtered) >= requested_limit
                or len(records) < raw_limit
                or raw_limit >= max_raw_limit
            ):
                return filtered[:requested_limit]
            raw_limit = min(max_raw_limit, raw_limit * 2)

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

    def get_header_declared_functions(
        self, header_files: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Get functions declared in header files (public API)."""
        from .indexing_runtime import heartbeat

        started = time.monotonic()
        progress: Dict[str, Any] = {"stage": "backend", "files": 0, "declarations": 0}
        logger.info("[entry-headers] started indexed_functions=%d", len(self._function_index))
        results: List[Dict[str, Any]] = []
        with heartbeat("entry-headers", progress):
            if self._backend:
                try:
                    results.extend(self._backend.get_header_declared_functions(header_files))
                except Exception as exc:
                    logger.debug("Backend header declaration lookup failed: %s", exc)
            progress["backend_declarations"] = len(results)
            progress["stage"] = "source_headers"
            results.extend(self._get_header_funcs_regex(header_files, progress=progress))

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
        logger.info(
            "[entry-headers] completed files=%d checked=%d matched=%d elapsed=%.3fs",
            progress["files"],
            progress["declarations"],
            len(deduped),
            time.monotonic() - started,
        )
        return list(deduped.values())

    def _get_header_funcs_regex(
        self, header_files: Optional[List[str]] = None, *, progress: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        func_decl_re = re.compile(
            r"^\s*(?:extern\s+)?"
            r"(?:(?:const|volatile|struct|enum|union|unsigned|signed|long|short)\s+)*"
            r"[A-Za-z_]\w*(?:\s*\*)*\s+"
            r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;",
            re.MULTILINE | re.DOTALL,
        )
        results = []
        progress = progress if progress is not None else {"files": 0, "declarations": 0}
        seen: set[Path] = set()
        globs = self._header_globs(header_files)
        for pattern in globs:
            for fp in self.source_root.rglob(pattern):
                if fp in seen:
                    continue
                seen.add(fp)
                progress.update(file=str(fp), line=0)
                try:
                    content = self._read_file_text(fp)
                except Exception:
                    continue
                lines = content.splitlines()
                scopes = self._cpp_type_scopes(lines)
                line_starts = [0] + [m.end() for m in re.finditer("\n", content)]
                for line_no, line in enumerate(lines, start=1):
                    if line_no % 64 == 0:
                        progress["line"] = line_no
                    parsed = self._parse_function_declaration_line(
                        line, lines, line_no, class_scope=scopes[line_no - 1]
                    )
                    if not parsed:
                        continue
                    name = parsed["name"]
                    progress["declarations"] += 1
                    if self._has_indexed_function(name):
                        results.append(
                            {
                                "name": name,
                                "filename": self._normalize_path(fp),
                                "lineNumber": line_no,
                            }
                        )
                for m in func_decl_re.finditer(content):
                    name = m.group("name")
                    line_no = bisect_right(line_starts, m.start())
                    if scopes[line_no - 1]:
                        continue
                    progress["declarations"] += 1
                    if self._has_indexed_function(name):
                        results.append(
                            {
                                "name": name,
                                "filename": self._normalize_path(fp),
                                "lineNumber": line_no,
                            }
                        )
                progress["files"] += 1
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
        getter = getattr(self._backend, "get_macro_definitions", None) if self._backend else None
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
            regex_records = (
                []
                if known_missing
                else list(self._get_macro_definition_index().get(clean_name, []))
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
                if self._safe_int(record.get("line") or record.get("start_line"), 1) == query_start
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
        indexed_end_line = int(record.get("end_line") or 0)
        if indexed_end_line >= start_line:
            return indexed_end_line
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
                            "start_line": start_idx + 1,
                            "end_line": idx + 1,
                            "macro_index_name": (
                                f"{parsed['name']}@"
                                f"{normalize_path(file_path, self.project_root)}:"
                                f"{start_idx + 1}-{idx + 1}"
                            ),
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
        normalized = str(file_path or "").replace("\\", "/")
        path = Path(normalized)
        if path.is_absolute() and path.exists():
            return path
        source_candidate = self.source_root / normalized
        if source_candidate.exists():
            return source_candidate
        project_candidate = self.project_root / normalized
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
        """Return the canonical project-relative POSIX representation."""
        return normalize_path(file_path, self.project_root)

    def get_function_location(self, func_name: str) -> Optional[str]:
        """Get function location string (file:line-line)."""
        func_name = self._resolve_function_name(func_name)
        if func_name not in self._function_index:
            return None
        info = self._function_index[func_name]
        resolved = self._resolve_file_path(info["file"])
        file_path = self._normalize_path(resolved)
        return f"{file_path}:{info['start_line']}-{info['end_line']}"

    def _filter_callee_names(self, names: Iterable[str]) -> List[str]:
        """Filter obvious C pseudo-callees while preserving order."""
        filtered = []
        seen = set()
        for name in names:
            if (
                not is_likely_function_call_identifier(name)
                or self._is_llvm_intrinsic_callee(name)
                or name in seen
            ):
                continue
            seen.add(name)
            filtered.append(name)
        return filtered

    def _filter_callee_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        filtered = []
        seen = set()
        for record in records:
            name = record.get("name")
            if (
                not is_likely_function_call_identifier(name)
                or self._is_llvm_intrinsic_callee(name)
                or name in seen
            ):
                continue
            seen.add(name)
            filtered.append(record)
        return filtered

    @staticmethod
    def _is_llvm_intrinsic_callee(name: object) -> bool:
        """Return whether a callee name belongs to LLVM's intrinsic namespace."""
        return str(name or "").strip().startswith("llvm.")

    def close(self):
        """Close backend resources."""
        with self._cache_lock:
            self._file_lines_cache.clear()
            self._function_impl_cache.clear()
            self._shared_cache_lru.clear()
            self._shared_cache_bytes = 0
            self._function_file_resolution_cache.clear()
            self._declaration_comment_index = None
            self._function_alias_index.clear()
            self._ambiguous_function_aliases.clear()
            self._function_query_index.clear()
            self._function_record_variants.clear()
            self._macro_definition_index = None
            self._global_definition_index = None
            self._macro_definition_miss_cache.clear()
        if self._backend:
            self._backend.close()
