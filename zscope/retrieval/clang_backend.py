"""
Clang-SQLite backend - implements CodeBackend using clangd LSP + KnowledgeDB.
Provides precise C/C++ code structure extraction without Joern dependency.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .backend_base import CodeBackend
from .clang_extractor import ClangExtractor
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)


class ClangBackend(CodeBackend):
    """
    基于 clangd LSP + SQLite 的代码分析后端。
    使用 ClangExtractor 批量提取代码结构，存入 KnowledgeDB 供查询。
    """

    MACRO_EXTRACTOR_VERSION = "2"
    SYMBOL_CONTEXT_EXTRACTOR_VERSION = "3"
    TYPE_EXTRACTOR_VERSION = "1"
    FUNCTION_TYPE_REF_EXTRACTOR_VERSION = "3"
    FUNCTION_SYMBOL_CONTEXT_INDEX = "function_symbol_context"
    FUNCTION_TYPE_REFS_INDEX = "function_type_refs"

    def __init__(
        self,
        clangd_path: str = "clangd",
        db_path: str = ".zscope_knowledge/code_knowledge.db",
        batch_size: int = 50,
        max_threads: int = 8,
    ):
        self._clangd_path = clangd_path
        self._db_path = db_path
        self._batch_size = batch_size
        self._max_threads = max_threads
        self._extractor: Optional[ClangExtractor] = None
        self._db: Optional[KnowledgeDB] = None
        self._status = "idle"
        self._source_path: Optional[Path] = None
        self._include_paths: List[Path] = []
        self._exclude_paths: List[Path] = []

    @property
    def db(self) -> Optional[KnowledgeDB]:
        return self._db

    # ── 生命周期 ──

    def initialize(self, source_path: str, **kwargs) -> bool:
        """初始化 clangd + SQLite 后端。"""
        project_root = kwargs.get("project_root", source_path)
        self._compile_commands_path = kwargs.get("compile_commands_path")
        wait = kwargs.get("wait", True)

        self._source_path = Path(source_path).absolute()
        project_root = Path(project_root).absolute() if project_root else self._source_path

        self._include_paths = [Path(p).absolute() for p in (kwargs.get("include_paths", []) or [])]
        self._exclude_paths = [Path(p).absolute() for p in (kwargs.get("exclude_paths", []) or [])]

        # 初始化 SQLite 知识库（存储在 project_root）
        db_full_path = project_root / self._db_path
        self._db = KnowledgeDB(str(db_full_path))

        self._status = "building"

        if wait:
            return self._run_full_extraction()
        else:
            import threading

            t = threading.Thread(target=self._run_full_extraction, daemon=True)
            t.start()
            return True

    def _ensure_extractor(self) -> bool:
        """按需启动 clangd 提取器（仅在有文件需要提取时调用）。"""
        if self._extractor is not None:
            return True
        if self._source_path is None:
            return False
        cc_dir = Path(self._compile_commands_path).parent if self._compile_commands_path else None
        self._extractor = ClangExtractor(
            project_root=self._source_path,  # clangd cwd/rootUri = source_root
            clangd_path=self._clangd_path,
            compile_commands_dir=cc_dir,
            max_threads=self._max_threads,
        )
        if not self._extractor.start():
            logger.error("Failed to start clangd extractor")
            return False
        return True

    def _run_full_extraction(self) -> bool:
        """Refresh base TU facts, then independently refresh derived indexes."""
        try:
            file_list = self._collect_source_files()
            from .clang_extractor import ClangExtractor

            if self._db is None:
                self._status = "error"
                return False

            db = self._db
            source_root = self._source_path
            existing_tus = list(db.get_all_tus())
            macro_version = self._metadata_value(db, "macro_extractor_version")
            type_version = self._metadata_value(db, "type_extractor_version")

            def normalize_db_path(path_value: str) -> str:
                p = Path(str(path_value))
                if not p.is_absolute() and source_root is not None:
                    p = source_root / p
                return str(p.resolve())

            current_files: Dict[str, Path] = {
                normalize_db_path(str(fp)): fp.resolve() for fp in file_list
            }
            existing_tus_by_path = {
                normalize_db_path(str(tu.get("file_path") or "")): tu
                for tu in existing_tus
                if str(tu.get("file_path") or "")
            }
            deleted_tus = [
                tu
                for tu in existing_tus
                if normalize_db_path(str(tu.get("file_path") or "")) not in current_files
            ]
            force_refresh_paths: set[str] = set()
            deleted_paths: List[Path] = []
            for tu in deleted_tus:
                tu_id = int(tu["id"])
                impact = db.get_tu_delete_impact(tu_id)
                db.delete_tu(tu_id)
                raw_path = str(tu.get("file_path") or "")
                if raw_path:
                    deleted_paths.append(Path(normalize_db_path(raw_path)))
                for related in impact.get("related_files", []):
                    related_key = normalize_db_path(str(related))
                    related_path = current_files.get(related_key)
                    if related_path is not None and self._is_path_allowed(related_path):
                        force_refresh_paths.add(related_key)

            changed_count = 0
            prescanned_tus: Dict[str, Tuple[int, bool]] = {}
            for fp in file_list:
                fp = fp.resolve()
                file_hash = ClangExtractor._compute_file_hash(fp)
                existing_tu = existing_tus_by_path.get(normalize_db_path(str(fp)))
                registered_path = (
                    str(existing_tu.get("file_path") or str(fp))
                    if existing_tu is not None
                    else str(fp)
                )
                tu_id, changed = db.register_tu_hash(registered_path, file_hash)
                if not changed and normalize_db_path(str(fp)) in force_refresh_paths:
                    changed = True
                    db.mark_tu_pending(tu_id)
                prescanned_tus[str(fp)] = (tu_id, changed)
                if changed:
                    changed_count += 1

            base_version_missing = not macro_version or not type_version
            explicit_base_version_mismatch = bool(
                (macro_version and macro_version != self.MACRO_EXTRACTOR_VERSION)
                or (type_version and type_version != self.TYPE_EXTRACTOR_VERSION)
            )
            can_confirm_v14_base = self._can_confirm_v14_base_facts(
                db,
                existing_tus=existing_tus,
                current_files=current_files,
                prescanned_tus=prescanned_tus,
                deleted_tus=deleted_tus,
                base_version_missing=base_version_missing,
                explicit_base_version_mismatch=explicit_base_version_mismatch,
                source_root=source_root,
            )
            if can_confirm_v14_base:
                logger.info(
                    "Incremental: confirmed schema-v14 base facts for %d unchanged TUs",
                    len(file_list),
                )
                self._mark_base_indexes_current(db)
                macro_version = self.MACRO_EXTRACTOR_VERSION
                type_version = self.TYPE_EXTRACTOR_VERSION

            force_macro_refresh = macro_version != self.MACRO_EXTRACTOR_VERSION
            force_type_refresh = type_version != self.TYPE_EXTRACTOR_VERSION

            if force_macro_refresh or force_type_refresh:
                for file_path, (tu_id, changed) in list(prescanned_tus.items()):
                    if not changed:
                        db.mark_tu_pending(tu_id)
                        prescanned_tus[file_path] = (tu_id, True)
                        changed_count += 1

            base_facts_changed = bool(deleted_tus or changed_count)
            if base_facts_changed:
                db.mark_derived_indexes_dirty(reason="base_facts_changed")

            derived_work = self._derived_indexes_needing_rebuild(db)
            needs_clangd = bool(file_list) and bool(changed_count or derived_work)
            extractor: Optional[ClangExtractor] = None
            if needs_clangd:
                if not self._ensure_extractor():
                    self._status = "error"
                    return False
                extractor = self._extractor
                if extractor is None:
                    self._status = "error"
                    return False
                if deleted_paths and hasattr(extractor, "notify_files_deleted"):
                    extractor.notify_files_deleted(deleted_paths)
                if not extractor.wait_for_indexing(timeout=120, idle_threshold=3.0):
                    logger.error("clangd indexing did not become ready before the hard timeout")
                    self._status = "error"
                    return False

            if changed_count:
                assert extractor is not None
                if force_macro_refresh:
                    clear_macros = getattr(db, "clear_macro_definitions", None)
                    if callable(clear_macros):
                        clear_macros()
                logger.info(
                    "Incremental: %d/%d TUs require base extraction",
                    changed_count,
                    len(file_list),
                )
                stats = extractor.run_batch_extraction(
                    file_list,
                    db,
                    batch_size=self._batch_size,
                    prescanned_tus=prescanned_tus,
                )
                logger.info(
                    "Base extraction complete: %d extracted, %d skipped, %d failed",
                    stats["success"],
                    stats["skipped"],
                    stats["failed"],
                )
                if int(stats.get("failed") or 0):
                    logger.error(
                        "Base extraction incomplete; derived indexes remain dirty failed_tus=%d",
                        int(stats.get("failed") or 0),
                    )
                    self._status = "error"
                    return False
                # Base versions become durable before either derived rebuild starts.
                self._mark_base_indexes_current(db)
            elif deleted_tus or not file_list:
                # Deletes were already applied transactionally by KnowledgeDB.  An empty
                # project has a valid empty base index and never needs clangd.
                if not file_list and force_macro_refresh:
                    clear_macros = getattr(db, "clear_macro_definitions", None)
                    if callable(clear_macros):
                        clear_macros()
                self._mark_base_indexes_current(db)
            elif force_macro_refresh or force_type_refresh:
                # This is only reachable for a zero-TU base refresh.
                self._mark_base_indexes_current(db)
            else:
                logger.info(
                    "Incremental: all %d TUs unchanged, reusing cached base facts",
                    len(file_list),
                )

            # Base extraction may have dirtied otherwise-current derived indexes.
            derived_work = self._derived_indexes_needing_rebuild(db)
            derived_failed = False
            begin_session = getattr(extractor, "begin_derived_rebuild_session", None)
            end_session = getattr(extractor, "end_derived_rebuild_session", None)
            session_started = False
            try:
                if derived_work and extractor is not None and callable(begin_session):
                    begin_session()
                    session_started = True
                for index_name, target_version, rebuild_method in derived_work:
                    try:
                        db.begin_derived_index_rebuild(index_name, target_version)
                        db.prepare_derived_index_staging(index_name)
                        if file_list:
                            if extractor is None:
                                raise RuntimeError(
                                    "clangd extractor unavailable for derived rebuild"
                                )
                            row_count = int(rebuild_method(extractor, db, use_staging=True))
                            stats_getter = getattr(extractor, "get_last_derived_stats", None)
                            last_stats = (
                                stats_getter(index_name)
                                if callable(stats_getter)
                                else {"rows": row_count}
                            )
                        else:
                            row_count = 0
                            last_stats = {"rows": 0, "files": 0, "functions": 0}
                        db.finalize_derived_index_rebuild(
                            index_name,
                            target_version,
                            last_stats,
                        )
                        logger.info("Rebuilt derived index %s rows=%d", index_name, row_count)
                    except Exception as exc:
                        derived_failed = True
                        logger.error("Derived index rebuild failed index=%s: %s", index_name, exc)
                        discard_staging = getattr(db, "discard_derived_index_staging", None)
                        if callable(discard_staging):
                            try:
                                discard_staging(index_name)
                            except Exception as discard_exc:
                                logger.error(
                                    "Failed to discard derived staging index=%s: %s",
                                    index_name,
                                    discard_exc,
                                )
                        try:
                            stats_getter = getattr(extractor, "get_last_derived_stats", None)
                            last_stats = (
                                stats_getter(index_name)
                                if extractor is not None and callable(stats_getter)
                                else {}
                            )
                            db.fail_derived_index_rebuild(
                                index_name,
                                target_version,
                                exc,
                                last_stats,
                            )
                        except Exception as state_exc:
                            logger.error(
                                "Failed to persist derived index failure index=%s: %s",
                                index_name,
                                state_exc,
                            )
            finally:
                if session_started and callable(end_session):
                    end_session()

            if derived_failed or not self._derived_indexes_are_current(db):
                self._status = "error"
                return False
            self._status = "ready"
            return True
        except Exception as e:
            logger.error("Extraction failed: %s", e)
            self._status = "error"
            return False

    @staticmethod
    def _metadata_value(db: Any, key: str) -> str:
        get_metadata = getattr(db, "get_metadata", None)
        if not callable(get_metadata):
            return ""
        try:
            return str(get_metadata(key) or "")
        except Exception:
            return ""

    def _mark_macro_index_current(self, db: Any) -> None:
        set_metadata = getattr(db, "set_metadata", None)
        if callable(set_metadata):
            set_metadata("macro_extractor_version", self.MACRO_EXTRACTOR_VERSION)

    def _mark_type_index_current(self, db: Any) -> None:
        set_metadata = getattr(db, "set_metadata", None)
        if callable(set_metadata):
            set_metadata("type_extractor_version", self.TYPE_EXTRACTOR_VERSION)

    def _mark_base_indexes_current(self, db: Any) -> None:
        self._mark_macro_index_current(db)
        self._mark_type_index_current(db)

    def _can_confirm_v14_base_facts(
        self,
        db: Any,
        *,
        existing_tus: List[Dict[str, Any]],
        current_files: Dict[str, Path],
        prescanned_tus: Dict[str, Tuple[int, bool]],
        deleted_tus: List[Dict[str, Any]],
        base_version_missing: bool,
        explicit_base_version_mismatch: bool,
        source_root: Optional[Path],
    ) -> bool:
        """One-time compatibility confirmation for pre-split schema-v14 caches."""
        if (
            not base_version_missing
            or explicit_base_version_mismatch
            or deleted_tus
            or not existing_tus
            or self._metadata_value(db, "schema_version") != "14"
        ):
            return False
        if any(str(tu.get("status") or "") != "indexed" for tu in existing_tus):
            return False
        existing_paths = set()
        for tu in existing_tus:
            path = Path(str(tu.get("file_path") or ""))
            if not path.is_absolute() and source_root is not None:
                path = source_root / path
            existing_paths.add(str(path.resolve()))
        if existing_paths != set(current_files):
            return False
        return bool(prescanned_tus) and not any(changed for _, changed in prescanned_tus.values())

    def _derived_indexes_needing_rebuild(
        self,
        db: Any,
    ) -> List[Tuple[str, str, Any]]:
        specs = (
            (
                self.FUNCTION_SYMBOL_CONTEXT_INDEX,
                self.SYMBOL_CONTEXT_EXTRACTOR_VERSION,
                lambda extractor, target_db, **kwargs: extractor.rebuild_function_symbol_refs(
                    target_db, **kwargs
                ),
            ),
            (
                self.FUNCTION_TYPE_REFS_INDEX,
                self.FUNCTION_TYPE_REF_EXTRACTOR_VERSION,
                lambda extractor, target_db, **kwargs: extractor.rebuild_function_type_refs(
                    target_db, **kwargs
                ),
            ),
        )
        return [spec for spec in specs if db.derived_index_needs_rebuild(spec[0], spec[1])]

    def _derived_indexes_are_current(self, db: Any) -> bool:
        expected = (
            (self.FUNCTION_SYMBOL_CONTEXT_INDEX, self.SYMBOL_CONTEXT_EXTRACTOR_VERSION),
            (self.FUNCTION_TYPE_REFS_INDEX, self.FUNCTION_TYPE_REF_EXTRACTOR_VERSION),
        )
        for index_name, target_version in expected:
            state = db.get_derived_index_state(index_name)
            if (
                str(state.get("status") or "") != "current"
                or str(state.get("applied_version") or "") != target_version
            ):
                return False
        return True

    def _is_path_allowed(self, p: Path) -> bool:
        """Check if a path passes include/exclude filters."""
        import os

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

        if self._exclude_paths:
            for ex in self._exclude_paths:
                if is_subpath(p, ex):
                    return False

        if self._include_paths:
            in_include = False
            for inc in self._include_paths:
                if is_subpath(p, inc):
                    in_include = True
                    break
            if not in_include:
                return False

        return True

    def _collect_source_files(self) -> List[Path]:
        """收集源码目录下所有 C/C++ 文件。"""
        files = []
        if self._source_path is None:
            return []
        extensions = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ph", ".inc", ".inl"}

        bases_to_search = self._include_paths if self._include_paths else [self._source_path]

        for base in bases_to_search:
            for file_path in base.rglob("*"):
                if file_path.suffix.lower() not in extensions:
                    continue
                if self._is_path_allowed(file_path):
                    files.append(file_path.resolve())

        # Remove duplicates
        return sorted(list(set(files)))

    def close(self) -> None:
        if self._extractor:
            self._extractor.stop()
            self._extractor = None
        if self._db:
            self._db.close()
            self._db = None
        self._status = "idle"

    def status(self) -> str:
        return self._status

    # ── 索引构建 ──

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        """从 KnowledgeDB 构建函数索引。"""
        if not self._db:
            return {}
        return self._db.get_all_functions()

    # ── 查询方法 ──

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return None
        func = self._db.get_function(name)
        if not func:
            return None
        return {
            "name": func["name"],
            "filename": func["file_path"],
            "lineNumber": func["start_line"],
            "lineNumberEnd": func["end_line"],
            "signature": func.get("signature", f"{name}(...)"),
            "is_static": bool(func.get("is_static")),
        }

    def get_macro_definitions(self, name: str, limit: int = 20) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_macro_definitions(name, limit=limit)

    def get_macro_definitions_batch(self, names: List[str]) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_macro_definitions_batch(names)

    def get_function_symbol_context(
        self,
        func_name: str,
        file_path: str = "",
    ) -> Dict[str, List[Dict[str, Any]]]:
        if not self._db:
            return {"referenced_globals": [], "referenced_macros": []}
        return self._db.get_function_symbol_context(func_name, file_path)

    def get_function_type_context(
        self,
        func_name: str,
        file_path: str = "",
        start_line: int = 0,
    ) -> Dict[str, Any]:
        if not self._db:
            return {"referenced_types": []}
        return self._db.get_function_type_context(func_name, file_path, start_line)

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callees(name, limit=limit)

    def get_callers(
        self,
        func_name: str,
        limit: int = 20,
        callee_file: str = "",
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callers(func_name, limit=limit, callee_file=callee_file)

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callees(func_name, limit=limit)

    def get_function_info_callees(
        self,
        func_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_all_callees(func_name, caller_file=file_path)

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return None
        return self._db.get_type_info(type_name)

    def find_type_infos(
        self,
        type_name: str,
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.find_type_infos(type_name, file_path=file_path)

    def get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> List[Dict[str, Any]]:
        """Clang 后端暂不支持数据流分析（需 SVF 集成）。"""
        logger.debug("Data flow analysis not available in Clang backend (requires SVF)")
        return []

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        """通过 KnowledgeDB call_edges 中 call_type='indirect' 查找函数指针。"""
        if not self._db:
            return []
        rows = self._db._conn.execute(
            "SELECT DISTINCT caller_name, caller_file, call_line "
            "FROM call_edges WHERE callee_name = ? AND call_type = 'indirect' LIMIT 20",
            (func_name,),
        ).fetchall()
        return [{"caller": r["caller_name"], "file": r["caller_file"],
                 "line": r["call_line"]} for r in rows]

    def get_header_declared_functions(
        self, header_files: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_header_functions(header_files, source_root=self._source_path)
