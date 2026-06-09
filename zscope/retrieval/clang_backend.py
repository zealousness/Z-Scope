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

    MACRO_EXTRACTOR_VERSION = "1"

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
            project_root=self._source_path,   # clangd cwd/rootUri = source_root
            clangd_path=self._clangd_path,
            compile_commands_dir=cc_dir,
            max_threads=self._max_threads,
        )
        if not self._extractor.start():
            logger.error("Failed to start clangd extractor")
            return False
        return True

    def _run_full_extraction(self) -> bool:
        """执行完整的代码提取流程（增量：仅提取哈希变化的文件）。"""
        try:
            # 收集所有 C/C++ 源文件
            file_list = self._collect_source_files()
            # 预扫描：检查有多少文件真正需要提取
            from .clang_extractor import ClangExtractor
            changed_count = 0
            prescanned_tus: Dict[str, Tuple[int, bool]] = {}
            if self._db is None:
                self._status = "error"
                return False

            db = self._db
            source_root = self._source_path
            force_macro_refresh = self._macro_index_needs_refresh(db)
            if force_macro_refresh:
                clear_macros = getattr(db, "clear_macro_definitions", None)
                if callable(clear_macros):
                    clear_macros()

            def normalize_db_path(path_value: str) -> str:
                p = Path(str(path_value))
                if not p.is_absolute() and source_root is not None:
                    p = source_root / p
                return str(p.resolve())

            current_files: Dict[str, Path] = {
                normalize_db_path(str(fp)): fp.resolve() for fp in file_list
            }
            deleted_tus = [
                tu for tu in db.get_all_tus()
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

            if not file_list:
                logger.warning("No source files found in %s", self._source_path)
                self._mark_macro_index_current(db)
                self._status = "ready"
                return True

            for fp in file_list:
                fp = fp.resolve()
                file_hash = ClangExtractor._compute_file_hash(fp)
                tu_id, changed = db.register_tu_hash(str(fp), file_hash)
                if not changed and (
                    normalize_db_path(str(fp)) in force_refresh_paths or force_macro_refresh
                ):
                    changed = True
                    db.mark_tu_pending(tu_id)
                prescanned_tus[str(fp)] = (tu_id, changed)
                if changed:
                    changed_count += 1

            if changed_count == 0:
                logger.info(
                    "Incremental: all %d files unchanged, reusing cached KnowledgeDB",
                    len(file_list),
                )
                self._mark_macro_index_current(db)
                self._status = "ready"
                return True

            logger.info(
                "Incremental: %d/%d files changed, starting clangd extraction",
                changed_count, len(file_list),
            )

            # 按需启动 clangd
            if not self._ensure_extractor():
                self._status = "error"
                return False
            extractor = self._extractor
            if extractor is None:
                self._status = "error"
                return False
            if deleted_paths and hasattr(extractor, "notify_files_deleted"):
                extractor.notify_files_deleted(deleted_paths)

            # 等待 clangd 后台索引稳定
            extractor.wait_for_indexing(timeout=120, idle_threshold=3.0)

            # 批量提取（复用预扫描结果，仅提取 changed 的）
            stats = extractor.run_batch_extraction(
                file_list,
                db,
                batch_size=self._batch_size,
                prescanned_tus=prescanned_tus,
            )
            logger.info(
                "Extraction complete: %d extracted, %d skipped, %d failed",
                stats["success"], stats["skipped"], stats["failed"],
            )
            self._mark_macro_index_current(db)
            self._status = "ready"
            return True
        except Exception as e:
            logger.error("Extraction failed: %s", e)
            self._status = "error"
            return False

    def _macro_index_needs_refresh(self, db: Any) -> bool:
        get_metadata = getattr(db, "get_metadata", None)
        if not callable(get_metadata):
            return False
        try:
            return str(get_metadata("macro_extractor_version") or "") != self.MACRO_EXTRACTOR_VERSION
        except Exception:
            return False

    def _mark_macro_index_current(self, db: Any) -> None:
        set_metadata = getattr(db, "set_metadata", None)
        if callable(set_metadata):
            set_metadata("macro_extractor_version", self.MACRO_EXTRACTOR_VERSION)

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
        extensions = ("*.c", "*.cpp", "*.cc", "*.cxx", "*.h", "*.hpp", "*.ph", "*.inc", "*.inl")
        
        bases_to_search = self._include_paths if self._include_paths else [self._source_path]
        
        for base in bases_to_search:
            for ext in extensions:
                for file_path in base.rglob(ext):
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
        }

    def get_macro_definitions(self, name: str, limit: int = 20) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_macro_definitions(name, limit=limit)

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

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return None
        return self._db.get_type_info(type_name)

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
