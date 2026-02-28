"""
Clang-SQLite backend - implements CodeBackend using clangd LSP + KnowledgeDB.
Provides precise C/C++ code structure extraction without Joern dependency.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .backend_base import CodeBackend
from .clang_extractor import ClangExtractor
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)


class ClangBackend(CodeBackend):
    """
    基于 clangd LSP + SQLite 的代码分析后端。
    使用 ClangExtractor 批量提取代码结构，存入 KnowledgeDB 供查询。
    """

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

    # ── 生命周期 ──

    def initialize(self, source_path: str, **kwargs) -> bool:
        """初始化 clangd + SQLite 后端。"""
        project_root = kwargs.get("project_root", source_path)
        compile_commands_path = kwargs.get("compile_commands_path")
        wait = kwargs.get("wait", True)

        self._source_path = Path(source_path).resolve()
        project_root = Path(project_root).resolve() if project_root else self._source_path

        # 初始化 SQLite 知识库
        db_full_path = project_root / self._db_path
        self._db = KnowledgeDB(str(db_full_path))

        # 初始化 clangd 提取器
        cc_dir = Path(compile_commands_path).parent if compile_commands_path else None
        self._extractor = ClangExtractor(
            project_root=project_root,
            clangd_path=self._clangd_path,
            compile_commands_dir=cc_dir,
            max_threads=self._max_threads,
        )

        if not self._extractor.start():
            self._status = "error"
            logger.error("Failed to start clangd extractor")
            return False

        self._status = "building"

        if wait:
            return self._run_full_extraction()
        else:
            import threading
            t = threading.Thread(target=self._run_full_extraction, daemon=True)
            t.start()
            return True

    def _run_full_extraction(self) -> bool:
        """执行完整的代码提取流程。"""
        try:
            # 收集所有 C/C++ 源文件
            file_list = self._collect_source_files()
            if not file_list:
                logger.warning("No source files found in %s", self._source_path)
                self._status = "ready"
                return True

            logger.info("Found %d source files to extract", len(file_list))

            # 等待 clangd 后台索引稳定
            self._extractor.wait_for_indexing(timeout=120, idle_threshold=3.0)

            # 批量提取
            stats = self._extractor.run_batch_extraction(
                file_list, self._db, batch_size=self._batch_size,
            )
            logger.info(
                "Extraction complete: %d/%d success, %d failed",
                stats["success"], stats["total"], stats["failed"],
            )
            self._status = "ready"
            return True
        except Exception as e:
            logger.error("Extraction failed: %s", e)
            self._status = "error"
            return False

    def _collect_source_files(self) -> List[Path]:
        """收集源码目录下所有 C/C++ 文件。"""
        files = []
        for ext in ("*.c", "*.cpp", "*.cc", "*.h", "*.hpp"):
            files.extend(self._source_path.rglob(ext))
        return sorted(files)

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

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callees(name, limit=limit)

    def get_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_callers(func_name, limit=limit)

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
        return self._db.get_header_functions(header_files)
