"""
Unified backend — Clang AST extraction + SVF deep analysis sharing one KnowledgeDB.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .backend_base import CodeBackend
from .clang_backend import ClangBackend
from .svf_analyzer import SvfAnalyzer

logger = logging.getLogger(__name__)


class UnifiedBackend(CodeBackend):
    """Facade: Clang AST + SVF 分析，共享同一个 KnowledgeDB。"""

    def __init__(
        self,
        clangd_path: str = "clangd",
        db_path: str = ".zscope_knowledge/code_knowledge.db",
        batch_size: int = 50,
        max_threads: int = 8,
        svf_bin_dir: str = "",
        gclang_path: str = "gclang",
        get_bc_path: str = "get-bc",
        llvm_link_path: str = "llvm-link",
        svf_heap_limit_mb: int = 32768,
        svf_timeout: int = 1800,
    ):
        self._clang = ClangBackend(
            clangd_path=clangd_path, db_path=db_path,
            batch_size=batch_size, max_threads=max_threads,
        )
        self._svf_cfg = dict(
            svf_bin_dir=svf_bin_dir, gclang_path=gclang_path,
            get_bc_path=get_bc_path, llvm_link_path=llvm_link_path,
            heap_limit_mb=svf_heap_limit_mb, timeout=svf_timeout,
        )
        self._svf: Optional[SvfAnalyzer] = None
        self._status = "idle"

    @property
    def db(self):
        return self._clang._db

    # ── 生命周期 ──

    def initialize(self, source_path: str, **kwargs) -> bool:
        self._status = "building"
        wait = kwargs.get("wait", True)

        # 阶段1: Clang AST 提取
        ok = self._clang.initialize(source_path, **kwargs)
        if not ok:
            self._status = "error"
            return False

        if not wait:
            self._status = "ready"
            return True

        # 阶段2: SVF 分析（共享 Clang 的 KnowledgeDB）
        if self._clang._db:
            self._svf = SvfAnalyzer(db=self._clang._db, **self._svf_cfg)
            cc = kwargs.get("compile_commands_path")
            project_root = kwargs.get("project_root", Path(source_path))
            self._svf.run(
                Path(source_path), Path(project_root),
                Path(cc) if cc else None,
            )

        self._status = "ready"
        return True

    def close(self) -> None:
        self._clang.close()
        self._svf = None
        self._status = "idle"

    def status(self) -> str:
        return self._status

    # ── 委托 ClangBackend 的 AST 查询 ──

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        return self._clang.build_function_index()

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        return self._clang.get_method(name)

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self._clang.get_method_callees(name, limit)

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        return self._clang.get_type_info(type_name)

    def get_header_declared_functions(self, header_files=None) -> List[Dict[str, Any]]:
        return self._clang.get_header_declared_functions(header_files)

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        return self._clang.find_function_pointers(func_name)

    # ── 合并查询（Clang direct + SVF indirect）──

    def get_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        direct = db.get_callers(func_name, limit=limit)
        indirect = db.get_indirect_callers(func_name, limit=limit)
        seen = {d["name"] for d in direct}
        for ic in indirect:
            if ic["name"] not in seen:
                direct.append({"name": ic["name"], "filename": ic.get("call_file", ""), "lineNumber": 0})
        return direct[:limit]

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        direct = db.get_callees(func_name, limit=limit)
        indirect = db.get_indirect_callees(func_name, limit=limit)
        seen = {d["name"] for d in direct}
        for ic in indirect:
            if ic["name"] not in seen:
                direct.append({"name": ic["name"], "source": ic.get("source", "svf")})
        return direct[:limit]

    def get_data_flow(self, source_func: str, source_param: str,
                      sink_pattern: str) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        return db.get_enriched_taint_bugs(bug_type=sink_pattern, func_name=source_func)

    # ── SVF 特有查询（供工具层调用）──

    def get_indirect_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        return db.get_indirect_callees(func_name, limit=limit)

    def get_taint_bugs(self, bug_type: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        db = self.db
        if not db:
            return []
        return db.get_enriched_taint_bugs(bug_type=bug_type, limit=limit)
