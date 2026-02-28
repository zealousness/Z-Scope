"""
SVF-backed code analysis backend (DEPRECATED).

.. deprecated::
    Use ``unified`` backend instead, which combines Clang AST + SVF analysis
    over a shared KnowledgeDB. See ``unified_backend.py``.
"""

import logging
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional

from .backend_base import CodeBackend
from .knowledge_db import KnowledgeDB
from .build_llvm import BitcodeBuilder
from .svf_runner import SvfRunner
from .svf_parser import SvfOutputMapper

logger = logging.getLogger(__name__)


class SvfBackend(CodeBackend):
    """SVF 后端：在 Clang 函数索引基础上叠加间接调用解析和污点分析。"""

    def __init__(
        self,
        db_path: str = ".zscope_knowledge/code_knowledge.db",
        svf_bin_dir: str = "",
        gclang_path: str = "gclang",
        get_bc_path: str = "get-bc",
        llvm_link_path: str = "llvm-link",
        heap_limit_mb: int = 32768,
        timeout: int = 1800,
    ):
        warnings.warn(
            "SvfBackend is deprecated. Use 'unified' backend instead (ClangBackend + SvfAnalyzer).",
            DeprecationWarning,
            stacklevel=2,
        )
        self._db_path = db_path
        self._db: Optional[KnowledgeDB] = None
        self._svf_bin_dir = svf_bin_dir
        self._gclang = gclang_path
        self._get_bc = get_bc_path
        self._llvm_link = llvm_link_path
        self._heap_limit = heap_limit_mb
        self._timeout = timeout
        self._status = "idle"

    def initialize(self, source_path: str, **kwargs) -> bool:
        """初始化：打开 DB，构建 bitcode，运行 SVF 分析。"""
        self._status = "building"
        self._db = KnowledgeDB(self._db_path)

        wait = kwargs.get("wait", True)
        compile_commands = kwargs.get("compile_commands_path")
        project_root = kwargs.get("project_root", Path(source_path))

        if not wait:
            self._status = "ready"
            return True

        if not compile_commands:
            logger.warning("No compile_commands_path, skipping SVF build")
            self._status = "ready"
            return True

        try:
            # 1. 构建 bitcode
            builder = BitcodeBuilder(
                source_root=Path(source_path),
                compile_commands_path=Path(compile_commands),
                gclang_path=self._gclang,
                get_bc_path=self._get_bc,
                llvm_link_path=self._llvm_link,
                timeout=self._timeout,
            )
            bc_path = builder.build()
            if not bc_path:
                logger.warning("Bitcode build failed, SVF analysis skipped")
                self._status = "ready"
                return True

            # 2. 运行 SVF
            runner = SvfRunner(
                svf_bin_dir=self._svf_bin_dir,
                heap_limit_mb=self._heap_limit,
                timeout=self._timeout,
            )
            output_dir = Path(project_root) / ".zscope_svf"
            results = runner.run_all(bc_path, output_dir)

            # 3. 导入结果到 DB
            mapper = SvfOutputMapper(self._db)
            ander = results.get("ander")
            if ander and ander.output_file:
                mapper.import_callgraph(ander.output_file)
            saber = results.get("saber")
            if saber and saber.bugs:
                mapper.import_saber_bugs(saber.bugs)

            self._status = "ready"
            return True
        except Exception as e:
            logger.error("SVF initialization failed: %s", e)
            self._status = "error"
            return False

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None

    def status(self) -> str:
        return self._status

    # ── 索引构建 ──

    def build_function_index(self) -> Dict[str, Dict[str, Any]]:
        if not self._db:
            return {}
        return self._db.get_all_functions()

    # ── 查询方法 ──

    def get_callers(self, func_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        # 合并直接调用 + 间接调用
        direct = self._db.get_callers(func_name, limit=limit)
        indirect = self._db.get_indirect_callers(func_name, limit=limit)
        seen = {d["name"] for d in direct}
        for ic in indirect:
            if ic["name"] not in seen:
                direct.append({"name": ic["name"], "filename": "", "lineNumber": 0})
        return direct[:limit]

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        direct = self._db.get_callees(func_name, limit=limit)
        indirect = self._db.get_indirect_callees(func_name, limit=limit)
        seen = {d["name"] for d in direct}
        for ic in indirect:
            if ic["name"] not in seen:
                direct.append({"name": ic["name"]})
        return direct[:limit]

    def get_type_info(self, type_name: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return None
        return self._db.get_type_info(type_name)

    def get_data_flow(self, source_func: str, source_param: str,
                      sink_pattern: str) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_taint_bugs(bug_type=sink_pattern)

    def find_function_pointers(self, func_name: str) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_indirect_callers(func_name)

    def get_header_declared_functions(self, header_files=None) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_header_functions(header_files)

    def get_method(self, name: str) -> Optional[Dict[str, Any]]:
        if not self._db:
            return None
        f = self._db.get_function(name)
        if not f:
            return None
        return {
            "filename": f["file_path"],
            "lineNumber": f["start_line"],
            "lineNumberEnd": f["end_line"],
            "signature": f.get("signature", ""),
        }

    def get_method_callees(self, name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return self.get_callees(name, limit=limit)

    # ── SVF 特有查询 ──

    def get_indirect_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_indirect_callees(func_name, limit=limit)

    def get_taint_bugs(self, bug_type: str = "", limit: int = 50) -> List[Dict[str, Any]]:
        if not self._db:
            return []
        return self._db.get_taint_bugs(bug_type, limit=limit)
