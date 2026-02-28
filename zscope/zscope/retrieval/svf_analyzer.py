"""
SVF analyzer — runs SVF tools and writes results into a shared KnowledgeDB.
Not a CodeBackend; used as an internal component of UnifiedBackend.
"""

import logging
from pathlib import Path
from typing import Dict, Optional

from .build_llvm import BitcodeBuilder
from .knowledge_db import KnowledgeDB
from .svf_runner import SvfRunner, SvfResult
from .svf_parser import SvfOutputMapper

logger = logging.getLogger(__name__)


class SvfAnalyzer:
    """SVF 分析器：接受共享 KnowledgeDB，运行 SVF 并写入结果。"""

    def __init__(
        self,
        db: KnowledgeDB,
        svf_bin_dir: str = "",
        gclang_path: str = "gclang",
        get_bc_path: str = "get-bc",
        llvm_link_path: str = "llvm-link",
        heap_limit_mb: int = 32768,
        timeout: int = 1800,
    ):
        self._db = db
        self._svf_bin_dir = svf_bin_dir
        self._gclang = gclang_path
        self._get_bc = get_bc_path
        self._llvm_link = llvm_link_path
        self._heap_limit = heap_limit_mb
        self._timeout = timeout
        self._results: Dict[str, SvfResult] = {}

    def run(self, source_path: Path, project_root: Path,
            compile_commands_path: Optional[Path] = None) -> bool:
        """构建 bitcode 并运行 SVF 分析，结果写入共享 DB。"""
        if not compile_commands_path:
            logger.warning("No compile_commands_path, skipping SVF")
            return True
        try:
            builder = BitcodeBuilder(
                source_root=source_path,
                compile_commands_path=compile_commands_path,
                gclang_path=self._gclang,
                get_bc_path=self._get_bc,
                llvm_link_path=self._llvm_link,
                timeout=self._timeout,
            )
            bc_path = builder.build()
            if not bc_path:
                logger.warning("Bitcode build failed, SVF skipped")
                return True

            runner = SvfRunner(
                svf_bin_dir=self._svf_bin_dir,
                heap_limit_mb=self._heap_limit,
                timeout=self._timeout,
            )
            output_dir = project_root / ".zscope_svf"
            self._results = runner.run_all(bc_path, output_dir)

            mapper = SvfOutputMapper(self._db)
            ander = self._results.get("ander")
            if ander and ander.output_file:
                mapper.import_callgraph(ander.output_file)
            saber = self._results.get("saber")
            if saber and saber.bugs:
                mapper.import_saber_bugs(saber.bugs)
            return True
        except Exception as e:
            logger.error("SVF analysis failed: %s", e)
            return False
