"""
SVF analyzer — runs SVF tools and writes results into a shared KnowledgeDB.
Not a CodeBackend; used as an internal component of UnifiedBackend.
"""

import hashlib
import json
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
            # 增量检查：计算源码聚合哈希
            agg_hash = self._compute_aggregate_hash(compile_commands_path)
            old_hash = self._db.get_svf_hash()
            if agg_hash and agg_hash == old_hash:
                logger.info(
                    "SVF incremental: source hash unchanged, reusing cached SVF data"
                )
                return True

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

            # 清除旧 SVF 数据后写入新结果
            self._db.purge_svf_data()
            mapper = SvfOutputMapper(self._db)
            ander = self._results.get("ander")
            if ander and ander.output_file:
                mapper.import_callgraph(ander.output_file)
            saber = self._results.get("saber")
            if saber and saber.bugs:
                mapper.import_saber_bugs(saber.bugs)

            # 记录新哈希
            if agg_hash:
                self._db.set_svf_hash(agg_hash)
            return True
        except Exception as e:
            logger.error("SVF analysis failed: %s", e)
            return False

    @staticmethod
    def _compute_aggregate_hash(compile_commands_path: Path) -> str:
        """基于 compile_commands.json 中所有源文件计算聚合 SHA-256。"""
        try:
            with open(compile_commands_path, "r", encoding="utf-8") as f:
                commands = json.load(f)
        except (json.JSONDecodeError, OSError):
            return ""

        c_exts = {".c", ".cc", ".cpp", ".cxx"}
        source_files = []
        for cmd in commands:
            src = cmd.get("file", "")
            if Path(src).suffix.lower() in c_exts:
                src_path = Path(src)
                if not src_path.is_absolute():
                    src_path = Path(cmd.get("directory", ".")) / src_path
                source_files.append(src_path.resolve())

        # 按路径排序以保证确定性
        source_files.sort()

        agg = hashlib.sha256()
        for fp in source_files:
            agg.update(str(fp).encode("utf-8"))
            try:
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        agg.update(chunk)
            except OSError:
                agg.update(b"__missing__")
        return agg.hexdigest()[:32]
