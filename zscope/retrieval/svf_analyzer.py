"""
SVF analyzer — runs SVF tools and writes results into a shared KnowledgeDB.
Not a CodeBackend; used as an internal component of UnifiedBackend.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

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
            compile_commands_path: Optional[Path] = None,
            svf_groups_config: str = "") -> bool:
        """构建 bitcode 并按分组运行 SVF 分析，结果隔离写入共享 DB。"""
        if not compile_commands_path:
            logger.warning("No compile_commands_path, skipping SVF")
            return True
        try:
            # 解析分组配置
            groups: Dict[str, List[str]] = {"default": []}
            if svf_groups_config:
                groups_path = Path(svf_groups_config)
                if not groups_path.is_absolute():
                    groups_path = project_root / groups_path
                if groups_path.exists():
                    try:
                        with open(groups_path, "r", encoding="utf-8") as f:
                            groups = json.load(f)
                    except json.JSONDecodeError as e:
                        logger.error("Failed to parse SVF groups config %s: %s", groups_path, e)

            # 增量检查：计算源码聚合哈希（连同分组配置的内容一起哈希，使得配置更改能触发重新分析）
            agg_hash = self._compute_aggregate_hash(compile_commands_path, groups)
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
            # 获取分组构建的三方件结果字典
            bc_paths = builder.build(groups=groups)
            if not bc_paths:
                logger.warning("Bitcode build failed or no bitcode generated, SVF skipped")
                return True

            runner = SvfRunner(
                svf_bin_dir=self._svf_bin_dir,
                heap_limit_mb=self._heap_limit,
                timeout=self._timeout,
            )
            
            # 循环对每一组进行分析
            for group_name, bc_path in bc_paths.items():
                logger.info("Running SVF analysis for group '%s' using %s", group_name, bc_path)
                
                # 为每组独立输出目录
                group_suffix = f"_{group_name}" if group_name != "default" else ""
                output_dir = project_root / f".zscope_svf{group_suffix}"
                
                self._results = runner.run_all(bc_path, output_dir)

                # 清除当前组的旧 SVF 数据
                self._db.purge_svf_data(group=group_name)
                
                # 当前组数据映射到 DB
                mapper = SvfOutputMapper(self._db, svf_group=group_name)
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
    def _compute_aggregate_hash(compile_commands_path: Path, groups_config: Optional[Dict] = None) -> str:
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
        
        # 将最新的分组配置内容先作为盐加进 hash，若配置变动立刻重新分析
        if groups_config:
            agg.update(json.dumps(groups_config, sort_keys=True).encode("utf-8"))

        for fp in source_files:
            agg.update(str(fp).encode("utf-8"))
            try:
                with open(fp, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        agg.update(chunk)
            except OSError:
                agg.update(b"__missing__")
        return agg.hexdigest()[:32]
