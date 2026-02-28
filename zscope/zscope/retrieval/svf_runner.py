"""
SVF execution engine wrapper — runs wpa/saber on merged LLVM bitcode.

核心原则：全局稀疏建图，按需局部查询。
- wpa -ander: Andersen 指针分析（流不敏感，可扩展到百万行）
- saber: 内存泄漏 / UAF / 双重释放检测
"""

import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SvfResult:
    """SVF 单次执行结果。"""
    tool: str  # "wpa" | "saber"
    success: bool = False
    output_file: Optional[Path] = None
    stderr: str = ""
    bugs: List[Dict[str, Any]] = field(default_factory=list)


class SvfRunner:
    """SVF 工具执行引擎。"""

    def __init__(
        self,
        svf_bin_dir: str = "",
        heap_limit_mb: int = 32768,
        timeout: int = 1800,
    ):
        self.svf_bin_dir = Path(svf_bin_dir) if svf_bin_dir else None
        self.heap_limit_mb = heap_limit_mb
        self.timeout = timeout

    def _tool_path(self, name: str) -> str:
        """解析 SVF 工具的完整路径。"""
        if self.svf_bin_dir:
            p = self.svf_bin_dir / name
            if p.exists():
                return str(p)
        return name  # 依赖 PATH

    def _make_env(self) -> Dict[str, str]:
        """构建带内存限制的环境变量。"""
        env = os.environ.copy()
        # ulimit 风格的软限制（Linux）；SVF 自身也会检查
        env["SVF_MEMORY_LIMIT"] = str(self.heap_limit_mb)
        return env

    def _run_cmd(self, cmd: List[str], work_dir: Path) -> subprocess.CompletedProcess:
        """执行子进程，统一超时和内存防护。"""
        logger.info("SVF cmd: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            cwd=str(work_dir),
            env=self._make_env(),
            timeout=self.timeout,
            capture_output=True,
            text=True,
        )

    def run_ander(self, bc_path: Path, output_dir: Path) -> SvfResult:
        """运行 Andersen 指针分析，生成调用图和指针别名信息。

        wpa -ander -dump-callgraph -dump-pag
        输出：callgraph_final.dot, pag_final.dot
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        result = SvfResult(tool="wpa-ander")

        cmd = [
            self._tool_path("wpa"),
            "-ander",              # Andersen 包含式指针分析
            "-dump-callgraph",     # 导出间接调用解析后的调用图
            "-dump-pag",           # 导出 PAG（程序赋值图）
            str(bc_path),
        ]

        try:
            proc = self._run_cmd(cmd, output_dir)
            result.stderr = proc.stderr
            result.success = proc.returncode == 0
            # wpa 在 cwd 下生成 .dot 文件
            cg_file = output_dir / "callgraph_final.dot"
            if cg_file.exists():
                result.output_file = cg_file
            logger.info(
                "wpa-ander %s (rc=%d)",
                "succeeded" if result.success else "failed",
                proc.returncode,
            )
        except subprocess.TimeoutExpired:
            logger.error("wpa-ander timed out after %ds", self.timeout)
            result.stderr = f"Timeout after {self.timeout}s"
        except FileNotFoundError:
            logger.error("wpa not found; check svf_bin_dir config")
            result.stderr = "wpa binary not found"

        return result

    def run_saber(self, bc_path: Path, output_dir: Path) -> SvfResult:
        """运行 Saber 检测内存泄漏 / UAF / 双重释放。

        saber -leak -uaf -dfree
        输出解析自 stderr 的 bug 报告。
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        result = SvfResult(tool="saber")

        cmd = [
            self._tool_path("saber"),
            "-leak",   # 内存泄漏
            "-uaf",    # use-after-free
            "-dfree",  # double-free
            str(bc_path),
        ]

        try:
            proc = self._run_cmd(cmd, output_dir)
            result.stderr = proc.stderr
            result.success = proc.returncode == 0
            result.bugs = self._parse_saber_output(proc.stdout + proc.stderr)
            logger.info(
                "saber %s, found %d bugs",
                "succeeded" if result.success else "failed",
                len(result.bugs),
            )
        except subprocess.TimeoutExpired:
            logger.error("saber timed out after %ds", self.timeout)
            result.stderr = f"Timeout after {self.timeout}s"
        except FileNotFoundError:
            logger.error("saber not found; check svf_bin_dir config")
            result.stderr = "saber binary not found"

        return result

    def run_all(self, bc_path: Path, output_dir: Path) -> Dict[str, SvfResult]:
        """依次运行 ander + saber，返回结果字典。"""
        return {
            "ander": self.run_ander(bc_path, output_dir),
            "saber": self.run_saber(bc_path, output_dir),
        }

    @staticmethod
    def _parse_saber_output(text: str) -> List[Dict[str, Any]]:
        """从 saber 输出中提取 bug 报告。

        Saber 输出格式示例：
          BUG: Memory Leak at   File: foo.c  Line: 42
        """
        import re
        bugs = []
        pattern = re.compile(
            r"BUG:\s*(?P<type>[^\n]+?)\s+at\s+"
            r"(?:File:\s*(?P<file>[^\s]+))?\s*"
            r"(?:Line:\s*(?P<line>\d+))?",
            re.IGNORECASE,
        )
        for m in pattern.finditer(text):
            bugs.append({
                "type": m.group("type").strip(),
                "file": m.group("file") or "",
                "line": int(m.group("line")) if m.group("line") else 0,
            })
        return bugs
