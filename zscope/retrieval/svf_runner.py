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
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .indexing_runtime import run_process

logger = logging.getLogger(__name__)


@dataclass
class SvfResult:
    """SVF 单次执行结果。"""
    tool: str  # "wpa" | "saber"
    success: bool = False
    timed_out: bool = False
    output_file: Optional[Path] = None
    stderr: str = ""
    bugs: List[Dict[str, Any]] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)


class SvfRunner:
    """SVF 工具执行引擎。"""

    def __init__(
        self,
        svf_bin_dir: str = "",
        heap_limit_mb: int = 32768,
        timeout: Optional[float] = 1800.0,
    ):
        self.svf_bin_dir = Path(svf_bin_dir) if svf_bin_dir else None
        self.heap_limit_mb = heap_limit_mb
        self.timeout = timeout
        self.cancel_event = threading.Event()

    def _tool_path(self, name: str) -> str:
        """解析 SVF 工具的完整路径。"""
        if self.svf_bin_dir:
            p = self.svf_bin_dir / name
            return str(p)  # An explicit directory must never fall back to PATH.
        return name  # 依赖 PATH

    def validate_llvm(self, llvm_link: str) -> None:
        from .llvm_toolchain import validate_svf_llvm
        validate_svf_llvm(str(self.svf_bin_dir or ""), llvm_link)

    def _make_env(self) -> Dict[str, str]:
        """构建带内存限制和库搜索路径的环境变量。"""
        from .llvm_toolchain import svf_environment
        env = svf_environment(str(self.svf_bin_dir or ""))
        # ulimit 风格的软限制（Linux）；SVF 自身也会检查
        env["SVF_MEMORY_LIMIT"] = str(self.heap_limit_mb)
        if env.get("LD_LIBRARY_PATH"):
            logger.info("SVF LD_LIBRARY_PATH: %s", env["LD_LIBRARY_PATH"])
        return env

    def _run_cmd(self, cmd: List[str], work_dir: Path) -> subprocess.CompletedProcess:
        """执行子进程，统一超时和内存防护。"""
        logger.info("SVF cmd: %s", " ".join(cmd))
        return run_process(  # type: ignore[return-value]
            cmd, cwd=work_dir, output_prefix=work_dir / "analysis",
            env=self._make_env(), timeout=self.timeout,
            memory_limit_mb=self.heap_limit_mb, label=Path(cmd[0]).name,
            cancel=self.cancel_event,
        )

    def run_ander(self, bc_path: Path, output_dir: Path) -> SvfResult:
        """运行 Andersen 指针分析，生成调用图和指针别名信息。

        wpa -ander -dump-callgraph
        输出：callgraph_final.dot
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        result = SvfResult(tool="wpa-ander")
        (output_dir / "callgraph_final.dot").unlink(missing_ok=True)

        cmd = [
            self._tool_path("wpa"),
            "-ander",              # Andersen 包含式指针分析
            "-dump-callgraph",     # 导出间接调用解析后的调用图
            str(bc_path),
        ]

        try:
            proc = self._run_cmd(cmd, output_dir)
            result.metrics = getattr(proc, "metrics", {})
            result.timed_out = bool(result.metrics.get("timed_out"))
            result.stderr = proc.stderr
            result.success = proc.returncode == 0 and not result.timed_out and not result.metrics.get("memory_exceeded")
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
            logger.error("wpa-ander timed out after %ss", self.timeout)
            result.timed_out = True
            result.stderr = f"Timeout after {self.timeout}s"
        except FileNotFoundError:
            logger.error("wpa not found; check svf_bin_dir config")
            result.stderr = "wpa binary not found"

        return result

    def run_saber(self, bc_path: Path, output_dir: Path) -> SvfResult:
        """运行 Saber 检测内存泄漏 / 双重释放。

        saber -leak -dfree (SVF 3.x 不支持 -uaf 标志)
        输出解析自 stderr 的 bug 报告。
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        result = SvfResult(tool="saber")

        cmd = [
            self._tool_path("saber"),
            "-leak",   # 内存泄漏（NeverFree, PartialLeak）
            "-dfree",  # 双重释放
            str(bc_path),
        ]

        try:
            proc = self._run_cmd(cmd, output_dir)
            result.metrics = getattr(proc, "metrics", {})
            result.timed_out = bool(result.metrics.get("timed_out"))
            result.stderr = proc.stderr
            result.success = proc.returncode == 0 and not result.timed_out and not result.metrics.get("memory_exceeded") and not result.metrics.get("output_truncated")
            result.bugs = self._parse_saber_output(proc.stdout + proc.stderr)
            logger.info(
                "saber %s, found %d bugs",
                "succeeded" if result.success else "failed",
                len(result.bugs),
            )
        except subprocess.TimeoutExpired:
            logger.error("saber timed out after %ss", self.timeout)
            result.timed_out = True
            result.stderr = f"Timeout after {self.timeout}s"
        except FileNotFoundError:
            logger.error("saber not found; check svf_bin_dir config")
            result.stderr = "saber binary not found"

        return result

    @staticmethod
    def _parse_saber_output(text: str) -> List[Dict[str, Any]]:
        """从 saber 输出中提取 bug 报告。

        兼容两种输出格式：
        - SVF 2.x: BUG: Memory Leak at   File: foo.c  Line: 42
        - SVF 3.x: NeverFree : memory allocation at : (CallICFGNode: { "ln": 19, "fl": "main.c" })
        """
        import re
        bugs = []

        # SVF 3.x 格式: <BugType> : ... (CallICFGNode: { "ln": N, ... "fl": "file.c" })
        #   类型: NeverFree, PartialLeak, UseAfterFree, DoubleFree
        pattern_v3 = re.compile(
            r'(?P<type>NeverFree|PartialLeak|UseAfterFree|DoubleFree|FreeNotMalloc)'
            r'\s*:\s*[^\n]*?\(CallICFGNode:\s*\{\s*"ln":\s*(?P<line>\d+)'
            r'[^}]*?"fl":\s*"(?P<file>[^"]+)"',
            re.IGNORECASE,
        )

        # SVF 2.x 格式: BUG: <type> at File: <file> Line: <line>
        pattern_v2 = re.compile(
            r"BUG:\s*(?P<type>[^\n]+?)\s+at\s+"
            r"(?:File:\s*(?P<file>[^\s]+))?\s*"
            r"(?:Line:\s*(?P<line>\d+))?",
            re.IGNORECASE,
        )

        # SVF 3.x 类型名映射
        type_map = {
            "NeverFree": "Memory Leak",
            "PartialLeak": "Partial Memory Leak",
            "UseAfterFree": "Use After Free",
            "DoubleFree": "Double Free",
            "FreeNotMalloc": "Free Not Malloc",
        }

        # 先尝试 v3 格式
        for m in pattern_v3.finditer(text):
            raw_type = m.group("type").strip()
            bugs.append({
                "type": type_map.get(raw_type, raw_type),
                "file": m.group("file") or "",
                "line": int(m.group("line")) if m.group("line") else 0,
            })

        # 如果 v3 没匹配到，回退 v2
        if not bugs:
            for m in pattern_v2.finditer(text):
                bugs.append({
                    "type": m.group("type").strip(),
                    "file": m.group("file") or "",
                    "line": int(m.group("line")) if m.group("line") else 0,
                })

        return bugs
