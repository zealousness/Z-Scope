"""
LLVM Bitcode builder — wraps gllvm/wllvm to produce whole-program .bc from compile_commands.json.

流程：
1. 读取 compile_commands.json
2. 用 gclang 替换原始编译器，注入 -g -O0
3. 编译每个 TU 为 .o（内嵌 bitcode）
4. get-bc 提取 .bc，llvm-link 合并为单一 .bc
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


class BitcodeBuilder:
    """从 compile_commands.json 构建全程序 LLVM bitcode。"""

    def __init__(
        self,
        source_root: Path,
        compile_commands_path: Path,
        output_dir: Optional[Path] = None,
        gclang_path: str = "gclang",
        get_bc_path: str = "get-bc",
        llvm_link_path: str = "llvm-link",
        timeout: int = 1800,
    ):
        self.source_root = Path(source_root).resolve()
        self.compile_commands_path = Path(compile_commands_path).resolve()
        self.output_dir = Path(output_dir or self.source_root / ".zscope_bc").resolve()
        self.gclang = gclang_path
        self.get_bc = get_bc_path
        self.llvm_link = llvm_link_path
        self.timeout = timeout
        self._bc_files: List[Path] = []

    def build(self) -> Optional[Path]:
        """执行完整构建流程，返回合并后的 .bc 路径。"""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        commands = self._load_compile_commands()
        if not commands:
            logger.error("No compile commands loaded")
            return None

        logger.info("Building bitcode for %d translation units", len(commands))

        # 逐 TU 编译
        for idx, cmd in enumerate(commands):
            self._compile_tu(cmd, idx)

        if not self._bc_files:
            logger.error("No .bc files produced")
            return None

        # 合并为单一 bc
        merged = self._link_all()
        return merged

    def _load_compile_commands(self) -> List[dict]:
        """加载并过滤 compile_commands.json。"""
        try:
            with open(self.compile_commands_path, "r", encoding="utf-8") as f:
                commands = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load compile_commands.json: %s", e)
            return []

        # 只保留 C/C++ 源文件
        c_exts = {".c", ".cc", ".cpp", ".cxx"}
        filtered = []
        for cmd in commands:
            src = cmd.get("file", "")
            if Path(src).suffix.lower() in c_exts:
                filtered.append(cmd)
        return filtered

    def _compile_tu(self, cmd: dict, idx: int) -> None:
        """用 gclang 编译单个 TU，提取 .bc。"""
        src_file = cmd.get("file", "")
        directory = cmd.get("directory", str(self.source_root))
        arguments = cmd.get("arguments", [])
        command_str = cmd.get("command", "")

        if arguments:
            args = list(arguments)
        elif command_str:
            args = command_str.split()
        else:
            return

        # 替换编译器为 gclang，注入调试标志
        if args:
            args[0] = self.gclang
        args = self._inject_flags(args)

        # 输出 .o 到 output_dir
        obj_name = f"tu_{idx}_{Path(src_file).stem}.o"
        obj_path = self.output_dir / obj_name
        args = self._replace_output(args, str(obj_path))

        try:
            subprocess.run(
                args,
                cwd=directory,
                timeout=self.timeout // max(1, len(self._bc_files) + 1),
                capture_output=True,
                check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.debug("Compile failed for %s: %s", src_file, e)
            return

        # get-bc 提取 .bc
        bc_path = obj_path.with_suffix(".o.bc")
        try:
            subprocess.run(
                [self.get_bc, str(obj_path)],
                cwd=str(self.output_dir),
                timeout=60,
                capture_output=True,
                check=True,
            )
            if bc_path.exists():
                self._bc_files.append(bc_path)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.debug("get-bc failed for %s: %s", obj_path, e)

    def _link_all(self) -> Optional[Path]:
        """llvm-link 合并所有 .bc 为单一文件。"""
        merged_path = self.output_dir / "merged.bc"
        cmd = [self.llvm_link, "-o", str(merged_path)] + [str(p) for p in self._bc_files]

        try:
            subprocess.run(
                cmd, timeout=self.timeout, capture_output=True, check=True,
            )
            logger.info("Merged %d .bc files → %s", len(self._bc_files), merged_path)
            return merged_path
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logger.error("llvm-link failed: %s", e)
            return None

    @staticmethod
    def _inject_flags(args: List[str]) -> List[str]:
        """注入 -g -O0，移除优化标志。"""
        filtered = []
        for a in args:
            if a.startswith("-O") and a != "-O0":
                continue
            filtered.append(a)
        if "-g" not in filtered:
            filtered.insert(1, "-g")
        if "-O0" not in filtered:
            filtered.insert(1, "-O0")
        return filtered

    @staticmethod
    def _replace_output(args: List[str], new_output: str) -> List[str]:
        """替换 -o 参数为新输出路径。"""
        result = []
        skip_next = False
        found_o = False
        for i, a in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if a == "-o" and i + 1 < len(args):
                result.extend(["-o", new_output])
                skip_next = True
                found_o = True
            else:
                result.append(a)
        if not found_o:
            result.extend(["-o", new_output])
        # 确保是编译模式（-c）
        if "-c" not in result:
            result.insert(1, "-c")
        return result
