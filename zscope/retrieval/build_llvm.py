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
import hashlib
import shlex
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .bitcode_scope import BitcodeScopeConfig, EntryBitcodeSelector

logger = logging.getLogger(__name__)


class BitcodeBuilder:
    """从 compile_commands.json 构建全程序 LLVM bitcode。"""

    # compile_commands.json 中需要跳过的 -D 宏（通常含未展开的 Make 函数）
    _SKIP_DEFINE_NAMES = {
        "__FILENAME__",
        "__VOSFILENAME__",
    }
    _MANIFEST_VERSION = 1
    _LINK_MANIFEST_VERSION = 1

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
        # 在 WSL 中，/mnt/ 路径上的 NTFS 文件系统与 gclang 的 objcopy 不兼容
        # 自动重定向到 Linux 原生临时目录
        default_out = self.source_root / ".zscope_bc"
        if output_dir is None and str(self.source_root).startswith("/mnt/"):
            import tempfile
            default_out = Path(tempfile.mkdtemp(prefix="zscope_bc_"))
            logger.info("WSL detected: using native temp dir for bitcode: %s", default_out)
        self.output_dir = Path(output_dir or default_out).resolve()
        self.gclang = gclang_path
        self.get_bc = get_bc_path
        self.llvm_link = llvm_link_path
        self.timeout = timeout
        # Map of generated .bc Path -> original c_src_path
        self._bc_to_src: Dict[Path, Path] = {}
        self._bc_compile_index: Dict[Path, int] = {}
        self._env = self._make_gllvm_env()
        self._manifest_path = self.output_dir / "bitcode_manifest.json"
        self._manifest: Dict[str, Any] = {}
        self._manifest_dirty = False
        self._state_lock = threading.Lock()
        self.reused_linked_groups: set[str] = set()
        self.failed_tus: List[Dict[str, str]] = []

    @staticmethod
    def _make_gllvm_env() -> dict:
        """构建 gllvm 所需的环境变量（LLVM_COMPILER, LLVM_CC_NAME）。"""
        env = os.environ.copy()
        # 确保关键系统路径在 PATH 中（WSL 最小 shell 可能缺失）
        path = env.get("PATH", "")
        for d in ["/usr/bin", "/usr/local/bin", "/usr/sbin"]:
            if d not in path:
                path = d + ":" + path
        env["PATH"] = path
        # gllvm 需要 LLVM_COMPILER 指明编译器家族
        if "LLVM_COMPILER" not in env:
            env["LLVM_COMPILER"] = "clang"
        # 自动检测带版本号的 clang（如 clang-18）
        if "LLVM_CC_NAME" not in env:
            for v in range(20, 14, -1):
                if shutil.which(f"clang-{v}"):
                    env["LLVM_CC_NAME"] = f"clang-{v}"
                    env["LLVM_CXX_NAME"] = f"clang++-{v}"
                    logger.info("Auto-detected clang: clang-%d", v)
                    break
        return env

    def build(
        self,
        groups: Optional[Dict[str, List[str]]] = None,
        *,
        scope_config: Optional[BitcodeScopeConfig] = None,
        entry_functions: Optional[Sequence[Any]] = None,
        knowledge_db: Optional[Any] = None,
        project_root: Optional[Path] = None,
    ) -> Dict[str, Path]:
        """执行完整构建流程，返回各分组合并后的 .bc 路径字典。
        
        groups: 可选的分组配置，格式 {"group_name": ["exclude_file1.c", ...]}
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._manifest = self._load_manifest()
        self._manifest_dirty = False
        self._bc_to_src.clear()
        self._bc_compile_index.clear()
        self.reused_linked_groups.clear()
        self.failed_tus.clear()

        commands = self._load_compile_commands()
        if not commands:
            logger.error("No compile commands loaded")
            return {}

        logger.info("Building bitcode for %d translation units", len(commands))

        # 逐 TU 编译
        workers = self._build_worker_count(len(commands))
        logger.info("Building bitcode with %d gclang worker(s)", workers)
        if workers <= 1:
            for idx, cmd in enumerate(commands):
                self._compile_tu(cmd, idx)
        else:
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="zscope-gclang") as executor:
                futures = [
                    executor.submit(self._compile_tu, cmd, idx)
                    for idx, cmd in enumerate(commands)
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:
                        logger.warning("Bitcode worker failed: %s", exc)

        if not self._bc_to_src:
            logger.error("No .bc files produced")
            return {}

        # 准备分组及排除列表
        if not groups:
            groups = {"default": []}

        selector: Optional[EntryBitcodeSelector] = None
        if scope_config and scope_config.mode != "full" and entry_functions and knowledge_db:
            selector = EntryBitcodeSelector(
                db=knowledge_db,
                source_root=self.source_root,
                project_root=Path(project_root or self.source_root),
                config=scope_config,
            )

        results: Dict[str, Path] = {}
        # 为每组过滤并合并 bc 文件
        for group_name, exclude_list in groups.items():
            logger.info("Linking group '%s' (excluding %d pattern(s))", group_name, len(exclude_list))
            previous_selected_bcs = self._load_previous_scope_plan_bcs(
                group_name,
                Path(project_root or self.source_root),
            )
            
            group_bcs = []
            bc_items = sorted(
                self._bc_to_src.items(),
                key=lambda item: self._bc_compile_index.get(item[0], len(commands)),
            )
            for bc_path, src_path in bc_items:
                src_name = src_path.name
                if any(ex in src_name for ex in exclude_list):
                    continue
                group_bcs.append(bc_path)

            if not group_bcs:
                logger.warning("No .bc files left for group '%s' after exclusions", group_name)
                continue

            if selector:
                selected_bcs, plan = selector.select(
                    group_name=group_name,
                    candidate_bcs=group_bcs,
                    bc_to_src=self._bc_to_src,
                    entries=entry_functions or [],
                )
                selector.write_plan(plan, self.output_dir)
                logger.info(
                    "SVF bitcode scope for group '%s': %d/%d .bc selected%s",
                    group_name,
                    len(selected_bcs),
                    len(group_bcs),
                    f" (fallback={plan.fallback_reason})" if plan.fallback_reason else "",
                )
                group_bcs = selected_bcs

            if not group_bcs:
                logger.warning("No .bc files selected for group '%s'", group_name)
                continue

            merged = self._link_all(
                group_bcs,
                group_name,
                previous_selected_bcs=previous_selected_bcs,
            )
            if merged:
                results[group_name] = merged

        self._save_manifest()
        return results

    def _load_manifest(self) -> Dict[str, Any]:
        if not self._manifest_path.exists():
            return {"version": self._MANIFEST_VERSION, "bitcode": {}}
        try:
            with open(self._manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Ignoring unreadable bitcode manifest %s: %s", self._manifest_path, exc)
            return {"version": self._MANIFEST_VERSION, "bitcode": {}}
        if not isinstance(data, dict) or data.get("version") != self._MANIFEST_VERSION:
            return {"version": self._MANIFEST_VERSION, "bitcode": {}}
        bitcode = data.get("bitcode", {})
        if not isinstance(bitcode, dict):
            bitcode = {}
        linked = data.get("linked", {})
        if not isinstance(linked, dict):
            linked = {}
        return {
            "version": self._MANIFEST_VERSION,
            "bitcode": bitcode,
            "linked": linked,
        }

    def _save_manifest(self) -> None:
        if not self._manifest_dirty:
            return
        try:
            self._manifest_path.write_text(
                json.dumps(self._manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            logger.debug("Failed to write bitcode manifest %s: %s", self._manifest_path, exc)

    def _linked_group_fingerprint(self, bc_files: Sequence[Path]) -> str:
        payload = {
            "version": self._LINK_MANIFEST_VERSION,
            "llvm_link": self.llvm_link,
            "inputs": [
                {
                    "path": str(Path(path).resolve()),
                    "hash": self._file_hash(path),
                }
                for path in bc_files
            ],
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def _reuse_linked_bitcode_if_current(
        self,
        merged_path: Path,
        group_name: str,
        fingerprint: str,
        bc_files: Sequence[Path],
        previous_selected_bcs: Optional[set[str]] = None,
    ) -> bool:
        resolved_merged = merged_path.resolve()
        with self._state_lock:
            entry = dict(self._manifest.get("linked", {}).get(group_name, {}))
        if (
            entry.get("fingerprint") == fingerprint
            and resolved_merged.exists()
            and entry.get("bitcode_hash") == self._file_hash(resolved_merged)
        ):
            self.reused_linked_groups.add(group_name)
            logger.info("Reusing unchanged merged bitcode %s", resolved_merged)
            return True

        current_bcs = {str(Path(path).resolve()) for path in bc_files}
        previous_bcs = previous_selected_bcs or set()
        if not previous_bcs or previous_bcs != current_bcs or not resolved_merged.exists():
            return False
        try:
            merged_mtime = resolved_merged.stat().st_mtime
            newest_input_mtime = max(Path(path).resolve().stat().st_mtime for path in bc_files)
        except OSError:
            return False
        if merged_mtime < newest_input_mtime:
            return False
        self._record_linked_bitcode_manifest(resolved_merged, group_name, fingerprint)
        self.reused_linked_groups.add(group_name)
        logger.info(
            "Reusing existing merged bitcode %s from unchanged scope plan",
            resolved_merged,
        )
        return True

    def _record_linked_bitcode_manifest(
        self,
        merged_path: Path,
        group_name: str,
        fingerprint: str,
    ) -> None:
        resolved_merged = merged_path.resolve()
        with self._state_lock:
            linked = self._manifest.setdefault("linked", {})
            linked[group_name] = {
                "fingerprint": fingerprint,
                "bitcode_hash": self._file_hash(resolved_merged),
                "path": str(resolved_merged),
            }
            self._manifest_dirty = True

    def _load_previous_scope_plan_bcs(self, group_name: str, base_dir: Path) -> set[str]:
        plan_path = self.output_dir / f"bitcode_scope_{group_name}.json"
        if not plan_path.exists():
            return set()
        try:
            with open(plan_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError, TypeError):
            return set()
        selected = data.get("selected_bcs") if isinstance(data, dict) else None
        if not isinstance(selected, list):
            return set()
        paths: set[str] = set()
        for raw in selected:
            if not raw:
                continue
            path = Path(str(raw))
            if not path.is_absolute():
                path = Path(base_dir).resolve() / path
            paths.add(str(path.resolve()))
        return paths

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
            args = self._split_command(command_str)
        else:
            self._record_tu_failure(src_file, "missing_compile_command")
            return

        # 替换编译器为 gclang，注入调试标志
        if args:
            args[0] = self.gclang
        args = self._inject_flags(args)
        args = self._sanitize_args(args, src_file)
        resolved_src = self._resolve_source_file(src_file, directory)
        command_fingerprint = self._tu_fingerprint(
            src_file=src_file,
            resolved_src=resolved_src,
            directory=directory,
            args=args,
        )

        # 输出 .o 到 output_dir
        obj_name = f"tu_{idx}_{Path(src_file).stem}.o"
        obj_path = self.output_dir / obj_name
        args = self._replace_output(args, str(obj_path))
        bc_path = Path(str(obj_path) + ".bc")

        if self._reuse_bitcode_if_current(bc_path, resolved_src, command_fingerprint, idx):
            return

        try:
            logger.info("gclang cmd: %s (cwd=%s)", " ".join(args), directory)
            proc = subprocess.run(
                args,
                cwd=directory,
                env=self._env,
                timeout=self.timeout,
                capture_output=True,
                text=True,
                check=True,
            )
            if proc.stderr:
                logger.debug("gclang stderr: %s", proc.stderr[:300])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            stderr = getattr(e, 'stderr', '') or ''
            logger.warning("Compile failed for %s: %s stderr=%s", src_file, e, stderr[:300])
            self._record_tu_failure(src_file, "compile_failed")
            return

        if not obj_path.exists():
            logger.warning("gclang succeeded but %s not found", obj_path)
            self._record_tu_failure(src_file, "object_missing")
            return
        logger.info("Compiled %s -> %s (%d bytes)", src_file, obj_path, obj_path.stat().st_size)

        # get-bc 提取 .bc（get-bc 在原文件名后追加 .bc）
        try:
            proc2 = subprocess.run(
                [self.get_bc, str(obj_path)],
                cwd=str(self.output_dir),
                env=self._env,
                timeout=60,
                capture_output=True,
                text=True,
                check=True,
            )
            if bc_path.exists():
                resolved_bc = bc_path.resolve()
                with self._state_lock:
                    self._bc_to_src[resolved_bc] = resolved_src
                    self._bc_compile_index[resolved_bc] = idx
                self._record_bitcode_manifest(resolved_bc, resolved_src, command_fingerprint)
                logger.info("Extracted %s (%d bytes)", bc_path, bc_path.stat().st_size)
            else:
                logger.warning("get-bc succeeded but %s not found", bc_path)
                self._record_tu_failure(src_file, "bitcode_missing")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            stderr = getattr(e, 'stderr', '') or ''
            logger.warning("get-bc failed for %s: %s stderr=%s", obj_path, e, stderr[:300])
            self._record_tu_failure(src_file, "get_bc_failed")

    def _record_tu_failure(self, src_file: str, reason: str) -> None:
        with self._state_lock:
            self.failed_tus.append({
                "file": str(src_file),
                "reason": reason,
            })

    def _reuse_bitcode_if_current(
        self,
        bc_path: Path,
        src_path: Path,
        fingerprint: str,
        idx: int,
    ) -> bool:
        resolved_bc = bc_path.resolve()
        with self._state_lock:
            entry = dict(self._manifest.get("bitcode", {}).get(str(resolved_bc), {}))
        if (
            entry.get("fingerprint") != fingerprint
            or not resolved_bc.exists()
            or entry.get("bitcode_hash") != self._file_hash(resolved_bc)
        ):
            return False
        with self._state_lock:
            self._bc_to_src[resolved_bc] = src_path
            self._bc_compile_index[resolved_bc] = idx
        logger.info("Reusing unchanged bitcode %s", resolved_bc)
        return True

    def _record_bitcode_manifest(self, bc_path: Path, src_path: Path, fingerprint: str) -> None:
        bitcode_hash = self._file_hash(bc_path)
        with self._state_lock:
            bitcode = self._manifest.setdefault("bitcode", {})
            bitcode[str(bc_path)] = {
                "fingerprint": fingerprint,
                "bitcode_hash": bitcode_hash,
                "source": str(src_path),
            }
            self._manifest_dirty = True

    def _tu_fingerprint(
        self,
        *,
        src_file: str,
        resolved_src: Path,
        directory: str,
        args: Sequence[str],
    ) -> str:
        payload = {
            "builder_version": self._MANIFEST_VERSION,
            "source": str(resolved_src),
            "source_hash": self._file_hash(resolved_src),
            "directory": str(Path(directory).resolve()),
            "args": list(args),
            "gclang": self.gclang,
            "get_bc": self.get_bc,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _build_worker_count(command_count: int) -> int:
        if command_count <= 0:
            return 1
        cpu_count = os.cpu_count() or 4
        return max(1, min(command_count, cpu_count, 8))

    def _link_all(
        self,
        bc_files: List[Path],
        group_name: str,
        *,
        previous_selected_bcs: Optional[set[str]] = None,
    ) -> Optional[Path]:
        """llvm-link 合并所有给定的 .bc 为单一文件（支持分批以避免参数过长）。"""
        merged_path = self.output_dir / f"merged_{group_name}.bc"
        if not bc_files:
            return None
        link_fingerprint = self._linked_group_fingerprint(bc_files)
        if self._reuse_linked_bitcode_if_current(
            merged_path,
            group_name,
            link_fingerprint,
            bc_files,
            previous_selected_bcs,
        ):
            return merged_path
        # 尝试一次性链接
        try:
            cmd = [self.llvm_link, "-o", str(merged_path)] + [str(p) for p in bc_files]
            proc = subprocess.run(
                cmd, timeout=self.timeout, capture_output=True, text=True, check=True,
            )
            logger.info("Merged %d .bc files → %s", len(bc_files), merged_path)
            self._record_linked_bitcode_manifest(merged_path, group_name, link_fingerprint)
            return merged_path
        except subprocess.CalledProcessError as e:
            # 命令太长或链接冲突
            stderr = e.stderr or ""
            if "Argument list too long" in str(e) or "Argument list too long" in stderr or e.returncode == 7: # 7 on windows
                logger.warning("llvm-link args too long, falling back to chunked linking...")
                return self._link_in_chunks(
                    bc_files,
                    merged_path,
                    group_name,
                    link_fingerprint,
                )
            
            # 其他链接错误（可能存在多重定义或 IR 版本不兼容）
            logger.error("llvm-link failed (exit code %d).", e.returncode)
            logger.error("llvm-link stderr (first 1000 chars):\n%s", stderr[:1000])
            return None
        except Exception as e:
            logger.error("llvm-link unexpected error: %s", e)
            return None

    def _link_in_chunks(
        self,
        bc_files: List[Path],
        final_output: Path,
        group_name: str,
        link_fingerprint: Optional[str] = None,
    ) -> Optional[Path]:
        """分批合并 bitcode 文件。"""
        chunk_size = 500
        intermediate_bcs = []
        for i in range(0, len(bc_files), chunk_size):
            chunk = bc_files[i:i + chunk_size]
            chunk_output = self.output_dir / f"chunk_{group_name}_{i//chunk_size}.bc"
            cmd = [self.llvm_link, "-o", str(chunk_output)] + [str(p) for p in chunk]
            try:
                subprocess.run(
                    cmd, timeout=self.timeout, capture_output=True, text=True, check=True
                )
                intermediate_bcs.append(chunk_output)
            except subprocess.CalledProcessError as e:
                logger.error("Chunk linking failed: %s\n%s", e, (e.stderr or "")[:1000])
                return None
        
        # 链接所有 chunk
        try:
            cmd = [self.llvm_link, "-o", str(final_output)] + [str(p) for p in intermediate_bcs]
            subprocess.run(
                cmd, timeout=self.timeout, capture_output=True, text=True, check=True
            )
            logger.info("Successfully merged via chunks → %s", final_output)
            self._record_linked_bitcode_manifest(
                final_output,
                group_name,
                link_fingerprint or self._linked_group_fingerprint(bc_files),
            )
            return final_output
        except subprocess.CalledProcessError as e:
            logger.error("Final chunk linking failed: %s\n%s", e, (e.stderr or "")[:1000])
            return None

    @staticmethod
    def _inject_flags(args: List[str]) -> List[str]:
        """注入 bitcode 构建所需的兼容标志，移除优化标志。"""
        filtered = []
        for a in args:
            if a.startswith("-O") and a != "-O0":
                continue
            filtered.append(a)
        injected = [
            "-Wno-implicit-function-declaration",
            "-include",
            "stddef.h",
        ]
        for flag in reversed(injected):
            if flag not in filtered:
                filtered.insert(1, flag)
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

    @staticmethod
    def _split_command(command_str: str) -> List[str]:
        """Split a compile_commands.json command using shell quoting rules."""
        try:
            return shlex.split(command_str)
        except ValueError as e:
            logger.debug(
                "Failed to parse compile command with shlex, falling back to split(): %s", e
            )
            return command_str.split()

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    digest.update(chunk)
        except OSError:
            digest.update(b"__missing__")
        return digest.hexdigest()

    @staticmethod
    def _resolve_source_file(src_file: str, directory: str) -> Path:
        path = Path(src_file)
        if not path.is_absolute():
            path = Path(directory) / path
        return path.resolve()

    @classmethod
    def _skipped_define_name(cls, arg: str) -> Optional[str]:
        if not arg.startswith("-D"):
            return None
        name = arg[2:].split("=", 1)[0]
        return name if name in cls._SKIP_DEFINE_NAMES else None

    @classmethod
    def _skipped_define_value_name(cls, arg: str) -> Optional[str]:
        name = arg.split("=", 1)[0]
        return name if name in cls._SKIP_DEFINE_NAMES else None

    @staticmethod
    def _make_filename_define(name: str, src_file: str) -> str:
        filename = Path(src_file).name or "unknown"
        filename = filename.replace("\\", "\\\\").replace('"', '\\"')
        return f'-D{name}="{filename}"'

    @classmethod
    def _sanitize_args(cls, args: List[str], src_file: str = "") -> List[str]:
        """过滤 compile_commands.json 中无法被 clang 处理的参数。

        处理两类问题：
        1. 将坏的文件名 -D 宏（_SKIP_DEFINE_NAMES 中定义）改写为安全文件名
        2. 含未展开 Make 函数的参数（检测 '$(' 语法）
        """
        cleaned = []
        dropped = []
        rewritten = []
        skip_next = False
        for idx, arg in enumerate(args):
            if skip_next:
                dropped.append(arg)
                skip_next = False
                continue
            # 将未展开 Make 语法的文件名宏替换为当前源文件 basename，避免源码引用宏时报未声明。
            define_name = cls._skipped_define_name(arg)
            if define_name:
                replacement = cls._make_filename_define(define_name, src_file)
                cleaned.append(replacement)
                rewritten.append((arg, replacement))
                dropped.append(arg)
                continue
            split_define_name = (
                cls._skipped_define_value_name(args[idx + 1])
                if arg == "-D" and idx + 1 < len(args)
                else None
            )
            if split_define_name:
                replacement = cls._make_filename_define(split_define_name, src_file)
                cleaned.append(replacement)
                rewritten.append((f"{arg} {args[idx + 1]}", replacement))
                dropped.append(arg)
                skip_next = True
                continue
            # 检测未展开的 Make 函数 $(...) 或 ${...}
            if "$(" in arg or "${" in arg:
                dropped.append(arg)
                continue
            # 跳过 Make 展开残留碎片（不以 - 开头、不是源文件、含 % 或 )" 等特征）
            if (not arg.startswith("-") and arg != args[0]
                    and ("%" in arg or arg.endswith(")\"'") or arg.endswith("))'"))):
                dropped.append(arg)
                continue
            cleaned.append(arg)
        if dropped:
            logger.debug(
                "Sanitized %d broken args for %s: %s",
                len(dropped), Path(src_file).name, dropped,
            )
        if rewritten:
            logger.debug(
                "Rewrote %d filename define(s) for %s: %s",
                len(rewritten), Path(src_file).name, rewritten,
            )
        return cleaned
