"""
Clang extractor - LSP-based batch code structure extractor.
Adapted from historical lsp_client.py, repurposed for batch extraction into SQLite.
"""

import json
import logging
import os
import subprocess
import threading
import time
import re
import hashlib
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from ..common.utils import is_likely_function_call_identifier
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
HEADER_LIKE_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".ph", ".inc", ".inl"}
MACRO_DEFINE_RE = re.compile(
    r"^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)(?P<tail>.*)$"
)


class ClangExtractor:
    """
    基于 clangd LSP 的批处理代码结构提取器。
    复用历史 LSP 通信层，改造为批量提取模式。
    """

    def __init__(
        self,
        project_root: Path,
        clangd_path: str = "clangd",
        compile_commands_dir: Optional[Path] = None,
        max_threads: int = 8,
    ):
        self.project_root = Path(project_root).resolve()
        self.clangd_path = clangd_path
        self.compile_commands_dir = compile_commands_dir
        self.max_threads = max_threads

        self.process: Optional[subprocess.Popen] = None
        self._id_counter = 0
        self._responses: Dict[int, Any] = {}
        self._lock = threading.Lock()
        self._io_lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._running = False
        self._initialized = False
        self._call_hierarchy_supported = False
        self._last_progress_time = time.time()
        self._opened_documents: Dict[str, int] = {}
        self._source_text_cache: OrderedDict[Tuple[str, int, int], str] = OrderedDict()
        self._source_text_cache_lock = threading.RLock()
        self._source_text_cache_limit = 32

    # ── 生命周期 ──

    def start(self) -> bool:
        """启动 clangd 子进程并完成 LSP 握手。"""
        if self.process:
            return True
        try:
            cmd = [
                self.clangd_path,
                "-log=error",
                "--header-insertion=never",
                "--background-index",
                "--pch-storage=memory",
                f"-j={self.max_threads}",
            ]
            if self.compile_commands_dir:
                cmd.append(f"--compile-commands-dir={self.compile_commands_dir}")

            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.project_root),
                bufsize=0,
            )
            self._running = True

            self._reader_thread = threading.Thread(
                target=self._read_loop, name="ClangReader", daemon=True
            )
            self._reader_thread.start()

            self._stderr_thread = threading.Thread(
                target=self._stderr_loop, name="ClangStderr", daemon=True
            )
            self._stderr_thread.start()

            time.sleep(0.5)
            if self.process.poll() is not None:
                logger.error("clangd process exited immediately")
                return False

            # LSP initialize 握手
            init_result = self.send_request(
                "initialize",
                {
                    "processId": os.getpid(),
                    "rootUri": self.project_root.as_uri(),
                    "capabilities": {
                        "window": {"workDoneProgress": True},
                        "textDocument": {
                            "documentSymbol": {"hierarchicalDocumentSymbolSupport": True},
                            "callHierarchy": {"dynamicRegistration": False},
                            "definition": {},
                            "references": {},
                            "hover": {},
                            "typeDefinition": {},
                        },
                        "workspace": {"symbol": {"dynamicRegistration": False}},
                    },
                    "initializationOptions": {
                        "clangdFileStatus": True,
                        "backgroundIndex": True,
                    },
                },
            )
            if init_result is None:
                logger.error("LSP initialize failed")
                self.stop()
                return False

            capabilities = (
                init_result.get("capabilities", {}) if isinstance(init_result, dict) else {}
            )
            self._call_hierarchy_supported = bool(capabilities.get("callHierarchyProvider"))

            self.send_notification("initialized", {})
            self._initialized = True
            logger.info("clangd LSP initialized successfully")
            return True
        except Exception as e:
            logger.error("Failed to start clangd: %s", e)
            self.stop()
            return False

    def stop(self):
        """关闭 clangd 进程。"""
        self._running = False
        if self.process:
            try:
                self.send_notification("exit", None)
            except Exception:
                pass
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        self._initialized = False
        self._opened_documents.clear()

    # ── JSON-RPC 通信 ──

    def send_request(self, method: str, params: Any, timeout: int = 120) -> Any:
        """发送 JSON-RPC 请求并阻塞等待响应。"""
        with self._lock:
            self._id_counter += 1
            msg_id = self._id_counter

        msg = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
        self._write_message(msg)

        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if msg_id in self._responses:
                    resp = self._responses.pop(msg_id)
                    if "error" in resp:
                        logger.debug("LSP error for %s: %s", method, resp["error"])
                        return None
                    return resp.get("result")
            # 如果索引仍在进行，延长 deadline
            if time.time() - self._last_progress_time < 2.0:
                deadline = max(deadline, time.time() + 30)
            time.sleep(0.05)
        logger.warning("LSP request '%s' timed out (id=%d)", method, msg_id)
        return None

    def send_notification(self, method: str, params: Any):
        """发送 JSON-RPC 通知（无响应）。"""
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._write_message(msg)

    def _write_message(self, msg: dict):
        """写入 LSP 消息到 stdin。"""
        body = json.dumps(msg)
        header = f"Content-Length: {len(body)}\r\n\r\n"
        with self._io_lock:
            if self.process and self.process.stdin:
                try:
                    self.process.stdin.write(header.encode("utf-8"))
                    self.process.stdin.write(body.encode("utf-8"))
                    self.process.stdin.flush()
                except (BrokenPipeError, OSError):
                    logger.error("Failed to write to clangd stdin")

    # ── 消息读取 ──

    def _read_loop(self):
        """后台线程：从 stdout 读取 JSON-RPC 消息。"""
        buf = b""
        if not self.process or not self.process.stdout:
            return
        fd = self.process.stdout.fileno()
        while self._running:
            try:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                while buf:
                    # 解析 Content-Length 头
                    header_end = buf.find(b"\r\n\r\n")
                    if header_end == -1:
                        break
                    header = buf[:header_end].decode("utf-8", errors="ignore")
                    match = re.search(r"Content-Length:\s*(\d+)", header)
                    if not match:
                        buf = buf[header_end + 4 :]
                        continue
                    content_len = int(match.group(1))
                    body_start = header_end + 4
                    if len(buf) < body_start + content_len:
                        break  # 等待更多数据
                    body = buf[body_start : body_start + content_len]
                    buf = buf[body_start + content_len :]
                    try:
                        msg = json.loads(body)
                        self._dispatch_message(msg)
                    except json.JSONDecodeError:
                        logger.debug("Failed to parse LSP message")
            except OSError:
                break

    def _dispatch_message(self, msg: dict):
        """分发收到的 LSP 消息。"""
        if "id" in msg:
            with self._lock:
                self._responses[msg["id"]] = msg
        elif msg.get("method") == "$/progress":
            self._last_progress_time = time.time()

    def _stderr_loop(self):
        """后台线程：读取 clangd stderr 日志。"""
        while self._running and self.process and self.process.stderr:
            try:
                line = self.process.stderr.readline()
                if not line:
                    break
                text = ANSI_ESCAPE.sub("", line.decode("utf-8", errors="ignore")).strip()
                if text and "Indexing" in text:
                    self._last_progress_time = time.time()
                    logger.debug("clangd: %s", text)
            except OSError:
                break

    # ── 文档管理 ──

    def open_document(self, file_path: Path) -> bool:
        uri = file_path.as_uri()
        if uri in self._opened_documents:
            return True
        text = self._read_source_text(file_path)
        if text is None:
            return False
        lang = "c" if file_path.suffix in (".c", ".h") else "cpp"
        self.send_notification(
            "textDocument/didOpen",
            {"textDocument": {"uri": uri, "languageId": lang, "version": 1, "text": text}},
        )
        self._opened_documents[uri] = 1
        return True

    def close_document(self, file_path: Path):
        uri = file_path.as_uri()
        if uri not in self._opened_documents:
            return
        self.send_notification("textDocument/didClose", {"textDocument": {"uri": uri}})
        del self._opened_documents[uri]

    def notify_files_deleted(self, file_paths: List[Path]) -> None:
        changes = []
        for file_path in file_paths:
            try:
                uri = Path(file_path).resolve().as_uri()
            except ValueError:
                continue
            if uri in self._opened_documents:
                self.send_notification("textDocument/didClose", {"textDocument": {"uri": uri}})
                del self._opened_documents[uri]
            changes.append({"uri": uri, "type": 3})
        if changes:
            self.send_notification("workspace/didChangeWatchedFiles", {"changes": changes})

    # ── LSP 查询 ──

    def get_document_symbols(self, file_path: Path) -> Optional[List[Dict]]:
        uri = file_path.as_uri()
        result = self.send_request("textDocument/documentSymbol", {"textDocument": {"uri": uri}})
        return cast(Optional[List[Dict]], result)

    def get_hover(self, file_path: Path, line: int, character: int = 0) -> Optional[Dict]:
        uri = file_path.as_uri()
        result = self.send_request(
            "textDocument/hover",
            {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character},
            },
            timeout=30,
        )
        return cast(Optional[Dict], result)

    def get_definition(self, file_path: Path, line: int, character: int = 0) -> Optional[List]:
        uri = file_path.as_uri()
        result = self.send_request(
            "textDocument/definition",
            {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character},
            },
            timeout=30,
        )
        return cast(Optional[List], result)

    def prepare_call_hierarchy(
        self, file_path: Path, line: int, character: int = 0
    ) -> Optional[List[Dict[str, Any]]]:
        uri = file_path.as_uri()
        result = self.send_request(
            "textDocument/prepareCallHierarchy",
            {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": character},
            },
            timeout=30,
        )
        return cast(Optional[List[Dict[str, Any]]], result)

    def get_outgoing_calls(self, item: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        result = self.send_request("callHierarchy/outgoingCalls", {"item": item}, timeout=60)
        return cast(Optional[List[Dict[str, Any]]], result)

    def get_workspace_symbols(self, query: str = "") -> Optional[List[Dict]]:
        return cast(Optional[List[Dict]], self.send_request("workspace/symbol", {"query": query}))

    # ── 索引等待 ──

    def wait_for_indexing(self, timeout: int = 300, idle_threshold: float = 5.0) -> bool:
        """等待 clangd 后台索引完成。通过检测 progress 消息空闲来判断。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            elapsed = time.time() - self._last_progress_time
            if elapsed >= idle_threshold and self._initialized:
                logger.info("clangd indexing appears idle (%.1fs no progress)", elapsed)
                return True
            # 索引活跃时延长 deadline
            if elapsed < 2.0:
                deadline = max(deadline, time.time() + 30)
            time.sleep(0.5)
        logger.warning("wait_for_indexing timed out after %ds", timeout)
        return False

    # ── 批量提取 ──

    # LSP SymbolKind 常量
    SK_FUNCTION = 12
    SK_METHOD = 6
    SK_CONSTRUCTOR = 9
    SK_STRUCT = 23
    SK_CLASS = 5
    SK_ENUM = 10
    SK_VARIABLE = 13
    SK_CONSTANT = 14
    SK_FIELD = 8
    SK_ENUM_MEMBER = 22

    def extract_tu(
        self,
        file_path: Path,
        db: KnowledgeDB,
        tu_id: int,
        progress_cb: Optional[Callable] = None,
    ) -> bool:
        """从单个 TU 提取所有符号信息写入 KnowledgeDB。"""
        file_path = Path(file_path).resolve()
        if not self.open_document(file_path):
            logger.warning("Failed to open document: %s", file_path)
            return False

        # 等待 clangd 处理该文件（短暂等待）
        time.sleep(0.3)

        symbols = self.get_document_symbols(file_path)
        if symbols is None:
            logger.debug("No symbols returned for %s", file_path)
            self.close_document(file_path)
            return False

        rel_path = self._project_relative_path(file_path)
        func_rows: List[Tuple[Any, ...]] = []
        call_rows: List[Tuple[Any, ...]] = []
        macro_rows = self._extract_macros(file_path, rel_path)

        for sym in symbols:
            self._process_symbol(sym, file_path, rel_path, tu_id, db, func_rows, call_rows)

        # 批量写入
        if func_rows:
            db.insert_functions_batch(func_rows)
        if call_rows:
            db.insert_call_edges_batch(call_rows)
        insert_macros = getattr(db, "insert_macro_definitions_batch", None)
        if macro_rows and callable(insert_macros):
            insert_macros(macro_rows)

        # 提取 #include 边
        self._extract_includes(file_path, rel_path, db)

        db.mark_tu_indexed(tu_id)

        if progress_cb:
            progress_cb(file_path)

        self.close_document(file_path)
        return True

    def _process_symbol(
        self,
        sym: Dict,
        file_path: Path,
        rel_path: str,
        tu_id: int,
        db: KnowledgeDB,
        func_rows: List[Tuple[Any, ...]],
        call_rows: List[Tuple[Any, ...]],
        scope: Optional[List[str]] = None,
        parent_kind: int = 0,
    ):
        """递归处理单个 LSP DocumentSymbol 节点。"""
        scope = list(scope or [])
        kind = sym.get("kind", 0)
        name = sym.get("name", "")
        range_info = sym.get("range", sym.get("location", {}).get("range", {}))
        start_line = range_info.get("start", {}).get("line", 0) + 1  # LSP 0-based → 1-based
        end_line = range_info.get("end", {}).get("line", 0) + 1
        detail = sym.get("detail", "")

        if kind in (self.SK_FUNCTION, self.SK_METHOD, self.SK_CONSTRUCTOR):
            stored_name = self._qualify_cpp_symbol_name(name, scope)
            backend_signature = f"{detail} {name}" if detail else f"{name}(...)"
            signature = (
                self._source_function_signature(file_path, start_line, end_line)
                or backend_signature
            )
            static_text = f"{detail} {signature.split('(', 1)[0]}"
            is_static = bool(re.search(r"\bstatic\b", static_text))
            is_inline = "inline" in detail if detail else False
            is_decl = self._is_function_declaration_symbol(
                file_path,
                start_line,
                end_line,
                detail,
                is_static=is_static,
                is_inline=is_inline,
            )
            func_rows.append(
                (
                    stored_name,
                    rel_path,
                    start_line,
                    end_line,
                    signature,
                    int(is_static),
                    int(is_inline),
                    int(is_decl),
                    tu_id,
                )
            )
            # 通过 hover 提取调用边
            if not is_decl:
                self._extract_call_edges(
                    file_path, stored_name, rel_path, start_line, end_line, call_rows, sym
                )

        elif kind in (self.SK_STRUCT, self.SK_CLASS, self.SK_ENUM):
            full_definition = self._source_range_text(file_path, range_info)
            kind_str = self._source_type_kind(
                full_definition,
                kind,
            )
            type_id = db.insert_type(
                name,
                kind_str,
                rel_path,
                start_line,
                end_line,
                full_definition=full_definition,
                tu_id=tu_id,
            )
            # 处理子成员
            for idx, child in enumerate(sym.get("children", [])):
                child_name = child.get("name", "")
                child_detail = child.get("detail", "")
                if child_name:
                    db.insert_type_member(type_id, child_name, child_detail, idx)

        elif kind == self.SK_VARIABLE and parent_kind not in {
            self.SK_FUNCTION,
            self.SK_METHOD,
            self.SK_CONSTRUCTOR,
            self.SK_STRUCT,
            self.SK_CLASS,
            self.SK_ENUM,
        }:
            metadata = self._global_variable_metadata(
                file_path,
                name,
                start_line,
                end_line,
                detail,
            )
            insert_global = getattr(db, "insert_global_variable", None)
            if callable(insert_global):
                insert_global(name, detail, rel_path, start_line, **metadata)
            else:
                db._conn.execute(
                    "INSERT OR REPLACE INTO global_variables "
                    "(name, type_str, file_path, line, is_extern) VALUES (?, ?, ?, ?, ?)",
                    (name, detail, rel_path, start_line, int(metadata["is_extern"])),
                )

        # 递归处理子符号
        child_scope = scope
        if kind in (self.SK_STRUCT, self.SK_CLASS):
            child_scope = scope + [name]
        for child in sym.get("children", []):
            self._process_symbol(
                child,
                file_path,
                rel_path,
                tu_id,
                db,
                func_rows,
                call_rows,
                child_scope,
                kind,
            )

    def _global_variable_metadata(
        self,
        file_path: Path,
        name: str,
        start_line: int,
        end_line: int,
        detail: str,
    ) -> Dict[str, Any]:
        lines = self._read_source_lines(file_path) or []
        start_idx = max(0, int(start_line or 1) - 1)
        end_idx = min(len(lines), max(start_idx + 1, int(end_line or start_line or 1)))
        declaration = re.sub(r"\s+", " ", "".join(lines[start_idx:end_idx])).strip()
        detail_text = str(detail or "")
        combined = f"{declaration} {detail_text}"
        is_extern = bool(re.search(r"\bextern\b", combined))
        if re.search(r"\bstatic\b", combined):
            storage_class = "static"
        elif is_extern:
            storage_class = "extern"
        elif re.search(r"\b(?:_Thread_local|thread_local)\b", combined):
            storage_class = "thread_local"
        else:
            storage_class = "global"

        qualifiers = [
            qualifier
            for qualifier, pattern in (
                ("const", r"\bconst\b"),
                ("volatile", r"\bvolatile\b"),
                ("atomic", r"\b(?:_Atomic|atomic_)"),
            )
            if re.search(pattern, combined)
        ]
        initializer = ""
        assignment = re.search(r"(?<![=!<>])=(?!=)(?P<value>.*?);?\s*$", declaration)
        if assignment:
            initializer = str(assignment.group("value") or "").strip()[:500]
        definition_kind = "declaration" if is_extern and not initializer else "definition"
        return {
            "is_extern": is_extern,
            "storage_class": storage_class,
            "qualifiers": ",".join(qualifiers),
            "initializer": initializer,
            "definition_kind": definition_kind,
        }

    def _source_function_signature(
        self,
        file_path: Path,
        start_line: int,
        end_line: int,
    ) -> str:
        lines = self._read_source_lines(file_path)
        if lines is None or start_line <= 0:
            return ""

        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), max(start_idx + 1, end_line))
        head_lines: List[str] = []
        for raw in lines[start_idx:min(len(lines), end_idx + 40)]:
            line = str(raw or "").strip()
            if not line:
                continue
            before_brace = line.split("{", 1)[0].strip()
            if before_brace:
                head_lines.append(before_brace)
            if "{" in line or ";" in line:
                break

        signature = re.sub(r"\s+", " ", "\n".join(head_lines)).strip()
        if not signature or "(" not in signature:
            return ""
        if signature.endswith(";"):
            signature = signature[:-1].strip()
        return signature

    def _source_range_text(
        self,
        file_path: Path,
        range_info: Dict[str, Any],
    ) -> str:
        lines = self._read_source_lines(file_path)
        if not lines:
            return ""

        start = range_info.get("start") or {}
        end = range_info.get("end") or {}
        start_line = max(0, int(start.get("line") or 0))
        end_line = max(start_line, int(end.get("line") or start_line))
        if start_line >= len(lines):
            return ""
        end_line = min(end_line, len(lines) - 1)
        start_character = max(0, int(start.get("character") or 0))
        has_end_character = "character" in end
        end_character = max(0, int(end.get("character") or 0))

        if start_line == end_line:
            raw = lines[start_line]
            if has_end_character:
                raw = raw[start_character:end_character]
            else:
                raw = raw[start_character:]
            return raw.strip()

        parts = list(lines[start_line : end_line + 1])
        parts[0] = parts[0][start_character:]
        if has_end_character:
            parts[-1] = parts[-1][:end_character]
        return "".join(parts).strip()

    def _source_type_kind(self, definition: str, symbol_kind: int) -> str:
        masked = self._mask_c_comments_and_literals(str(definition or ""))
        header = masked.split("{", 1)[0]
        match = re.search(r"\b(struct|union|enum|class)\b", header)
        if match:
            return match.group(1)
        return {
            self.SK_STRUCT: "struct",
            self.SK_CLASS: "class",
            self.SK_ENUM: "enum",
        }.get(symbol_kind, "unknown")

    def _qualify_cpp_symbol_name(self, name: str, scope: List[str]) -> str:
        clean_name = str(name or "").strip()
        if not clean_name or "::" in clean_name or not scope:
            return clean_name
        return "::".join(scope + [clean_name])

    def _extract_includes(self, file_path: Path, rel_path: str, db: KnowledgeDB):
        """提取 #include 边。"""
        lines = self._read_source_lines(file_path)
        if lines is None:
            return
        try:
            for line_no, line in enumerate(lines, 1):
                m = re.match(r'\s*#\s*include\s+([<"])([^>"]+)[>"]', line)
                if m:
                    is_system = 1 if m.group(1) == "<" else 0
                    included = m.group(2)
                    db._conn.execute(
                        "INSERT OR IGNORE INTO include_edges "
                        "(source_file, included_file, line, is_system) VALUES (?, ?, ?, ?)",
                        (rel_path, included, line_no, is_system),
                    )
        except Exception:
            pass

    def _extract_macros(self, file_path: Path, rel_path: str) -> List[Tuple[Any, ...]]:
        rows: List[Tuple[Any, ...]] = []
        lines = self._read_source_lines(file_path)
        if lines is None:
            return rows

        idx = 0
        while idx < len(lines):
            line = lines[idx]
            match = MACRO_DEFINE_RE.match(line)
            if not match:
                idx += 1
                continue

            start_idx = idx
            body_lines = [line]
            while body_lines[-1].rstrip().endswith("\\") and idx + 1 < len(lines):
                idx += 1
                body_lines.append(lines[idx])

            rows.append(
                (
                    match.group("name"),
                    rel_path,
                    start_idx + 1,
                    "".join(body_lines),
                    int(str(match.group("tail") or "").startswith("(")),
                )
            )
            idx += 1

        return rows

    def rebuild_function_symbol_refs(self, db: KnowledgeDB) -> int:
        get_functions = getattr(db, "get_function_records", None)
        get_globals = getattr(db, "get_global_variables", None)
        get_macros = getattr(db, "get_all_macro_definitions", None)
        clear_refs = getattr(db, "clear_function_symbol_refs", None)
        insert_refs = getattr(db, "insert_function_symbol_refs_batch", None)
        if not all(
            callable(method)
            for method in (get_functions, get_globals, get_macros, clear_refs, insert_refs)
        ):
            return 0

        functions = [row for row in get_functions() if not row.get("is_declaration")]
        globals_by_name = self._records_by_name(get_globals())
        macros_by_name = self._records_by_name(get_macros())
        aggregated: Dict[Tuple[str, str, str, str, str, int], str] = {}

        functions_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for function in functions:
            functions_by_file.setdefault(str(function.get("file_path") or ""), []).append(function)

        for function_file, file_functions in sorted(functions_by_file.items()):
            source_path = self._resolve_indexed_source_path(function_file)
            lines = self._read_source_lines(source_path)
            if not lines:
                continue
            document_opened = False
            try:
                document_opened = bool(self.open_document(source_path))
            except Exception:
                document_opened = False

            try:
                for function in file_functions:
                    self._collect_function_symbol_refs(
                        function,
                        function_file,
                        source_path,
                        lines,
                        globals_by_name,
                        macros_by_name,
                        aggregated,
                    )
            finally:
                if document_opened:
                    try:
                        self.close_document(source_path)
                    except Exception:
                        pass

        rows = [(*key, access) for key, access in sorted(aggregated.items())]
        clear_refs()
        insert_refs(rows)
        db.commit()
        return len(rows)

    def _collect_function_symbol_refs(
        self,
        function: Dict[str, Any],
        function_file: str,
        source_path: Path,
        lines: List[str],
        globals_by_name: Dict[str, List[Dict[str, Any]]],
        macros_by_name: Dict[str, List[Dict[str, Any]]],
        aggregated: Dict[Tuple[str, str, str, str, str, int], str],
    ) -> None:
        start_line = max(1, int(function.get("start_line") or 1))
        end_line = min(len(lines), max(start_line, int(function.get("end_line") or start_line)))
        body_lines = lines[start_line - 1:end_line]
        local_declarations = self._local_identifier_declaration_lines(
            "".join(body_lines),
            str(function.get("signature") or ""),
            start_line,
        )
        for offset, raw_line in enumerate(body_lines):
            absolute_line = start_line + offset
            if raw_line.lstrip().startswith("#"):
                continue
            masked_line = self._mask_c_comments_and_literals(raw_line)
            for match in re.finditer(r"\b[A-Za-z_]\w*\b", masked_line):
                name = match.group(0)
                global_candidates = globals_by_name.get(name, [])
                macro_candidates = macros_by_name.get(name, [])
                if not global_candidates and not macro_candidates:
                    continue

                definitions = self._definition_locations(
                    source_path,
                    absolute_line,
                    match.start(),
                )
                local_line = local_declarations.get(name)
                is_shadowed = local_line is not None and absolute_line >= local_line
                if global_candidates and not is_shadowed and not self._is_field_access(
                    masked_line,
                    match.start(),
                ):
                    global_record = self._resolve_symbol_candidate(
                        global_candidates,
                        function_file,
                        definitions,
                    )
                    if global_record is not None:
                        symbol_file = str(global_record.get("file_path") or "")
                        key = (
                            str(function.get("name") or ""),
                            function_file,
                            name,
                            "global",
                            symbol_file,
                            absolute_line,
                        )
                        aggregated[key] = self._merge_access_kind(
                            aggregated.get(key, "unknown"),
                            self._global_access_kind(masked_line, match.start(), match.end()),
                        )

                if macro_candidates:
                    macro_record = self._resolve_symbol_candidate(
                        macro_candidates,
                        function_file,
                        definitions,
                    )
                    if macro_record is None:
                        continue
                    if bool(macro_record.get("is_function_like")) and not re.match(
                        r"\s*\(", masked_line[match.end():]
                    ):
                        continue
                    symbol_file = str(macro_record.get("file_path") or "")
                    key = (
                        str(function.get("name") or ""),
                        function_file,
                        name,
                        "macro",
                        symbol_file,
                        absolute_line,
                    )
                    aggregated[key] = "unknown"

    @staticmethod
    def _records_by_name(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        result: Dict[str, List[Dict[str, Any]]] = {}
        for record in records:
            name = str(record.get("name") or "")
            if name:
                result.setdefault(name, []).append(dict(record))
        for rows in result.values():
            rows.sort(key=lambda row: (str(row.get("file_path") or ""), int(row.get("line") or 0)))
        return result

    def _resolve_indexed_source_path(self, file_path: str) -> Path:
        path = Path(str(file_path or ""))
        if not path.is_absolute():
            path = self.project_root / path
        return path.resolve()

    def _definition_locations(
        self,
        file_path: Path,
        line: int,
        character: int,
    ) -> List[Tuple[str, int]]:
        try:
            definitions = self.get_definition(file_path, max(0, line - 1), max(0, character))
        except Exception:
            return []
        locations: List[Tuple[str, int]] = []
        for definition in definitions or []:
            if not isinstance(definition, dict):
                continue
            uri = definition.get("targetUri") or definition.get("uri") or ""
            target_file = self._uri_to_project_path(str(uri))
            range_info = (
                definition.get("targetSelectionRange")
                or definition.get("targetRange")
                or definition.get("range")
                or {}
            )
            start = range_info.get("start", {}) if isinstance(range_info, dict) else {}
            target_line = int(start.get("line") or 0) + 1
            if target_file:
                locations.append((target_file, target_line))
        return locations

    def _resolve_symbol_candidate(
        self,
        candidates: List[Dict[str, Any]],
        function_file: str,
        definitions: List[Tuple[str, int]],
    ) -> Optional[Dict[str, Any]]:
        if definitions:
            for target_file, target_line in definitions:
                for candidate in candidates:
                    candidate_file = str(candidate.get("file_path") or "")
                    candidate_line = int(candidate.get("line") or 0)
                    if self._paths_match(target_file, candidate_file) and (
                        target_line <= 0 or candidate_line <= 0 or target_line == candidate_line
                    ):
                        return candidate
            return None

        ranked = sorted(
            candidates,
            key=lambda candidate: (
                0 if self._paths_match(function_file, str(candidate.get("file_path") or "")) else 1,
                0 if str(candidate.get("definition_kind") or "") == "definition" else 1,
                int(bool(candidate.get("is_extern"))),
                str(candidate.get("file_path") or ""),
                int(candidate.get("line") or 0),
            ),
        )
        return ranked[0] if ranked else None

    @staticmethod
    def _paths_match(left: str, right: str) -> bool:
        left_value = str(left or "").replace("\\", "/").lstrip("./")
        right_value = str(right or "").replace("\\", "/").lstrip("./")
        if not left_value or not right_value:
            return False
        return (
            left_value == right_value
            or left_value.endswith("/" + right_value)
            or right_value.endswith("/" + left_value)
        )

    @staticmethod
    def _is_field_access(line: str, start: int) -> bool:
        prefix = line[:start].rstrip()
        return prefix.endswith(".") or prefix.endswith("->")

    @staticmethod
    def _local_identifier_declaration_lines(
        body: str,
        signature: str,
        start_line: int,
    ) -> Dict[str, int]:
        names: Dict[str, int] = {}
        signature_text = str(signature or "")
        if "(" in signature_text and ")" in signature_text:
            params = signature_text[signature_text.find("(") + 1:signature_text.rfind(")")]
            for parameter in params.split(","):
                identifiers = re.findall(r"\b[A-Za-z_]\w*\b", parameter)
                if identifiers and identifiers[-1] not in {"void", "const", "volatile"}:
                    names[identifiers[-1]] = start_line

        declaration_pattern = re.compile(
            r"(?:^|[;{}])\s*(?:const\s+|volatile\s+|static\s+|register\s+|auto\s+|"
            r"signed\s+|unsigned\s+|short\s+|long\s+|_Atomic\s+)*"
            r"(?:void|char|int|float|double|size_t|ssize_t|bool|_Bool|"
            r"struct\s+[A-Za-z_]\w*|union\s+[A-Za-z_]\w*|enum\s+[A-Za-z_]\w*)"
            r"(?:\s+|\s*\*+\s*)(?P<name>[A-Za-z_]\w*)\s*(?=[=;,\[])"
        )
        for match in declaration_pattern.finditer(body):
            declaration_line = start_line + body[:match.start("name")].count("\n")
            name = match.group("name")
            names[name] = min(names.get(name, declaration_line), declaration_line)
        return names

    @staticmethod
    def _global_access_kind(line: str, start: int, end: int) -> str:
        prefix = line[:start].rstrip()
        suffix = line[end:]
        if prefix.endswith("++") or prefix.endswith("--"):
            return "read_write"
        operation = re.match(
            r"\s*(?:\[[^\]]*\]|\.\s*[A-Za-z_]\w*|->\s*[A-Za-z_]\w*)*\s*"
            r"(?P<op>\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=|=(?!=))",
            suffix,
        )
        if not operation:
            return "read"
        return "write" if operation.group("op") == "=" else "read_write"

    @staticmethod
    def _merge_access_kind(left: str, right: str) -> str:
        values = {left or "unknown", right or "unknown"}
        if "read_write" in values or {"read", "write"}.issubset(values):
            return "read_write"
        if "write" in values:
            return "write"
        if "read" in values:
            return "read"
        return "unknown"

    def run_batch_extraction(
        self,
        file_list: List[Path],
        db: KnowledgeDB,
        batch_size: int = 50,
        progress_cb: Optional[Callable] = None,
        prescanned_tus: Optional[Dict[str, Tuple[int, bool]]] = None,
    ) -> Dict[str, int]:
        """滑动窗口批量提取（增量模式：哈希未变的文件自动跳过）。"""
        stats = {"total": len(file_list), "success": 0, "failed": 0, "skipped": 0}
        prescanned_tus = prescanned_tus or {}

        for i in range(0, len(file_list), batch_size):
            batch = file_list[i : i + batch_size]
            logger.info(
                "Processing batch %d/%d (%d files)",
                i // batch_size + 1,
                (len(file_list) + batch_size - 1) // batch_size,
                len(batch),
            )

            for fp in batch:
                fp = Path(fp).resolve()
                tu_scan = prescanned_tus.get(str(fp))
                if tu_scan is None:
                    file_hash = self._compute_file_hash(fp)
                    tu_id, changed = db.register_tu_hash(str(fp), file_hash)
                else:
                    tu_id, changed = tu_scan
                if not changed:
                    stats["skipped"] += 1
                    continue
                # 文件变化 → 清除旧数据后重新提取
                db.purge_tu_data(tu_id)
                try:
                    ok = self.extract_tu(fp, db, tu_id, progress_cb)
                    if ok:
                        stats["success"] += 1
                    else:
                        stats["failed"] += 1
                except Exception as e:
                    logger.error("Failed to extract %s: %s", fp, e)
                    stats["failed"] += 1

            # 每批次提交一次
            db.commit()
            logger.info(
                "Batch committed. Progress: %d extracted, %d skipped, %d failed",
                stats["success"],
                stats["skipped"],
                stats["failed"],
            )

        ref_count = self.rebuild_function_symbol_refs(db)
        logger.info("Rebuilt %d function symbol references", ref_count)
        return stats

    def _extract_call_edges(
        self,
        file_path: Path,
        caller_name: str,
        caller_file: str,
        start_line: int,
        end_line: int,
        call_rows: List[Tuple[Any, ...]],
        sym: Optional[Dict[str, Any]] = None,
    ):
        """Extract call edges, preferring clangd's AST-backed call hierarchy."""
        hierarchy_count = self._extract_call_edges_from_call_hierarchy(
            file_path, caller_name, caller_file, start_line, call_rows, sym
        )
        if hierarchy_count is not None:
            return

        self._extract_call_edges_by_regex(
            file_path, caller_name, caller_file, start_line, end_line, call_rows
        )

    def _extract_call_edges_from_call_hierarchy(
        self,
        file_path: Path,
        caller_name: str,
        caller_file: str,
        start_line: int,
        call_rows: List[Tuple[Any, ...]],
        sym: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        if not self._call_hierarchy_supported:
            return None

        try:
            position = self._symbol_position(sym, start_line)
            items = self.prepare_call_hierarchy(file_path, position["line"], position["character"])
            if not items:
                return None

            local_rows: List[Tuple[Any, ...]] = []
            seen: set[tuple[str, str, int]] = set()
            for item in items:
                outgoing = self.get_outgoing_calls(item)
                if outgoing is None:
                    return None
                for call in outgoing:
                    target = call.get("to", {}) if isinstance(call, dict) else {}
                    callee = target.get("name", "")
                    if (
                        not is_likely_function_call_identifier(callee)
                        or callee == caller_name
                    ):
                        continue
                    callee_file = self._uri_to_project_path(target.get("uri", ""))
                    call_line = self._call_line_from_ranges(call.get("fromRanges", []), start_line)
                    key = (callee, callee_file, call_line)
                    if key in seen:
                        continue
                    seen.add(key)
                    local_rows.append(
                        (caller_name, caller_file, callee, callee_file, call_line, "direct")
                    )
            call_rows.extend(local_rows)
            return len(local_rows)
        except Exception as e:
            logger.debug("Failed to extract call hierarchy in %s: %s", caller_name, e)
            return None

    def _extract_call_edges_by_regex(
        self,
        file_path: Path,
        caller_name: str,
        caller_file: str,
        start_line: int,
        end_line: int,
        call_rows: List[Tuple[Any, ...]],
    ):
        """Fallback call extraction for clangd versions without call hierarchy."""
        try:
            lines = self._read_source_lines(file_path)
            if lines is None:
                return
            body = "".join(lines[start_line - 1 : end_line])
            masked_body = self._mask_c_comments_and_literals(body)

            call_pattern = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
            for m in call_pattern.finditer(masked_body):
                callee = m.group(1)
                if (
                    not is_likely_function_call_identifier(callee)
                    or callee == caller_name
                ):
                    continue

                match_start_idx = m.start(1)
                prefix = masked_body[:match_start_idx]
                offset_lines = prefix.count("\n")
                call_line = start_line + offset_lines

                last_newline = prefix.rfind("\n")
                if last_newline == -1:
                    char_offset = len(prefix)
                else:
                    char_offset = len(prefix) - last_newline - 1

                callee_file = ""
                defs = self.get_definition(file_path, call_line - 1, char_offset)
                if defs and isinstance(defs, list) and len(defs) > 0:
                    uri = defs[0].get("targetUri") or defs[0].get("uri", "")
                    callee_file = self._uri_to_project_path(uri)

                call_rows.append(
                    (caller_name, caller_file, callee, callee_file, call_line, "direct")
                )
        except Exception as e:
            logger.debug("Failed to extract calls in %s: %s", caller_name, e)

    def _symbol_position(self, sym: Optional[Dict[str, Any]], start_line: int) -> Dict[str, int]:
        if sym:
            range_info = sym.get("selectionRange") or sym.get("range") or {}
            start = range_info.get("start", {}) if isinstance(range_info, dict) else {}
            line = start.get("line")
            character = start.get("character", 0)
            if isinstance(line, int) and isinstance(character, int):
                return {"line": line, "character": character}
        return {"line": max(start_line - 1, 0), "character": 0}

    def _call_line_from_ranges(self, ranges: Any, default_line: int) -> int:
        if isinstance(ranges, list) and ranges:
            first = ranges[0]
            if isinstance(first, dict):
                start = first.get("start", {})
                line = start.get("line")
                if isinstance(line, int):
                    return line + 1
        return default_line

    def _uri_to_project_path(self, uri: str) -> str:
        if not uri or not uri.startswith("file://"):
            return ""
        try:
            from urllib.parse import urlparse
            from urllib.request import url2pathname

            parsed = urlparse(uri)
            abs_path = Path(url2pathname(parsed.path)).resolve()
            return self._project_relative_path(abs_path)
        except Exception:
            return ""

    def _project_relative_path(self, path: Path) -> str:
        resolved = Path(path).resolve()
        try:
            return resolved.relative_to(self.project_root).as_posix()
        except ValueError:
            return resolved.as_posix()

    def _is_function_declaration_symbol(
        self,
        file_path: Path,
        start_line: int,
        end_line: int,
        detail: str,
        *,
        is_static: bool,
        is_inline: bool,
    ) -> bool:
        has_body = self._symbol_range_has_function_body(file_path, start_line, end_line)
        if has_body is not None:
            return not has_body

        if "extern" in str(detail or ""):
            return True
        suffix = file_path.suffix.lower()
        return (
            suffix in HEADER_LIKE_SUFFIXES
            and end_line - start_line <= 1
            and not is_static
            and not is_inline
        )

    def _symbol_range_has_function_body(
        self,
        file_path: Path,
        start_line: int,
        end_line: int,
    ) -> Optional[bool]:
        lines = self._read_source_lines(file_path)
        if lines is None:
            return None

        if not lines:
            return None
        start_idx = max(0, int(start_line or 1) - 1)
        end_idx = min(len(lines), max(start_idx + 1, int(end_line or start_line or 1)))
        text = "".join(lines[start_idx:end_idx])
        if not text.strip():
            return None

        masked = self._mask_c_comments_and_literals(text)
        for match in re.finditer(r"\{", masked):
            brace_pos = match.start()
            paren_pos = masked.rfind(")", 0, brace_pos)
            if paren_pos == -1:
                continue
            if ";" in masked[paren_pos + 1 : brace_pos]:
                continue
            return True
        return False

    def _source_cache_key(self, file_path: Path) -> Optional[Tuple[str, int, int]]:
        try:
            resolved = Path(file_path).resolve()
            stat = resolved.stat()
        except OSError:
            return None
        return (str(resolved), int(stat.st_mtime_ns), int(stat.st_size))

    def _read_source_text(self, file_path: Path) -> Optional[str]:
        cache_key = self._source_cache_key(file_path)
        if cache_key is None:
            return None

        with self._source_text_cache_lock:
            cached = self._source_text_cache.get(cache_key)
            if cached is not None:
                self._source_text_cache.move_to_end(cache_key)
                return cached

        try:
            text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return None

        if self._source_cache_key(file_path) != cache_key:
            return text

        with self._source_text_cache_lock:
            self._source_text_cache[cache_key] = text
            self._source_text_cache.move_to_end(cache_key)
            while len(self._source_text_cache) > self._source_text_cache_limit:
                self._source_text_cache.popitem(last=False)
        return text

    def _read_source_lines(self, file_path: Path) -> Optional[List[str]]:
        text = self._read_source_text(file_path)
        if text is None:
            return None
        return text.splitlines(True)

    def _mask_c_comments_and_literals(self, text: str) -> str:
        chars = list(text)
        i = 0
        state = "code"
        while i < len(chars):
            ch = chars[i]
            nxt = chars[i + 1] if i + 1 < len(chars) else ""

            if state == "code":
                if ch == "/" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    state = "line_comment"
                    continue
                if ch == "/" and nxt == "*":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    state = "block_comment"
                    continue
                if ch == '"':
                    chars[i] = " "
                    i += 1
                    state = "string"
                    continue
                if ch == "'":
                    chars[i] = " "
                    i += 1
                    state = "char"
                    continue
            elif state == "line_comment":
                if ch == "\n":
                    state = "code"
                else:
                    chars[i] = " "
            elif state == "block_comment":
                if ch == "*" and nxt == "/":
                    chars[i] = chars[i + 1] = " "
                    i += 2
                    state = "code"
                    continue
                if ch != "\n":
                    chars[i] = " "
            elif state in ("string", "char"):
                quote = '"' if state == "string" else "'"
                if ch == "\\":
                    chars[i] = " "
                    if i + 1 < len(chars) and chars[i + 1] != "\n":
                        chars[i + 1] = " "
                        i += 2
                        continue
                if ch == quote:
                    chars[i] = " "
                    state = "code"
                elif ch != "\n":
                    chars[i] = " "

            i += 1
        return "".join(chars)

    @staticmethod
    def _compute_file_hash(file_path: Path) -> str:
        """计算文件的 SHA-256 哈希（hex，前32字符）。"""
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
        except OSError:
            return ""
        return h.hexdigest()[:32]
