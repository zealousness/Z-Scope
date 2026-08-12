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
MACRO_DEFINE_RE = re.compile(r"^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)(?P<tail>.*)$")
TYPE_CONTEXT_BUILTINS = {
    "void",
    "char",
    "signed",
    "unsigned",
    "short",
    "int",
    "long",
    "float",
    "double",
    "bool",
    "_Bool",
    "size_t",
    "ssize_t",
    "ptrdiff_t",
    "wchar_t",
    "const",
    "volatile",
    "restrict",
    "_Atomic",
    "atomic",
    "static",
    "extern",
    "register",
    "auto",
    "inline",
    "struct",
    "union",
    "enum",
    "class",
    "typename",
    "return",
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "break",
    "continue",
    "goto",
    "sizeof",
    "alignof",
    "_Alignof",
    "offsetof",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "intptr_t",
    "uintptr_t",
    "intmax_t",
    "uintmax_t",
}


class ClangExtractor:
    """
    基于 clangd LSP 的批处理代码结构提取器。
    复用历史 LSP 通信层，改造为批量提取模式。
    """

    _SEMANTIC_TOKEN_TYPES = [
        "namespace",
        "type",
        "class",
        "enum",
        "interface",
        "struct",
        "typeParameter",
        "parameter",
        "variable",
        "property",
        "enumMember",
        "event",
        "function",
        "method",
        "macro",
        "label",
        "comment",
        "string",
        "keyword",
        "number",
        "regexp",
        "operator",
        "decorator",
    ]
    _SEMANTIC_TOKEN_MODIFIERS = [
        "declaration",
        "definition",
        "readonly",
        "static",
        "deprecated",
        "abstract",
        "async",
        "modification",
        "documentation",
        "defaultLibrary",
        "functionScope",
        "classScope",
        "fileScope",
        "globalScope",
        "localScope",
    ]
    _REQUEST_LATENCY_SAMPLE_LIMIT = 256
    _MAX_INDEXING_WAIT_SECONDS = 120.0

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
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._pending_requests: Dict[Any, Optional[Dict[str, Any]]] = {}
        self._transport_closed = False
        self._io_lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._running = False
        self._initialized = False
        self._call_hierarchy_supported = False
        self._position_encoding = "utf-16"
        self._semantic_token_types: List[str] = []
        self._semantic_token_modifiers: List[str] = []
        self._progress_tokens: Dict[Any, str] = {}
        self._last_progress_time = time.monotonic()
        self._lsp_request_metrics: Dict[str, Dict[str, Any]] = {}
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
            with self._condition:
                self._running = True
                self._transport_closed = False
                self._progress_tokens.clear()
                self._last_progress_time = time.monotonic()
                self._condition.notify_all()

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
                self.stop()
                return False

            # LSP initialize 握手
            init_result = self.send_request(
                "initialize",
                {
                    "processId": os.getpid(),
                    "rootUri": self.project_root.as_uri(),
                    "capabilities": self._client_capabilities(),
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
            self._apply_server_capabilities(capabilities)

            self.send_notification("initialized", {})
            with self._condition:
                self._initialized = True
                self._condition.notify_all()
            logger.info("clangd LSP initialized successfully")
            return True
        except Exception as e:
            logger.error("Failed to start clangd: %s", e)
            self.stop()
            return False

    def stop(self):
        """关闭 clangd 进程。"""
        self._signal_transport_closed()
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
        self._opened_documents.clear()

    def _client_capabilities(self) -> Dict[str, Any]:
        return {
            "general": {"positionEncodings": ["utf-8"]},
            "window": {"workDoneProgress": True},
            "textDocument": {
                "documentSymbol": {"hierarchicalDocumentSymbolSupport": True},
                "callHierarchy": {"dynamicRegistration": False},
                "definition": {},
                "references": {},
                "hover": {},
                "typeDefinition": {},
                "semanticTokens": {
                    "dynamicRegistration": False,
                    "requests": {"full": True},
                    "tokenTypes": list(self._SEMANTIC_TOKEN_TYPES),
                    "tokenModifiers": list(self._SEMANTIC_TOKEN_MODIFIERS),
                    "formats": ["relative"],
                },
            },
            "workspace": {"symbol": {"dynamicRegistration": False}},
        }

    def _apply_server_capabilities(self, capabilities: Dict[str, Any]) -> None:
        self._call_hierarchy_supported = bool(capabilities.get("callHierarchyProvider"))
        self._position_encoding = str(capabilities.get("positionEncoding") or "utf-16")
        semantic_tokens = capabilities.get("semanticTokensProvider")
        legend = semantic_tokens.get("legend", {}) if isinstance(semantic_tokens, dict) else {}
        token_types = legend.get("tokenTypes", []) if isinstance(legend, dict) else []
        token_modifiers = legend.get("tokenModifiers", []) if isinstance(legend, dict) else []
        self._semantic_token_types = [str(value) for value in token_types]
        self._semantic_token_modifiers = [str(value) for value in token_modifiers]

    # ── JSON-RPC 通信 ──

    def send_request(self, method: str, params: Any, timeout: int = 120) -> Any:
        """发送 JSON-RPC 请求，在固定 monotonic deadline 内等待响应。"""
        started_at = time.monotonic()
        deadline = started_at + max(0.0, float(timeout))
        with self._condition:
            self._id_counter += 1
            msg_id = self._id_counter
            self._pending_requests[msg_id] = None
            metrics = self._lsp_request_metrics.setdefault(
                method, {"count": 0, "timeouts": 0, "latencies_ms": []}
            )
            metrics["count"] += 1

        msg = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
        self._write_message(msg)

        response: Optional[Dict[str, Any]] = None
        timed_out = False
        with self._condition:
            while True:
                now = time.monotonic()
                pending_response = self._pending_requests.get(msg_id)
                if pending_response is not None and now <= deadline:
                    response = pending_response
                    self._pending_requests.pop(msg_id, None)
                    self._record_request_latency_locked(method, started_at, timed_out=False)
                    break
                remaining = deadline - now
                if remaining <= 0:
                    self._pending_requests.pop(msg_id, None)
                    self._record_request_latency_locked(method, started_at, timed_out=True)
                    timed_out = True
                    break
                if self._transport_closed:
                    self._pending_requests.pop(msg_id, None)
                    self._record_request_latency_locked(method, started_at, timed_out=False)
                    break
                self._condition.wait(timeout=remaining)

        if response is not None:
            if "error" in response:
                logger.debug("LSP error for %s: %s", method, response["error"])
                return None
            return response.get("result")
        if timed_out:
            self.send_notification("$/cancelRequest", {"id": msg_id})
            logger.warning("LSP request '%s' timed out (id=%d)", method, msg_id)
        else:
            logger.debug(
                "LSP request '%s' aborted because the transport closed (id=%d)", method, msg_id
            )
        return None

    def _record_request_latency_locked(
        self, method: str, started_at: float, *, timed_out: bool
    ) -> None:
        metrics = self._lsp_request_metrics[method]
        if timed_out:
            metrics["timeouts"] += 1
        samples = metrics["latencies_ms"]
        samples.append(max(0.0, (time.monotonic() - started_at) * 1000.0))
        if len(samples) > self._REQUEST_LATENCY_SAMPLE_LIMIT:
            del samples[: len(samples) - self._REQUEST_LATENCY_SAMPLE_LIMIT]

    def get_request_metrics(self, method: str) -> Dict[str, Any]:
        """返回指定 LSP method 的有界延迟统计快照。"""
        with self._condition:
            metrics = self._lsp_request_metrics.get(method)
            if not metrics:
                return {
                    "count": 0,
                    "timeouts": 0,
                    "average_latency_ms": 0.0,
                    "p95_latency_ms": 0.0,
                }
            samples = list(metrics["latencies_ms"])
            count = int(metrics["count"])
            timeouts = int(metrics["timeouts"])
        if not samples:
            return {
                "count": count,
                "timeouts": timeouts,
                "average_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
            }
        ordered = sorted(float(value) for value in samples)
        p95_index = max(0, ((len(ordered) * 95 + 99) // 100) - 1)
        return {
            "count": count,
            "timeouts": timeouts,
            "average_latency_ms": sum(ordered) / len(ordered),
            "p95_latency_ms": ordered[p95_index],
        }

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
            self._signal_transport_closed()
            return
        fd = self.process.stdout.fileno()
        try:
            while self._running:
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
            pass
        finally:
            self._signal_transport_closed()

    def _dispatch_message(self, msg: dict):
        """分发收到的 LSP 消息。"""
        has_method = isinstance(msg.get("method"), str)
        has_id = "id" in msg
        if has_method and has_id:
            self._handle_server_request(msg)
        elif has_method:
            self._handle_server_notification(msg)
        elif has_id:
            self._handle_response(msg)
        else:
            logger.debug("Ignoring malformed JSON-RPC message: %r", msg)

    def _handle_response(self, msg: Dict[str, Any]) -> None:
        msg_id = msg.get("id")
        with self._condition:
            if msg_id not in self._pending_requests:
                logger.debug("Discarding late or unknown LSP response id=%r", msg_id)
                return
            self._pending_requests[msg_id] = msg
            self._condition.notify_all()

    def _handle_server_request(self, msg: Dict[str, Any]) -> None:
        method = str(msg.get("method") or "")
        msg_id = msg.get("id")
        if method == "window/workDoneProgress/create":
            params = msg.get("params")
            token = params.get("token") if isinstance(params, dict) else None
            if self._is_progress_token(token):
                with self._condition:
                    self._progress_tokens[token] = "created"
                    self._last_progress_time = time.monotonic()
                    self._condition.notify_all()
            self._write_message({"jsonrpc": "2.0", "id": msg_id, "result": None})
            return
        self._write_message(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        )

    def _handle_server_notification(self, msg: Dict[str, Any]) -> None:
        if msg.get("method") != "$/progress":
            return
        params = msg.get("params")
        if not isinstance(params, dict):
            return
        token = params.get("token")
        value = params.get("value")
        if not self._is_progress_token(token) or not isinstance(value, dict):
            return
        kind = str(value.get("kind") or "")
        with self._condition:
            self._last_progress_time = time.monotonic()
            if kind in {"begin", "report"}:
                self._progress_tokens[token] = kind
            elif kind == "end":
                self._progress_tokens.pop(token, None)
            self._condition.notify_all()

    @staticmethod
    def _is_progress_token(token: Any) -> bool:
        return isinstance(token, (str, int)) and not isinstance(token, bool)

    def _signal_transport_closed(self) -> None:
        with self._condition:
            self._running = False
            self._initialized = False
            self._transport_closed = True
            self._condition.notify_all()

    def _has_active_progress_locked(self) -> bool:
        return any(status in {"begin", "report"} for status in self._progress_tokens.values())

    def _stderr_loop(self):
        """后台线程：读取 clangd stderr 日志。"""
        while self._running and self.process and self.process.stderr:
            try:
                line = self.process.stderr.readline()
                if not line:
                    break
                text = ANSI_ESCAPE.sub("", line.decode("utf-8", errors="ignore")).strip()
                if text and "Indexing" in text:
                    with self._condition:
                        self._last_progress_time = time.monotonic()
                        self._condition.notify_all()
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
        lsp_character = self._python_offset_to_lsp(file_path, line, character)
        result = self.send_request(
            "textDocument/hover",
            {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": lsp_character},
            },
            timeout=30,
        )
        return cast(Optional[Dict], result)

    def get_definition(self, file_path: Path, line: int, character: int = 0) -> Optional[List]:
        uri = file_path.as_uri()
        lsp_character = self._python_offset_to_lsp(file_path, line, character)
        result = self.send_request(
            "textDocument/definition",
            {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": lsp_character},
            },
            timeout=30,
        )
        return cast(Optional[List], result)

    def get_references(
        self,
        file_path: Path,
        line: int,
        character: int = 0,
        include_declaration: bool = False,
    ) -> Optional[List[Dict]]:
        uri = file_path.as_uri()
        lsp_character = self._python_offset_to_lsp(file_path, line, character)
        result = self.send_request(
            "textDocument/references",
            {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": lsp_character},
                "context": {"includeDeclaration": include_declaration},
            },
            timeout=30,
        )
        return cast(Optional[List[Dict]], result)

    def get_semantic_tokens(self, file_path: Path) -> Optional[Dict]:
        result = self.send_request(
            "textDocument/semanticTokens/full",
            {"textDocument": {"uri": file_path.as_uri()}},
            timeout=60,
        )
        return cast(Optional[Dict], result)

    def _python_offset_to_lsp(self, file_path: Path, line: int, character: int) -> int:
        source_lines = self._read_source_lines(file_path)
        if not source_lines or line < 0 or line >= len(source_lines):
            return max(0, int(character))
        return self._python_offset_to_lsp_in_text(source_lines[line], character)

    def _python_offset_to_lsp_in_text(self, text: str, character: int) -> int:
        prefix = str(text or "")[: max(0, int(character))]
        if self._position_encoding == "utf-8":
            return len(prefix.encode("utf-8"))
        if self._position_encoding == "utf-32":
            return len(prefix)
        return len(prefix.encode("utf-16-le")) // 2

    def _lsp_offset_to_python_in_text(self, text: str, character: int) -> int:
        target = max(0, int(character))
        if str(text or "").isascii():
            return min(len(text), target)
        if self._position_encoding == "utf-32":
            return min(len(text), target)
        consumed = 0
        for index, value in enumerate(str(text or "")):
            width = (
                len(value.encode("utf-8"))
                if self._position_encoding == "utf-8"
                else len(value.encode("utf-16-le")) // 2
            )
            if consumed + width > target:
                return index
            consumed += width
            if consumed == target:
                return index + 1
        return len(text)

    def prepare_call_hierarchy(
        self, file_path: Path, line: int, character: int = 0
    ) -> Optional[List[Dict[str, Any]]]:
        uri = file_path.as_uri()
        lsp_character = self._python_offset_to_lsp(file_path, line, character)
        result = self.send_request(
            "textDocument/prepareCallHierarchy",
            {
                "textDocument": {"uri": uri},
                "position": {"line": line, "character": lsp_character},
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

    def wait_for_indexing(self, timeout: int = 120, idle_threshold: float = 5.0) -> bool:
        """等待 work-done tokens 结束并达到空闲阈值，最多等待 120 秒。"""
        effective_timeout = min(
            self._MAX_INDEXING_WAIT_SECONDS,
            max(0.0, float(timeout)),
        )
        idle_threshold = max(0.0, float(idle_threshold))
        deadline = time.monotonic() + effective_timeout
        with self._condition:
            while True:
                now = time.monotonic()
                idle_elapsed = max(0.0, now - self._last_progress_time)
                progress_active = self._has_active_progress_locked()
                if self._initialized and not progress_active and idle_elapsed >= idle_threshold:
                    logger.info("clangd indexing appears idle (%.1fs no progress)", idle_elapsed)
                    return True
                remaining = deadline - now
                if remaining <= 0:
                    break
                if self._transport_closed:
                    return False
                wait_time = remaining
                if self._initialized and not progress_active:
                    wait_time = min(wait_time, max(0.0, idle_threshold - idle_elapsed))
                self._condition.wait(timeout=wait_time)
        logger.warning("wait_for_indexing timed out after %.1fs", effective_timeout)
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

    _DIRECT_CALL_TARGET_KINDS = frozenset({SK_FUNCTION, SK_METHOD, SK_CONSTRUCTOR})
    _FUNCTION_POINTER_TARGET_KINDS = {
        SK_FIELD: "function_pointer_field",
        SK_VARIABLE: "function_pointer_variable",
    }

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
        for raw in lines[start_idx : min(len(lines), end_idx + 40)]:
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
                    if not is_system:
                        included = self._canonical_included_file(file_path, included)
                    db._conn.execute(
                        "INSERT OR IGNORE INTO include_edges "
                        "(source_file, included_file, line, is_system) VALUES (?, ?, ?, ?)",
                        (rel_path, included, line_no, is_system),
                    )
        except Exception:
            pass

    def _canonical_included_file(self, source_file: Path, included: str) -> str:
        clean = str(included or "").replace("\\", "/").strip()
        local_candidate = (source_file.parent / clean).resolve()
        root_candidate = (self.project_root / clean).resolve()
        candidates = [path for path in (local_candidate, root_candidate) if path.exists()]
        if not candidates and clean:
            suffix_parts = Path(clean).parts
            candidates = [
                path.resolve()
                for path in self.project_root.rglob(Path(clean).name)
                if path.is_file() and tuple(path.parts[-len(suffix_parts) :]) == suffix_parts
            ]
        unique = sorted({path for path in candidates})
        selected = unique[0] if len(unique) == 1 else local_candidate
        try:
            return selected.relative_to(self.project_root).as_posix()
        except ValueError:
            return selected.as_posix()

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
                    idx + 1,
                    (f"{match.group('name')}@{rel_path}:" f"{start_idx + 1}-{idx + 1}"),
                    "".join(body_lines),
                    int(str(match.group("tail") or "").startswith("(")),
                )
            )
            idx += 1

        return rows

    def rebuild_function_symbol_refs(
        self,
        db: KnowledgeDB,
        *,
        use_staging: bool = False,
    ) -> int:
        get_functions = getattr(db, "get_function_records", None)
        get_globals = getattr(db, "get_global_variables", None)
        get_macros = getattr(db, "get_all_macro_definitions", None)
        clear_refs = getattr(db, "clear_function_symbol_refs", None)
        insert_refs = getattr(db, "insert_function_symbol_refs_batch", None)
        replace_macro_refs = getattr(db, "replace_function_macro_refs", None)
        stage_refs = getattr(db, "stage_function_symbol_refs_batch", None)
        stage_macro_refs = getattr(db, "stage_function_macro_refs_batch", None)
        required_methods = [get_functions, get_globals, get_macros]
        if use_staging:
            required_methods.extend([stage_refs, stage_macro_refs])
        else:
            required_methods.extend([clear_refs, insert_refs, replace_macro_refs])
        if not all(callable(method) for method in required_methods):
            return 0
        assert callable(get_functions)
        assert callable(get_globals)
        assert callable(get_macros)

        functions = [row for row in get_functions() if not row.get("is_declaration")]
        globals_by_name = self._records_by_name(get_globals())
        macros_by_name = self._records_by_name(get_macros())
        aggregated: Dict[Tuple[str, str, str, str, str, int], str] = {}
        macro_refs: set[Tuple[int, int, int]] = set()

        functions_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for function in functions:
            functions_by_file.setdefault(str(function.get("file_path") or ""), []).append(function)
        include_closures = self._load_include_closures(db, list(functions_by_file))
        shared_reference_cache: Dict[Tuple[Any, ...], set[Tuple[str, int, int]]] = {}
        shared_declaration_char_cache: Dict[Tuple[Any, ...], Optional[Tuple[Path, int, int]]] = {}
        stats = self._new_derived_stats(
            "function_symbol_context",
            len(functions_by_file),
            len(functions),
        )
        logger.info(
            "[symbol-context] rebuild started files=%d functions=%d",
            len(functions_by_file),
            len(functions),
        )
        self._store_derived_stats_snapshot(stats)
        staged_count = 0

        for function_file, file_functions in sorted(functions_by_file.items()):
            source_path = self._resolve_indexed_source_path(function_file)
            lines = self._read_source_lines(source_path)
            if not lines:
                stats["files_processed"] += 1
                self._log_derived_progress(stats)
                continue
            document_opened = False
            try:
                document_opened = bool(self.open_document(source_path))
            except Exception:
                document_opened = False

            file_aggregated: Dict[Tuple[str, str, str, str, str, int], str] = {}
            file_macro_refs: set[Tuple[int, int, int]] = set()
            semantic_context = self._get_file_semantic_context(
                source_path,
                lines,
                enabled=document_opened,
            )
            semantic_context["reference_cache"] = shared_reference_cache
            semantic_context["declaration_char_cache"] = shared_declaration_char_cache
            try:
                for function in file_functions:
                    self._collect_function_symbol_refs(
                        function,
                        function_file,
                        source_path,
                        lines,
                        globals_by_name,
                        macros_by_name,
                        file_aggregated,
                        file_macro_refs,
                        include_closures.get(function_file, [function_file]),
                        semantic_context,
                        stats,
                    )
                    stats["functions_processed"] += 1
            finally:
                if document_opened:
                    try:
                        self.close_document(source_path)
                    except Exception:
                        pass

            if use_staging:
                assert callable(stage_refs)
                assert callable(stage_macro_refs)
                file_rows = [(*key, access) for key, access in sorted(file_aggregated.items())]
                for offset in range(0, len(file_rows), 1000):
                    stage_refs(file_rows[offset : offset + 1000])
                sorted_macro_refs = sorted(file_macro_refs)
                for offset in range(0, len(sorted_macro_refs), 1000):
                    stage_macro_refs(sorted_macro_refs[offset : offset + 1000])
                staged_count += len(file_rows) + len(sorted_macro_refs)
            else:
                for key, access in file_aggregated.items():
                    aggregated[key] = self._merge_access_kind(
                        aggregated.get(key, "unknown"),
                        access,
                    )
                macro_refs.update(file_macro_refs)
            stats["files_processed"] += 1
            self._log_derived_progress(stats)

        if use_staging:
            result_count = staged_count
        else:
            rows = [(*key, access) for key, access in sorted(aggregated.items())]
            replace_context = getattr(db, "replace_function_symbol_context", None)
            if callable(replace_context):
                replace_context(rows, sorted(macro_refs))
            else:
                assert callable(clear_refs)
                assert callable(insert_refs)
                assert callable(replace_macro_refs)
                clear_refs()
                insert_refs(rows)
                replace_macro_refs(sorted(macro_refs))
            db.commit()
            result_count = len(rows) + len(macro_refs)
        stats["rows"] = result_count
        self._finish_derived_stats(stats)
        return result_count

    def rebuild_function_type_refs(
        self,
        db: KnowledgeDB,
        *,
        use_staging: bool = False,
    ) -> int:
        """Rebuild direct function type references after all TU facts are current."""
        get_functions = getattr(db, "get_function_records", None)
        get_types = getattr(db, "get_all_type_definitions", None)
        replace_refs = getattr(db, "replace_function_type_refs", None)
        stage_refs = getattr(db, "stage_function_type_refs_batch", None)
        required_methods = [get_functions, get_types, stage_refs if use_staging else replace_refs]
        if not all(callable(method) for method in required_methods):
            return 0
        assert callable(get_functions)
        assert callable(get_types)

        functions = [row for row in get_functions() if not row.get("is_declaration")]
        type_records = list(get_types())
        types_by_name = self._records_by_name(type_records)
        rows: List[Tuple[Any, ...]] = []
        functions_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for function in functions:
            functions_by_file.setdefault(str(function.get("file_path") or ""), []).append(function)
        include_closures = self._load_include_closures(db, list(functions_by_file))
        shared_reference_cache: Dict[Tuple[Any, ...], set[Tuple[str, int, int]]] = {}
        shared_declaration_char_cache: Dict[Tuple[Any, ...], Optional[Tuple[Path, int, int]]] = {}
        stats = self._new_derived_stats(
            "function_type_refs",
            len(functions_by_file),
            len(functions),
        )
        logger.info(
            "[type-context] rebuild started files=%d functions=%d",
            len(functions_by_file),
            len(functions),
        )
        self._store_derived_stats_snapshot(stats)
        staged_count = 0

        for function_file, file_functions in sorted(functions_by_file.items()):
            source_path = self._resolve_indexed_source_path(function_file)
            lines = self._read_source_lines(source_path)
            if not lines:
                stats["files_processed"] += 1
                self._log_derived_progress(stats)
                continue
            document_opened = False
            try:
                document_opened = bool(self.open_document(source_path))
            except Exception:
                document_opened = False
            semantic_context = self._get_file_semantic_context(
                source_path,
                lines,
                enabled=document_opened,
            )
            semantic_context["reference_cache"] = shared_reference_cache
            semantic_context["declaration_char_cache"] = shared_declaration_char_cache
            file_rows: List[Tuple[Any, ...]] = []
            try:
                include_closure = include_closures.get(function_file, [function_file])
                for function in file_functions:
                    file_rows.extend(
                        self._collect_function_type_refs(
                            function,
                            function_file,
                            source_path,
                            lines,
                            types_by_name,
                            include_closure,
                            semantic_context,
                            stats,
                        )
                    )
                    stats["functions_processed"] += 1
            finally:
                if document_opened:
                    try:
                        self.close_document(source_path)
                    except Exception:
                        pass

            deduplicated_file_rows = sorted(
                set(file_rows), key=lambda row: tuple(str(value) for value in row)
            )
            if use_staging:
                assert callable(stage_refs)
                for offset in range(0, len(deduplicated_file_rows), 1000):
                    stage_refs(deduplicated_file_rows[offset : offset + 1000])
                staged_count += len(deduplicated_file_rows)
            else:
                rows.extend(deduplicated_file_rows)
            stats["files_processed"] += 1
            self._log_derived_progress(stats)

        if use_staging:
            result_count = staged_count
        else:
            assert callable(replace_refs)
            deduplicated = sorted(set(rows), key=lambda row: tuple(str(value) for value in row))
            replace_refs(deduplicated)
            db.commit()
            result_count = len(deduplicated)
        stats["rows"] = result_count
        self._finish_derived_stats(stats)
        return result_count

    def _collect_function_type_refs(
        self,
        function: Dict[str, Any],
        function_file: str,
        source_path: Path,
        lines: List[str],
        types_by_name: Dict[str, List[Dict[str, Any]]],
        include_closure: List[str],
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> List[Tuple[Any, ...]]:
        function_id = int(function.get("id") or 0)
        if function_id <= 0:
            return []
        candidates = self._direct_function_type_candidates(function, lines, set(types_by_name))
        resolved_cache: Dict[Tuple[str, int, int], Tuple[Optional[Dict[str, Any]], str]] = {}
        rows: List[Tuple[Any, ...]] = []
        for candidate in candidates:
            stats["candidates"] += 1
            if int(stats["candidates"]) % 1000 == 0:
                self._log_derived_progress(stats)
            name = str(candidate["name"])
            lookup_line = int(candidate.get("lookup_line") or candidate["line"])
            lookup_char = int(candidate.get("lookup_char") or candidate["character"])
            cache_key = (name, lookup_line, lookup_char)
            if cache_key not in resolved_cache:
                resolved_cache[cache_key] = self._resolve_type_occurrence(
                    name=name,
                    candidates=types_by_name.get(name, []),
                    function_file=function_file,
                    source_path=source_path,
                    lookup_line=lookup_line,
                    lookup_char=lookup_char,
                    include_closure=include_closure,
                    semantic_context=semantic_context,
                    stats=stats,
                )
            type_record, reason = resolved_cache[cache_key]
            if type_record is None:
                self._record_unresolved(
                    stats,
                    reason,
                    {
                        "function": str(function.get("name") or ""),
                        "file": function_file,
                        "name": name,
                        "line": int(candidate["line"]),
                    },
                )
                rows.append(
                    (
                        function_id,
                        None,
                        "",
                        name,
                        function_file,
                        int(candidate["line"]),
                        str(candidate["kind"]),
                        reason,
                    )
                )
                continue
            type_index_name = KnowledgeDB.type_index_name(type_record)
            rows.append(
                (
                    function_id,
                    int(type_record["id"]),
                    type_index_name,
                    name,
                    function_file,
                    int(candidate["line"]),
                    str(candidate["kind"]),
                    "",
                )
            )
        return rows

    def _direct_function_type_candidates(
        self,
        function: Dict[str, Any],
        lines: List[str],
        indexed_type_names: set[str],
    ) -> List[Dict[str, Any]]:
        start_line = max(1, int(function.get("start_line") or 1))
        end_line = min(len(lines), max(start_line, int(function.get("end_line") or start_line)))
        function_name = str(function.get("name") or "").split("::")[-1]
        source_lines = lines[start_line - 1 : end_line]
        joined = "".join(source_lines)
        brace_offset = joined.find("{")
        signature_text = joined if brace_offset < 0 else joined[:brace_offset]
        signature_end_line = start_line + signature_text.count("\n")
        signature_function_match = re.search(rf"\b{re.escape(function_name)}\s*\(", signature_text)
        signature_function_offset = (
            signature_function_match.start() if signature_function_match else len(signature_text)
        )
        parameter_names = self._signature_parameter_names(signature_text, function_name)
        candidates: List[Dict[str, Any]] = []
        seen: set[Tuple[str, int, int, str]] = set()

        def add(
            name: str,
            line: int,
            character: int,
            kind: str,
            *,
            lookup_line: Optional[int] = None,
            lookup_char: Optional[int] = None,
        ) -> None:
            clean_name = str(name or "")
            if (
                not clean_name
                or clean_name in TYPE_CONTEXT_BUILTINS
                or clean_name == function_name
                or not self._is_direct_type_candidate_name(
                    clean_name,
                    indexed_type_names,
                )
            ):
                return
            key = (clean_name, int(line), int(character), kind)
            if key in seen:
                return
            seen.add(key)
            candidates.append(
                {
                    "name": clean_name,
                    "line": int(line),
                    "character": int(character),
                    "kind": kind,
                    "lookup_line": int(lookup_line or line),
                    "lookup_char": int(lookup_char if lookup_char is not None else character),
                }
            )

        running_offset = 0
        for line_offset, raw_line in enumerate(source_lines):
            absolute_line = start_line + line_offset
            signature_line = absolute_line <= signature_end_line
            line_limit = len(raw_line)
            if signature_line and absolute_line == signature_end_line and brace_offset >= 0:
                line_prefix_offset = sum(len(value) for value in source_lines[:line_offset])
                line_limit = max(0, brace_offset - line_prefix_offset)
            masked_line = self._mask_c_comments_and_literals(raw_line[:line_limit])
            if signature_line:
                for token in re.finditer(r"\b[A-Za-z_]\w*\b", masked_line):
                    name = token.group(0)
                    absolute_offset = running_offset + token.start()
                    if name in parameter_names or not self._is_direct_type_candidate_name(
                        name,
                        indexed_type_names,
                    ):
                        continue
                    kind = "return" if absolute_offset < signature_function_offset else "parameter"
                    parameter_fragment = masked_line[max(0, token.start() - 24) : token.end() + 48]
                    if "(*" in parameter_fragment.replace(" ", ""):
                        kind = "function_pointer"
                    add(name, absolute_line, token.start(), kind)
            running_offset += len(raw_line)

        variable_types: Dict[str, Tuple[str, int, int]] = {}
        declaration_pattern = re.compile(
            r"(?:^|[;{}])\s*(?:const\s+|volatile\s+|static\s+|register\s+|auto\s+|"
            r"signed\s+|unsigned\s+|short\s+|long\s+|_Atomic\s+)*"
            r"(?:(?:struct|union|enum|class)\s+)?(?P<type>[A-Za-z_]\w*)"
            r"(?P<middle>(?:\s+|\*+|&+|const\b|volatile\b)+)"
            r"(?P<var>[A-Za-z_]\w*)\s*(?=[=;,{\[])"
        )
        operator_patterns = (
            (
                "sizeof",
                re.compile(r"\bsizeof\s*\(\s*(?:(?:struct|union|enum)\s+)?(?P<type>[A-Za-z_]\w*)"),
            ),
            (
                "alignof",
                re.compile(
                    r"\b(?:_Alignof|alignof)\s*\(\s*(?:(?:struct|union|enum)\s+)?(?P<type>[A-Za-z_]\w*)"
                ),
            ),
            (
                "offsetof",
                re.compile(
                    r"\boffsetof\s*\(\s*(?:(?:struct|union|enum)\s+)?(?P<type>[A-Za-z_]\w*)"
                ),
            ),
            (
                "compound_literal",
                re.compile(
                    r"\(\s*(?:(?:struct|union|enum)\s+)?(?P<type>[A-Za-z_]\w*)\s*(?:\*+\s*)?\)\s*\{"
                ),
            ),
            (
                "cast",
                re.compile(
                    r"\(\s*(?:(?:struct|union|enum)\s+)?(?P<type>[A-Za-z_]\w*)"
                    r"\s*(?:\*+|&)?\s*\)\s*(?=[A-Za-z_0-9&*!~(+-])"
                ),
            ),
        )
        for line_offset, raw_line in enumerate(source_lines):
            absolute_line = start_line + line_offset
            if absolute_line <= signature_end_line:
                continue
            masked_line = self._mask_c_comments_and_literals(raw_line)
            for kind, pattern in operator_patterns:
                for match in pattern.finditer(masked_line):
                    name = match.group("type")
                    add(name, absolute_line, match.start("type"), kind)
            for match in declaration_pattern.finditer(masked_line):
                name = match.group("type")
                variable = match.group("var")
                if name in TYPE_CONTEXT_BUILTINS:
                    continue
                kind = "function_pointer" if "(*" in match.group(0).replace(" ", "") else "local"
                add(name, absolute_line, match.start("type"), kind)
                variable_types[variable] = (name, absolute_line, match.start("type"))

        signature_decl_pattern = re.compile(
            r"(?:(?:struct|union|enum|class)\s+)?(?P<type>[A-Za-z_]\w*)"
            r"(?:\s|\*|&|const|volatile)+(?P<var>[A-Za-z_]\w*)\s*(?=[,)])"
        )
        for match in signature_decl_pattern.finditer(signature_text):
            name = match.group("type")
            if name in TYPE_CONTEXT_BUILTINS:
                continue
            line = start_line + signature_text[: match.start("type")].count("\n")
            line_start = signature_text.rfind("\n", 0, match.start("type")) + 1
            character = match.start("type") - line_start
            variable_types[match.group("var")] = (name, line, character)

        member_access_pattern = re.compile(r"\b(?P<variable>[A-Za-z_]\w*)\s*(?:->|\.)")
        for line_offset, raw_line in enumerate(source_lines):
            absolute_line = start_line + line_offset
            masked_line = self._mask_c_comments_and_literals(raw_line)
            for access in member_access_pattern.finditer(masked_line):
                variable_type = variable_types.get(access.group("variable"))
                if variable_type is None:
                    continue
                name, lookup_line, lookup_char = variable_type
                add(
                    name,
                    absolute_line,
                    access.start(),
                    "member_access",
                    lookup_line=lookup_line,
                    lookup_char=lookup_char,
                )

        return sorted(
            candidates,
            key=lambda item: (item["line"], item["character"], item["name"], item["kind"]),
        )

    @staticmethod
    def _is_direct_type_candidate_name(
        name: str,
        indexed_type_names: set[str],
    ) -> bool:
        clean = str(name or "")
        if not clean or clean in TYPE_CONTEXT_BUILTINS:
            return False
        return clean in indexed_type_names or clean[:1].isupper() or clean.endswith("_t")

    @staticmethod
    def _signature_parameter_names(signature_text: str, function_name: str) -> set[str]:
        match = re.search(
            rf"\b{re.escape(function_name)}\s*\((?P<params>.*)\)", signature_text, re.S
        )
        if not match:
            return set()
        names: set[str] = set()
        for parameter in match.group("params").split(","):
            identifiers = [
                item
                for item in re.findall(r"\b[A-Za-z_]\w*\b", parameter)
                if item not in TYPE_CONTEXT_BUILTINS
            ]
            if len(identifiers) >= 2:
                names.add(identifiers[-1])
        return names

    def _resolve_type_definition_candidate(
        self,
        name: str,
        candidates: List[Dict[str, Any]],
        definitions: List[Tuple[str, int]],
        function_file: str,
        include_closure: List[str],
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        if not candidates:
            return None, "type_definition_not_found"
        matched: List[Dict[str, Any]] = []
        for target_file, target_line in definitions:
            for candidate in candidates:
                start_line = int(candidate.get("start_line") or 0)
                end_line = int(candidate.get("end_line") or start_line)
                if self._paths_match(target_file, str(candidate.get("file_path") or "")) and (
                    target_line <= 0 or start_line <= target_line <= max(start_line, end_line)
                ):
                    matched.append(candidate)
        unique_matched = {int(item.get("id") or 0): item for item in matched}
        if len(unique_matched) == 1:
            return next(iter(unique_matched.values())), ""
        if len(unique_matched) > 1:
            return None, "type_definition_ambiguous"
        if definitions:
            return None, "definition_not_indexed"
        return None, "type_not_visible"

    def _collect_function_symbol_refs(
        self,
        function: Dict[str, Any],
        function_file: str,
        source_path: Path,
        lines: List[str],
        globals_by_name: Dict[str, List[Dict[str, Any]]],
        macros_by_name: Dict[str, List[Dict[str, Any]]],
        aggregated: Dict[Tuple[str, str, str, str, str, int], str],
        macro_refs: set[Tuple[int, int, int]],
        include_closure: List[str],
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> None:
        start_line = max(1, int(function.get("start_line") or 1))
        end_line = min(len(lines), max(start_line, int(function.get("end_line") or start_line)))
        body_lines = lines[start_line - 1 : end_line]
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
                stats["candidates"] += 1
                if int(stats["candidates"]) % 1000 == 0:
                    self._log_derived_progress(stats)
                local_line = local_declarations.get(name)
                is_shadowed = local_line is not None and absolute_line >= local_line
                is_field = self._is_field_access(masked_line, match.start())
                if global_candidates and is_shadowed:
                    stats["filtered_local_shadow"] += 1
                if global_candidates and is_field:
                    stats["filtered_field"] += 1
                callable_macros = [
                    row
                    for row in macro_candidates
                    if not bool(row.get("is_function_like"))
                    or bool(re.match(r"\s*\(", masked_line[match.end() :]))
                ]
                stats["filtered_non_call_macro"] += len(macro_candidates) - len(callable_macros)
                active_globals = [] if is_shadowed or is_field else global_candidates
                if not active_globals and not callable_macros:
                    continue

                token = self._semantic_token_at(
                    semantic_context,
                    absolute_line,
                    match.start(),
                )
                global_record: Optional[Dict[str, Any]] = None
                macro_record: Optional[Dict[str, Any]] = None
                if active_globals and not callable_macros:
                    global_record = self._resolve_symbol_occurrence(
                        kind="global",
                        candidates=active_globals,
                        function_file=function_file,
                        source_path=source_path,
                        line=absolute_line,
                        character=match.start(),
                        include_closure=include_closure,
                        semantic_context=semantic_context,
                        semantic_token=token,
                        stats=stats,
                    )
                elif callable_macros and not active_globals:
                    macro_record = self._resolve_symbol_occurrence(
                        kind="macro",
                        candidates=callable_macros,
                        function_file=function_file,
                        source_path=source_path,
                        line=absolute_line,
                        character=match.start(),
                        include_closure=include_closure,
                        semantic_context=semantic_context,
                        semantic_token=token,
                        stats=stats,
                    )
                else:
                    resolved_kind, resolved_record = self._resolve_cross_kind_occurrence(
                        function_file=function_file,
                        source_path=source_path,
                        line=absolute_line,
                        character=match.start(),
                        global_candidates=active_globals,
                        macro_candidates=callable_macros,
                        include_closure=include_closure,
                        semantic_context=semantic_context,
                        semantic_token=token,
                        stats=stats,
                    )
                    if resolved_kind == "global":
                        global_record = resolved_record
                    elif resolved_kind == "macro":
                        macro_record = resolved_record

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

                if macro_record is not None:
                    function_id = int(function.get("id") or 0)
                    macro_id = int(macro_record.get("id") or 0)
                    if function_id > 0 and macro_id > 0:
                        macro_refs.add((function_id, macro_id, absolute_line))

    @staticmethod
    def _records_by_name(records: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        result: Dict[str, List[Dict[str, Any]]] = {}
        for record in records:
            name = str(record.get("name") or "")
            if name:
                result.setdefault(name, []).append(dict(record))
        for rows in result.values():
            rows.sort(
                key=lambda row: (
                    str(row.get("file_path") or ""),
                    int(row.get("start_line") or row.get("line") or 0),
                )
            )
        return result

    def _load_include_closures(
        self,
        db: KnowledgeDB,
        source_files: List[str],
    ) -> Dict[str, List[str]]:
        cache_key = (id(db), tuple(sorted(str(value) for value in source_files)))
        cache = getattr(self, "_include_closure_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            setattr(self, "_include_closure_cache", cache)
        cached = cache.get(cache_key)
        if isinstance(cached, dict):
            return {str(key): list(value) for key, value in cached.items()}
        batch_getter = getattr(db, "get_transitive_include_closures", None)
        if callable(batch_getter):
            result = {
                str(key): list(value) for key, value in dict(batch_getter(source_files)).items()
            }
        else:
            getter = getattr(db, "get_transitive_include_closure", None)
            if callable(getter):
                result = {source_file: list(getter(source_file)) for source_file in source_files}
            else:
                result = {source_file: [source_file] for source_file in source_files}
        cache[cache_key] = {str(key): list(value) for key, value in result.items()}
        return result

    def begin_derived_rebuild_session(self) -> None:
        """Reset base-dependent caches before one or more derived rebuilds."""
        self._include_closure_cache: Dict[Tuple[int, Tuple[str, ...]], Dict[str, List[str]]] = {}
        self._derived_session_active = True

    def end_derived_rebuild_session(self) -> None:
        """Release per-file semantic facts retained across sibling rebuilds."""
        self._derived_session_active = False
        cache = getattr(self, "_semantic_context_cache", None)
        if isinstance(cache, OrderedDict):
            while len(cache) > 64:
                cache.popitem(last=False)

    @staticmethod
    def _new_derived_stats(
        index_name: str,
        files_total: int,
        functions_total: int,
    ) -> Dict[str, Any]:
        return {
            "index_name": index_name,
            "files_total": int(files_total),
            "files_processed": 0,
            "functions_total": int(functions_total),
            "functions_processed": 0,
            "candidates": 0,
            "filtered_local_shadow": 0,
            "filtered_field": 0,
            "filtered_non_call_macro": 0,
            "semantic_resolved": 0,
            "local_resolved": 0,
            "references_requests": 0,
            "references_resolved": 0,
            "definition_requests": 0,
            "definition_timeouts": 0,
            "definition_average_latency_ms": 0.0,
            "definition_p95_latency_ms": 0.0,
            "unresolved_reasons": {},
            "unresolved_samples": [],
            "rows": 0,
            "elapsed_seconds": 0.0,
            "_started_monotonic": time.monotonic(),
            "_last_log_monotonic": 0.0,
            "_definition_latencies_ms": [],
            "_definition_latency_sum_ms": 0.0,
            "_definition_latency_count": 0,
        }

    def _log_derived_progress(self, stats: Dict[str, Any], *, force: bool = False) -> None:
        now = time.monotonic()
        last_log = float(stats.get("_last_log_monotonic") or 0.0)
        if not force and last_log and now - last_log < 5.0:
            return
        stats["_last_log_monotonic"] = now
        logger.info(
            "[%s] files=%d/%d functions=%d/%d candidates=%d "
            "local=%d references=%d definitions=%d unresolved=%d",
            stats.get("index_name"),
            int(stats.get("files_processed") or 0),
            int(stats.get("files_total") or 0),
            int(stats.get("functions_processed") or 0),
            int(stats.get("functions_total") or 0),
            int(stats.get("candidates") or 0),
            int(stats.get("local_resolved") or 0),
            int(stats.get("references_resolved") or 0),
            int(stats.get("definition_requests") or 0),
            sum(int(value) for value in dict(stats.get("unresolved_reasons") or {}).values()),
        )
        self._store_derived_stats_snapshot(stats)

    @staticmethod
    def _record_unresolved(
        stats: Dict[str, Any],
        reason: str,
        sample: Dict[str, Any],
    ) -> None:
        clean_reason = str(reason or "unresolved")
        reasons = stats.setdefault("unresolved_reasons", {})
        reasons[clean_reason] = int(reasons.get(clean_reason) or 0) + 1
        samples = stats.setdefault("unresolved_samples", [])
        if len(samples) < 10:
            samples.append({**sample, "reason": clean_reason})

    def _finish_derived_stats(self, stats: Dict[str, Any]) -> None:
        latencies = sorted(float(value) for value in stats.get("_definition_latencies_ms", []))
        latency_count = int(stats.get("_definition_latency_count") or 0)
        if latency_count:
            stats["definition_average_latency_ms"] = round(
                float(stats.get("_definition_latency_sum_ms") or 0.0) / latency_count,
                3,
            )
        if latencies:
            percentile_index = max(
                0, min(len(latencies) - 1, int(0.95 * len(latencies) + 0.999) - 1)
            )
            stats["definition_p95_latency_ms"] = round(latencies[percentile_index], 3)
        stats["elapsed_seconds"] = round(
            max(0.0, time.monotonic() - float(stats.get("_started_monotonic") or 0.0)),
            3,
        )
        stats.pop("_started_monotonic", None)
        stats.pop("_last_log_monotonic", None)
        stats.pop("_definition_latencies_ms", None)
        stats.pop("_definition_latency_sum_ms", None)
        stats.pop("_definition_latency_count", None)
        self._log_derived_progress(stats, force=True)
        stats.pop("_last_log_monotonic", None)
        unresolved_total = sum(
            int(value) for value in dict(stats.get("unresolved_reasons") or {}).values()
        )
        if unresolved_total:
            logger.warning(
                "[%s] unresolved=%d reasons=%s samples=%s",
                stats.get("index_name"),
                unresolved_total,
                stats.get("unresolved_reasons"),
                stats.get("unresolved_samples"),
            )
        self._store_derived_stats_snapshot(stats)

    def _store_derived_stats_snapshot(self, stats: Dict[str, Any]) -> None:
        snapshot = {str(key): value for key, value in stats.items() if not str(key).startswith("_")}
        started = stats.get("_started_monotonic")
        if isinstance(started, (int, float)):
            snapshot["elapsed_seconds"] = round(
                max(0.0, time.monotonic() - float(started)),
                3,
            )
        all_stats = getattr(self, "_last_derived_stats", None)
        if not isinstance(all_stats, dict):
            all_stats = {}
            setattr(self, "_last_derived_stats", all_stats)
        all_stats[str(stats.get("index_name") or "")] = snapshot

    def get_last_derived_stats(self, index_name: str) -> Dict[str, Any]:
        all_stats = getattr(self, "_last_derived_stats", {})
        value = all_stats.get(index_name, {}) if isinstance(all_stats, dict) else {}
        return dict(value) if isinstance(value, dict) else {}

    def _get_file_semantic_context(
        self,
        source_path: Path,
        lines: List[str],
        *,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        try:
            stat = source_path.stat()
            cache_key = (str(source_path.resolve()), int(stat.st_mtime_ns), int(stat.st_size))
        except OSError:
            cache_key = (str(source_path.resolve()), 0, 0)
        cache = getattr(self, "_semantic_context_cache", None)
        if not isinstance(cache, OrderedDict):
            cache = OrderedDict()
            setattr(self, "_semantic_context_cache", cache)
        cached = cache.get(cache_key)
        if isinstance(cached, dict):
            cache.move_to_end(cache_key)
            return cached

        context: Dict[str, Any] = {
            "available": False,
            "tokens_by_line": {},
            "tokens_by_position": {},
            "reference_cache": {},
            "definition_cache": {},
            "declaration_char_cache": {},
        }
        can_query = enabled and (self.process is not None or "get_semantic_tokens" in self.__dict__)
        getter = getattr(self, "get_semantic_tokens", None)
        if can_query and callable(getter):
            try:
                response = getter(source_path)
            except Exception:
                response = None
            data = response.get("data") if isinstance(response, dict) else None
            if isinstance(data, list):
                context["available"] = True
                self._semantic_decode_source_lines: Optional[List[str]] = lines
                try:
                    context["tokens_by_line"] = self._decode_semantic_tokens(data)
                finally:
                    self._semantic_decode_source_lines = None
                context["tokens_by_position"] = {
                    (line, int(token.get("start") or 0)): token
                    for line, tokens in context["tokens_by_line"].items()
                    for token in tokens
                }

        cache[cache_key] = context
        cache.move_to_end(cache_key)
        if not bool(getattr(self, "_derived_session_active", False)):
            while len(cache) > 64:
                cache.popitem(last=False)
        return context

    def _decode_semantic_tokens(self, data: List[Any]) -> Dict[int, List[Dict[str, Any]]]:
        token_types = list(getattr(self, "_semantic_token_types", []) or [])
        modifier_types = list(getattr(self, "_semantic_token_modifiers", []) or [])
        result: Dict[int, List[Dict[str, Any]]] = {}
        current_line = 0
        current_start = 0
        source_lines_by_index: Dict[int, str] = {}
        for offset in range(0, len(data) - 4, 5):
            try:
                delta_line = int(data[offset])
                delta_start = int(data[offset + 1])
                length = int(data[offset + 2])
                token_index = int(data[offset + 3])
                modifier_bits = int(data[offset + 4])
            except (TypeError, ValueError):
                continue
            current_line += delta_line
            current_start = delta_start if delta_line else current_start + delta_start
            source_line = source_lines_by_index.get(current_line, "")
            if not source_line:
                source_lines = getattr(self, "_semantic_decode_source_lines", None)
                if isinstance(source_lines, list) and 0 <= current_line < len(source_lines):
                    source_line = str(source_lines[current_line])
                    source_lines_by_index[current_line] = source_line
            python_start = self._lsp_offset_to_python_in_text(source_line, current_start)
            python_end = self._lsp_offset_to_python_in_text(
                source_line,
                current_start + max(0, length),
            )
            token_type = (
                str(token_types[token_index])
                if 0 <= token_index < len(token_types)
                else str(token_index)
            )
            modifiers = {
                str(name)
                for index, name in enumerate(modifier_types)
                if modifier_bits & (1 << index)
            }
            result.setdefault(current_line + 1, []).append(
                {
                    "start": python_start,
                    "end": python_end,
                    "type": token_type,
                    "modifiers": modifiers,
                }
            )
        return result

    @staticmethod
    def _semantic_token_at(
        semantic_context: Dict[str, Any],
        line: int,
        character: int,
    ) -> Optional[Dict[str, Any]]:
        exact = semantic_context.get("tokens_by_position", {}).get((int(line), int(character)))
        if isinstance(exact, dict):
            return exact
        tokens = semantic_context.get("tokens_by_line", {}).get(int(line), [])
        for token in tokens:
            if int(token.get("start") or 0) <= character < int(token.get("end") or 0):
                return cast(Dict[str, Any], token)
        return None

    @staticmethod
    def _semantic_token_proves_kind(token: Optional[Dict[str, Any]], kind: str) -> bool:
        if not token:
            return False
        token_type = str(token.get("type") or "")
        modifiers = {str(value) for value in token.get("modifiers", set())}
        if kind == "macro":
            return token_type.lower() in {"macro", "macroname"}
        global_scope = bool(
            modifiers
            & {
                "globalScope",
                "fileScope",
                "namespaceScope",
                "global",
            }
        )
        if kind == "global":
            return global_scope and token_type in {"variable", "enumMember"}
        if kind == "type":
            return global_scope and token_type in {
                "type",
                "class",
                "struct",
                "enum",
                "interface",
                "typeParameter",
            }
        return False

    @staticmethod
    def _semantic_token_is_local(token: Optional[Dict[str, Any]]) -> bool:
        if not token:
            return False
        token_type = str(token.get("type") or "")
        modifiers = {str(value) for value in token.get("modifiers", set())}
        return token_type in {"parameter", "property"} or bool(
            modifiers
            & {
                "functionScope",
                "classScope",
                "localScope",
                "local",
            }
        )

    def _visible_candidates(
        self,
        candidates: List[Dict[str, Any]],
        function_file: str,
        include_closure: List[str],
    ) -> List[Dict[str, Any]]:
        visible: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for candidate in candidates:
            candidate_file = str(candidate.get("file_path") or "")
            if not (
                self._paths_match(function_file, candidate_file)
                or any(self._paths_match(path, candidate_file) for path in include_closure)
            ):
                continue
            identity = self._candidate_identity(candidate)
            visible[identity] = candidate
        return list(visible.values())

    @staticmethod
    def _candidate_identity(candidate: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            str(candidate.get("file_path") or ""),
            int(candidate.get("line") or candidate.get("start_line") or 0),
            int(candidate.get("end_line") or 0),
            str(candidate.get("name") or ""),
            str(candidate.get("kind") or candidate.get("definition_kind") or ""),
            int(candidate.get("id") or 0),
        )

    def _resolve_symbol_occurrence(
        self,
        *,
        kind: str,
        candidates: List[Dict[str, Any]],
        function_file: str,
        source_path: Path,
        line: int,
        character: int,
        include_closure: List[str],
        semantic_context: Dict[str, Any],
        semantic_token: Optional[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        if kind == "global" and self._semantic_token_is_local(semantic_token):
            stats["filtered_local_shadow"] += 1
            stats["semantic_resolved"] += 1
            return None
        visible = self._visible_candidates(candidates, function_file, include_closure)
        if len(visible) == 1 and self._semantic_token_proves_kind(semantic_token, kind):
            stats["semantic_resolved"] += 1
            stats["local_resolved"] += 1
            return visible[0]
        by_references = self._resolve_candidate_by_references(
            visible or candidates,
            kind=kind,
            source_path=source_path,
            line=line,
            character=character,
            semantic_context=semantic_context,
            stats=stats,
        )
        if by_references is not None:
            stats["references_resolved"] += 1
            return by_references
        definitions = self._definition_locations_cached(
            source_path,
            line,
            character,
            semantic_context,
            stats,
        )
        resolved = self._resolve_symbol_candidate(candidates, function_file, definitions)
        if resolved is None:
            self._record_unresolved(
                stats,
                "definition_not_indexed" if definitions else "definition_unresolved",
                {"file": function_file, "name": str(candidates[0].get("name") or ""), "line": line},
            )
        return resolved

    def _resolve_cross_kind_occurrence(
        self,
        *,
        function_file: str,
        source_path: Path,
        line: int,
        character: int,
        global_candidates: List[Dict[str, Any]],
        macro_candidates: List[Dict[str, Any]],
        include_closure: List[str],
        semantic_context: Dict[str, Any],
        semantic_token: Optional[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        visible_globals = self._visible_candidates(
            global_candidates,
            function_file,
            include_closure,
        )
        visible_macros = self._visible_candidates(
            macro_candidates,
            function_file,
            include_closure,
        )
        if len(visible_globals) == 1 and self._semantic_token_proves_kind(
            semantic_token,
            "global",
        ):
            stats["semantic_resolved"] += 1
            stats["local_resolved"] += 1
            return "global", visible_globals[0]
        if len(visible_macros) == 1 and self._semantic_token_proves_kind(
            semantic_token,
            "macro",
        ):
            stats["semantic_resolved"] += 1
            stats["local_resolved"] += 1
            return "macro", visible_macros[0]
        global_by_references = self._resolve_candidate_by_references(
            visible_globals or global_candidates,
            kind="global",
            source_path=source_path,
            line=line,
            character=character,
            semantic_context=semantic_context,
            stats=stats,
        )
        macro_by_references = self._resolve_candidate_by_references(
            visible_macros or macro_candidates,
            kind="macro",
            source_path=source_path,
            line=line,
            character=character,
            semantic_context=semantic_context,
            stats=stats,
        )
        if global_by_references is not None and macro_by_references is None:
            stats["references_resolved"] += 1
            return "global", global_by_references
        if macro_by_references is not None and global_by_references is None:
            stats["references_resolved"] += 1
            return "macro", macro_by_references
        definitions = self._definition_locations_cached(
            source_path,
            line,
            character,
            semantic_context,
            stats,
        )
        global_record = self._resolve_symbol_candidate(
            global_candidates,
            function_file,
            definitions,
        )
        macro_record = self._resolve_symbol_candidate(
            macro_candidates,
            function_file,
            definitions,
        )
        if global_record is not None and macro_record is None:
            return "global", global_record
        if macro_record is not None and global_record is None:
            return "macro", macro_record
        self._record_unresolved(
            stats,
            "cross_kind_ambiguous" if definitions else "definition_unresolved",
            {
                "file": function_file,
                "name": str((global_candidates or macro_candidates)[0].get("name") or ""),
                "line": line,
            },
        )
        return "", None

    def _resolve_type_occurrence(
        self,
        *,
        name: str,
        candidates: List[Dict[str, Any]],
        function_file: str,
        source_path: Path,
        lookup_line: int,
        lookup_char: int,
        include_closure: List[str],
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        if not candidates:
            return None, "type_definition_not_found"
        token = self._semantic_token_at(semantic_context, lookup_line, lookup_char)
        if self._semantic_token_is_local(token):
            stats["semantic_resolved"] += 1
            return None, "local_type_shadow"
        visible = self._visible_candidates(candidates, function_file, include_closure)
        if len(visible) == 1 and self._semantic_token_proves_kind(token, "type"):
            stats["semantic_resolved"] += 1
            stats["local_resolved"] += 1
            return visible[0], ""
        by_references = self._resolve_candidate_by_references(
            visible or candidates,
            kind="type",
            source_path=source_path,
            line=lookup_line,
            character=lookup_char,
            semantic_context=semantic_context,
            stats=stats,
        )
        if by_references is not None:
            stats["references_resolved"] += 1
            return by_references, ""
        definitions = self._definition_locations_cached(
            source_path,
            lookup_line,
            lookup_char,
            semantic_context,
            stats,
        )
        return self._resolve_type_definition_candidate(
            name,
            candidates,
            definitions,
            function_file,
            include_closure,
        )

    def _resolve_candidate_by_references(
        self,
        candidates: List[Dict[str, Any]],
        *,
        kind: str,
        source_path: Path,
        line: int,
        character: int,
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        can_query = self.process is not None or "get_references" in self.__dict__
        getter = getattr(self, "get_references", None)
        if not can_query or not callable(getter):
            return None
        matched: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for candidate in candidates:
            locations = self._candidate_reference_locations(
                candidate,
                kind=kind,
                semantic_context=semantic_context,
                stats=stats,
            )
            if any(
                self._paths_match(target_file, str(source_path))
                and target_line == int(line)
                and target_character == int(character)
                for target_file, target_line, target_character in locations
            ):
                matched[self._candidate_identity(candidate)] = candidate
        return next(iter(matched.values())) if len(matched) == 1 else None

    def _candidate_reference_locations(
        self,
        candidate: Dict[str, Any],
        *,
        kind: str,
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> set[Tuple[str, int, int]]:
        cache = semantic_context.setdefault("reference_cache", {})
        cache_key = (kind, self._candidate_identity(candidate))
        if cache_key in cache:
            return set(cache[cache_key])
        declaration = self._candidate_declaration_position(candidate, semantic_context)
        if declaration is None:
            cache[cache_key] = set()
            return set()
        declaration_path, declaration_line, declaration_character = declaration
        stats["references_requests"] += 1
        try:
            raw_locations = self.get_references(
                declaration_path,
                max(0, declaration_line - 1),
                max(0, declaration_character),
                include_declaration=False,
            )
        except Exception:
            raw_locations = None
        locations: set[Tuple[str, int, int]] = set()
        for location in raw_locations or []:
            if not isinstance(location, dict):
                continue
            uri = str(location.get("uri") or location.get("targetUri") or "")
            target_file = self._uri_to_project_path(uri)
            range_info = location.get("range") or location.get("targetSelectionRange") or {}
            start = range_info.get("start", {}) if isinstance(range_info, dict) else {}
            if target_file and isinstance(start, dict):
                target_line_zero = int(start.get("line") or 0)
                target_character = int(start.get("character") or 0)
                target_path = self._resolve_indexed_source_path(target_file)
                target_lines = self._read_source_lines(target_path)
                if target_lines and 0 <= target_line_zero < len(target_lines):
                    target_character = self._lsp_offset_to_python_in_text(
                        target_lines[target_line_zero],
                        target_character,
                    )
                locations.add(
                    (
                        target_file,
                        target_line_zero + 1,
                        target_character,
                    )
                )
        cache[cache_key] = locations
        return locations

    def _candidate_declaration_position(
        self,
        candidate: Dict[str, Any],
        semantic_context: Dict[str, Any],
    ) -> Optional[Tuple[Path, int, int]]:
        cache = semantic_context.setdefault("declaration_char_cache", {})
        identity = self._candidate_identity(candidate)
        if identity in cache:
            return cast(Optional[Tuple[Path, int, int]], cache[identity])
        file_path = str(candidate.get("file_path") or "")
        name = str(candidate.get("name") or "")
        start_line = int(candidate.get("line") or candidate.get("start_line") or 0)
        end_line = int(candidate.get("end_line") or start_line)
        if not file_path or not name or start_line <= 0:
            cache[identity] = None
            return None
        path = self._resolve_indexed_source_path(file_path)
        source_lines = self._read_source_lines(path)
        if not source_lines:
            cache[identity] = None
            return None
        last_line = min(len(source_lines), max(start_line, min(end_line, start_line + 20)))
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        for declaration_line in range(start_line, last_line + 1):
            match = pattern.search(
                self._mask_c_comments_and_literals(source_lines[declaration_line - 1])
            )
            if match:
                value = (path, declaration_line, match.start())
                cache[identity] = value
                return value
        cache[identity] = None
        return None

    def _definition_locations_cached(
        self,
        source_path: Path,
        line: int,
        character: int,
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> List[Tuple[str, int]]:
        cache = semantic_context.setdefault("definition_cache", {})
        cache_key = (str(source_path.resolve()), int(line), int(character))
        if cache_key in cache:
            return list(cache[cache_key])
        metrics_getter = getattr(self, "get_request_metrics", None)
        before_timeouts = 0
        if callable(metrics_getter):
            before_timeouts = int(
                dict(metrics_getter("textDocument/definition")).get("timeouts") or 0
            )
        started = time.monotonic()
        stats["definition_requests"] += 1
        locations = self._definition_locations(source_path, line, character)
        elapsed_ms = (time.monotonic() - started) * 1000.0
        latency_samples = stats.setdefault("_definition_latencies_ms", [])
        latency_samples.append(elapsed_ms)
        if len(latency_samples) > 4096:
            del latency_samples[: len(latency_samples) - 4096]
        stats["_definition_latency_sum_ms"] = (
            float(stats.get("_definition_latency_sum_ms") or 0.0) + elapsed_ms
        )
        stats["_definition_latency_count"] = int(stats.get("_definition_latency_count") or 0) + 1
        if callable(metrics_getter):
            after_timeouts = int(
                dict(metrics_getter("textDocument/definition")).get("timeouts") or 0
            )
            stats["definition_timeouts"] += max(0, after_timeouts - before_timeouts)
        cache[cache_key] = list(locations)
        return locations

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
        if not definitions:
            return None
        matched: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for target_file, target_line in definitions:
            for candidate in candidates:
                candidate_file = str(candidate.get("file_path") or "")
                candidate_line = int(candidate.get("line") or 0)
                if self._paths_match(target_file, candidate_file) and (
                    target_line <= 0 or candidate_line <= 0 or target_line == candidate_line
                ):
                    matched[self._candidate_identity(candidate)] = candidate
        return next(iter(matched.values())) if len(matched) == 1 else None

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
            params = signature_text[signature_text.find("(") + 1 : signature_text.rfind(")")]
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
            declaration_line = start_line + body[: match.start("name")].count("\n")
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
                    if not is_likely_function_call_identifier(callee) or callee == caller_name:
                        continue
                    callee_file = self._uri_to_project_path(target.get("uri", ""))
                    call_line = self._call_line_from_ranges(call.get("fromRanges", []), start_line)
                    key = (callee, callee_file, call_line)
                    if key in seen:
                        continue
                    seen.add(key)
                    call_type, callee_kind = self._call_hierarchy_target_classification(target)
                    callee_signature = str(target.get("detail") or "").strip()
                    local_rows.append(
                        (
                            caller_name,
                            caller_file,
                            callee,
                            callee_file,
                            call_line,
                            call_type,
                            callee_kind,
                            callee_signature,
                        )
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
            source_text = "".join(lines)
            masked_source = self._mask_c_comments_and_literals(source_text)

            call_pattern = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")
            seen: set[tuple[str, int]] = set()
            for m in call_pattern.finditer(masked_body):
                callee = m.group(1)
                if not is_likely_function_call_identifier(callee) or callee == caller_name:
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

                call_type, callee_kind = self._regex_call_classification(
                    masked_body,
                    masked_source,
                    callee,
                    match_start_idx,
                    has_definition=bool(defs),
                )

                call_rows.append(
                    (
                        caller_name,
                        caller_file,
                        callee,
                        callee_file,
                        call_line,
                        call_type,
                        callee_kind,
                        "",
                    )
                )
                seen.add((callee, call_line))

            explicit_pointer_pattern = re.compile(r"\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\(")
            for m in explicit_pointer_pattern.finditer(masked_body):
                callee = m.group(1)
                if not is_likely_function_call_identifier(callee) or callee == caller_name:
                    continue
                prefix = masked_body[: m.start(1)]
                call_line = start_line + prefix.count("\n")
                if (callee, call_line) in seen:
                    continue
                last_newline = prefix.rfind("\n")
                char_offset = len(prefix) if last_newline == -1 else len(prefix) - last_newline - 1
                callee_file = ""
                defs = self.get_definition(file_path, call_line - 1, char_offset)
                if defs and isinstance(defs, list):
                    uri = defs[0].get("targetUri") or defs[0].get("uri", "") if defs else ""
                    callee_file = self._uri_to_project_path(uri)
                call_rows.append(
                    (
                        caller_name,
                        caller_file,
                        callee,
                        callee_file,
                        call_line,
                        "indirect",
                        "function_pointer_variable",
                        "",
                    )
                )
        except Exception as e:
            logger.debug("Failed to extract calls in %s: %s", caller_name, e)

    def _call_hierarchy_target_classification(
        self,
        target: Dict[str, Any],
    ) -> Tuple[str, str]:
        try:
            symbol_kind = int(target.get("kind", 0) or 0)
        except (TypeError, ValueError):
            symbol_kind = 0
        pointer_kind = self._FUNCTION_POINTER_TARGET_KINDS.get(symbol_kind)
        if pointer_kind:
            return "indirect", pointer_kind
        if symbol_kind in self._DIRECT_CALL_TARGET_KINDS:
            return "direct", "function"
        return "direct", "unknown_callable"

    def _regex_call_classification(
        self,
        masked_body: str,
        masked_source: str,
        callee: str,
        match_start_idx: int,
        *,
        has_definition: bool,
    ) -> Tuple[str, str]:
        prefix = masked_body[:match_start_idx]
        if re.search(r"(?:\.|->)\s*$", prefix):
            return "indirect", "function_pointer_field"
        if self._source_declares_function_pointer(masked_source, callee):
            return "indirect", "function_pointer_variable"
        if has_definition:
            return "direct", "function"
        return "direct", "unknown_callable"

    @staticmethod
    def _source_declares_function_pointer(masked_source: str, name: str) -> bool:
        escaped_name = re.escape(name)
        if re.search(
            rf"\(\s*\*\s*{escaped_name}\s*\)\s*\(",
            masked_source,
        ):
            return True
        typedef_names = {
            match.group(1)
            for match in re.finditer(
                r"\btypedef\b[^;]*?\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\([^;]*\)\s*;",
                masked_source,
                flags=re.DOTALL,
            )
        }
        return any(
            re.search(rf"\b{re.escape(type_name)}\b[^;{{}}]*\b{escaped_name}\b", masked_source)
            for type_name in typedef_names
        )

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
