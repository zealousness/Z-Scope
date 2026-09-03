"""
Clang extractor - LSP-based batch code structure extractor.
Adapted from historical lsp_client.py, repurposed for batch extraction into SQLite.
"""

import json
import logging
import os
import queue
import subprocess
import threading
import time
import re
import hashlib
from collections import OrderedDict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
    cast,
)

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


@dataclass
class _OutboundMessage:
    generation: int
    payload: bytes
    body_size: int
    deadline: Optional[float]
    request_id: Optional[Any]
    enqueued_at: float = field(default_factory=time.monotonic)
    written: threading.Event = field(default_factory=threading.Event)


@dataclass
class _DerivedFileResult:
    """Rows and worker-local telemetry produced without touching SQLite."""

    stats_by_index: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    symbol_rows: List[Tuple[Any, ...]] = field(default_factory=list)
    macro_rows: List[Tuple[int, int, int]] = field(default_factory=list)
    type_rows: List[Tuple[Any, ...]] = field(default_factory=list)
    errors: Dict[str, Exception] = field(default_factory=dict)


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
    _WRITER_QUEUE_LIMIT = 1024

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
        self._generation = 0
        self._lifecycle_lock = threading.RLock()
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._pending_requests: Dict[Any, Optional[Dict[str, Any]]] = {}
        self._pending_request_deadlines: Dict[Any, float] = {}
        self._transport_closed = False
        self._writer_queue: Optional[queue.Queue[Optional[_OutboundMessage]]] = None
        self._writer_thread: Optional[threading.Thread] = None
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
        self._file_status: Dict[str, Tuple[str, float]] = {}
        self._lsp_request_metrics: Dict[str, Dict[str, Any]] = {}
        self._request_outcome_local = threading.local()
        self._transport_metrics: Dict[str, Any] = {
            "messages_enqueued": 0,
            "messages_written": 0,
            "payload_bytes_enqueued": 0,
            "payload_bytes_written": 0,
            "wire_bytes_enqueued": 0,
            "wire_bytes_written": 0,
            "enqueue_failures": 0,
            "write_failures": 0,
            "expired_before_write": 0,
            "writer_queue_peak": 0,
            "reader_bytes": 0,
            "reader_messages": 0,
            "reader_payload_bytes": 0,
            "reader_max_payload_bytes": 0,
            "write_latencies_ms": [],
        }
        self._documents_lock = threading.RLock()
        self._opened_documents: Dict[str, int] = {}
        self._source_text_cache: OrderedDict[Tuple[str, int, int], str] = OrderedDict()
        self._source_lines_cache: OrderedDict[
            Tuple[str, int, int], List[str]
        ] = OrderedDict()
        self._masked_source_cache: OrderedDict[Tuple[str, int, int], str] = OrderedDict()
        self._function_pointer_name_cache: OrderedDict[
            Tuple[str, int, int], set[str]
        ] = OrderedDict()
        self._source_text_cache_lock = threading.RLock()
        self._derived_cache_lock = threading.RLock()
        self._source_text_cache_limit = 32
        self._base_publish_lock = threading.Lock()
        self._project_file_index_lock = threading.Lock()
        self._project_file_index: Optional[Dict[str, List[Path]]] = None

    # ── 生命周期 ──

    def start(self) -> bool:
        """启动 clangd 子进程并完成 LSP 握手。"""
        with self._lifecycle_lock:
            if self.is_healthy():
                return True
            if self.process is not None:
                self.stop()
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

                process = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(self.project_root),
                    bufsize=0,
                )
                outbound: queue.Queue[Optional[_OutboundMessage]] = queue.Queue(
                    maxsize=self._WRITER_QUEUE_LIMIT
                )
                with self._condition:
                    self.process = process
                    self._generation += 1
                    generation = self._generation
                    self._writer_queue = outbound
                    self._running = True
                    self._initialized = False
                    self._transport_closed = False
                    self._progress_tokens.clear()
                    self._file_status.clear()
                    self._last_progress_time = time.monotonic()
                    self._condition.notify_all()

                self._writer_thread = threading.Thread(
                    target=self._writer_loop,
                    args=(process, generation, outbound),
                    name="ClangWriter",
                    daemon=True,
                )
                self._reader_thread = threading.Thread(
                    target=self._read_loop,
                    args=(process, generation),
                    name="ClangReader",
                    daemon=True,
                )
                self._stderr_thread = threading.Thread(
                    target=self._stderr_loop,
                    args=(process, generation),
                    name="ClangStderr",
                    daemon=True,
                )
                self._writer_thread.start()
                self._reader_thread.start()
                self._stderr_thread.start()

                if not self._process_is_alive(process):
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
        with self._lifecycle_lock:
            process = self.process
            generation = self._generation
            outbound = self._writer_queue
            if process is not None and self._process_is_alive(process):
                try:
                    if self.is_healthy():
                        self.send_request("shutdown", None, timeout=1.0)
                    exit_item = self._enqueue_message(
                        {"jsonrpc": "2.0", "method": "exit"},
                        generation=generation,
                    )
                    if exit_item is not None:
                        exit_item.written.wait(timeout=0.2)
                except Exception:
                    pass

            self._signal_transport_closed(generation)
            if outbound is not None:
                try:
                    outbound.put_nowait(None)
                except queue.Full:
                    pass

            if process is not None:
                try:
                    process.terminate()
                except (AttributeError, OSError):
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        process.kill()
                    except (AttributeError, OSError):
                        pass
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass

            self._join_transport_threads()
            with self._condition:
                if generation == self._generation and self.process is process:
                    self.process = None
                    self._writer_queue = None
                self._condition.notify_all()
            with self._documents_lock:
                self._opened_documents.clear()

    @staticmethod
    def _process_is_alive(process: Any) -> bool:
        try:
            return process is not None and process.poll() is None
        except (AttributeError, OSError):
            return False

    def is_healthy(self) -> bool:
        """Return whether the current clangd generation completed initialization."""
        with self._condition:
            process = self.process
            return bool(
                process is not None
                and self._running
                and self._initialized
                and not self._transport_closed
                and self._process_is_alive(process)
            )

    def _join_transport_threads(self) -> None:
        current = threading.current_thread()
        for thread in (self._writer_thread, self._reader_thread, self._stderr_thread):
            if thread is None or thread is current:
                continue
            join = getattr(thread, "join", None)
            if callable(join):
                join(timeout=1)
        self._writer_thread = None
        self._reader_thread = None
        self._stderr_thread = None

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
                "symbolInfo": {},
                "ast": {},
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

    def send_request(self, method: str, params: Any, timeout: float = 120) -> Any:
        """发送 JSON-RPC 请求，在固定 monotonic deadline 内等待响应。"""
        started_at = time.monotonic()
        deadline = started_at + max(0.0, float(timeout))
        with self._condition:
            self._id_counter += 1
            msg_id = self._id_counter
            self._pending_requests[msg_id] = None
            self._pending_request_deadlines[msg_id] = deadline
            metrics = self._lsp_request_metrics.setdefault(
                method, {"count": 0, "timeouts": 0, "latencies_ms": []}
            )
            metrics["count"] += 1

        msg = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
        write_result = self._write_message(msg)
        if write_result is False:
            with self._condition:
                self._pending_requests.pop(msg_id, None)
                self._pending_request_deadlines.pop(msg_id, None)
                self._record_request_latency_locked(method, started_at, timed_out=False)
            self._record_thread_request_outcome(method, timed_out=False)
            logger.debug("LSP request '%s' could not be queued (id=%d)", method, msg_id)
            return None

        response: Optional[Dict[str, Any]] = None
        timed_out = False
        with self._condition:
            while True:
                now = time.monotonic()
                pending_response = self._pending_requests.get(msg_id)
                if pending_response is not None and now <= deadline:
                    response = pending_response
                    self._pending_requests.pop(msg_id, None)
                    self._pending_request_deadlines.pop(msg_id, None)
                    self._record_request_latency_locked(method, started_at, timed_out=False)
                    break
                remaining = deadline - now
                if remaining <= 0:
                    self._pending_requests.pop(msg_id, None)
                    self._pending_request_deadlines.pop(msg_id, None)
                    self._record_request_latency_locked(method, started_at, timed_out=True)
                    timed_out = True
                    break
                if self._transport_closed:
                    self._pending_requests.pop(msg_id, None)
                    self._pending_request_deadlines.pop(msg_id, None)
                    self._record_request_latency_locked(method, started_at, timed_out=False)
                    break
                self._condition.wait(timeout=remaining)

        if response is not None:
            self._record_thread_request_outcome(method, timed_out=False)
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
        self._record_thread_request_outcome(method, timed_out=timed_out)
        return None

    def _record_thread_request_outcome(self, method: str, *, timed_out: bool) -> None:
        self._request_outcome_local.last = (str(method), bool(timed_out))

    def _consume_thread_request_timeout(self, method: str) -> bool:
        outcome = getattr(self._request_outcome_local, "last", None)
        self._request_outcome_local.last = None
        return bool(
            isinstance(outcome, tuple)
            and len(outcome) == 2
            and str(outcome[0]) == str(method)
            and bool(outcome[1])
        )

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

    def send_notification(self, method: str, params: Any) -> bool:
        """发送 JSON-RPC 通知（无响应）。"""
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        return self._write_message(msg) is not False

    def _write_message(self, msg: dict) -> bool:
        """Queue an LSP message without letting a blocked pipe consume request timeout."""
        return self._enqueue_message(msg) is not None

    def _enqueue_message(
        self, msg: Dict[str, Any], *, generation: Optional[int] = None
    ) -> Optional[_OutboundMessage]:
        body = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        packet = header + body
        request_id = msg.get("id") if isinstance(msg.get("method"), str) else None
        with self._condition:
            current_generation = self._generation
            target_generation = current_generation if generation is None else generation
            process = self.process
            outbound = self._writer_queue
            if (
                target_generation != current_generation
                or self._transport_closed
                or outbound is None
                or process is None
                or getattr(process, "stdin", None) is None
                or not self._process_is_alive(process)
            ):
                self._transport_metrics["enqueue_failures"] += 1
                return None
            deadline = (
                self._pending_request_deadlines.get(request_id)
                if request_id is not None
                else None
            )
            item = _OutboundMessage(
                generation=target_generation,
                payload=packet,
                body_size=len(body),
                deadline=deadline,
                request_id=request_id,
            )
            try:
                outbound.put_nowait(item)
            except queue.Full:
                self._transport_metrics["enqueue_failures"] += 1
                return None
            self._transport_metrics["messages_enqueued"] += 1
            self._transport_metrics["payload_bytes_enqueued"] += len(body)
            self._transport_metrics["wire_bytes_enqueued"] += len(packet)
            self._transport_metrics["writer_queue_peak"] = max(
                self._transport_metrics["writer_queue_peak"], outbound.qsize()
            )
            return item

    def _writer_loop(
        self,
        process: Any,
        generation: int,
        outbound: queue.Queue[Optional[_OutboundMessage]],
    ) -> None:
        """Serialize writes for one process generation on a dedicated thread."""
        while True:
            item = outbound.get()
            try:
                if item is None:
                    return
                now = time.monotonic()
                with self._condition:
                    is_current = generation == self._generation and process is self.process
                    transport_closed = self._transport_closed
                    still_pending = (
                        item.request_id is None or item.request_id in self._pending_requests
                    )
                    if (
                        not is_current
                        or transport_closed
                        or not still_pending
                        or (item.deadline is not None and now >= item.deadline)
                    ):
                        if item.deadline is not None and now >= item.deadline:
                            self._transport_metrics["expired_before_write"] += 1
                        if not is_current or transport_closed:
                            return
                        continue

                stdin = getattr(process, "stdin", None)
                if stdin is None:
                    raise BrokenPipeError("clangd stdin is unavailable")
                view = memoryview(item.payload)
                offset = 0
                while offset < len(view):
                    written = stdin.write(view[offset:])
                    if written is None:
                        offset = len(view)
                    elif written <= 0:
                        raise BrokenPipeError("clangd stdin accepted no data")
                    else:
                        offset += int(written)
                stdin.flush()

                with self._condition:
                    self._transport_metrics["messages_written"] += 1
                    self._transport_metrics["payload_bytes_written"] += item.body_size
                    self._transport_metrics["wire_bytes_written"] += len(item.payload)
                    samples = self._transport_metrics["write_latencies_ms"]
                    samples.append(max(0.0, (time.monotonic() - item.enqueued_at) * 1000.0))
                    if len(samples) > self._REQUEST_LATENCY_SAMPLE_LIMIT:
                        del samples[: len(samples) - self._REQUEST_LATENCY_SAMPLE_LIMIT]
            except (BrokenPipeError, OSError, ValueError, AttributeError):
                with self._condition:
                    self._transport_metrics["write_failures"] += 1
                logger.error("Failed to write to clangd stdin")
                self._signal_transport_closed(generation)
                return
            finally:
                if item is not None:
                    item.written.set()
                outbound.task_done()

    def get_transport_metrics(self) -> Dict[str, Any]:
        """Return a snapshot of queue, payload, write, and reader transport metrics."""
        with self._condition:
            snapshot = {
                key: value
                for key, value in self._transport_metrics.items()
                if key != "write_latencies_ms"
            }
            samples = list(self._transport_metrics["write_latencies_ms"])
        ordered = sorted(float(value) for value in samples)
        snapshot["average_write_latency_ms"] = (
            sum(ordered) / len(ordered) if ordered else 0.0
        )
        p95_index = max(0, ((len(ordered) * 95 + 99) // 100) - 1)
        snapshot["p95_write_latency_ms"] = ordered[p95_index] if ordered else 0.0
        return snapshot

    # ── 消息读取 ──

    def _read_loop(
        self, process: Optional[Any] = None, generation: Optional[int] = None
    ) -> None:
        """后台线程：从 stdout 读取 JSON-RPC 消息。"""
        process = self.process if process is None else process
        generation = self._generation if generation is None else generation
        buf = bytearray()
        stdout = getattr(process, "stdout", None)
        if stdout is None:
            self._signal_transport_closed(generation)
            return
        fd = stdout.fileno()
        try:
            while True:
                with self._condition:
                    if generation != self._generation or not self._running:
                        break
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                buf.extend(chunk)
                with self._condition:
                    self._transport_metrics["reader_bytes"] += len(chunk)
                consumed = 0
                while consumed < len(buf):
                    # 解析 Content-Length 头
                    header_end = buf.find(b"\r\n\r\n", consumed)
                    if header_end == -1:
                        break
                    header = bytes(buf[consumed:header_end]).decode("ascii", errors="ignore")
                    match = re.search(r"Content-Length:\s*(\d+)", header)
                    if not match:
                        consumed = header_end + 4
                        continue
                    content_len = int(match.group(1))
                    body_start = header_end + 4
                    body_end = body_start + content_len
                    if len(buf) < body_end:
                        break  # 等待更多数据
                    body = bytes(buf[body_start:body_end])
                    consumed = body_end
                    with self._condition:
                        self._transport_metrics["reader_messages"] += 1
                        self._transport_metrics["reader_payload_bytes"] += content_len
                        self._transport_metrics["reader_max_payload_bytes"] = max(
                            self._transport_metrics["reader_max_payload_bytes"], content_len
                        )
                    try:
                        msg = json.loads(body)
                        self._dispatch_message(msg, generation=generation)
                    except json.JSONDecodeError:
                        logger.debug("Failed to parse LSP message")
                if consumed:
                    del buf[:consumed]
        except OSError:
            pass
        finally:
            self._signal_transport_closed(generation)

    def _dispatch_message(self, msg: dict, *, generation: Optional[int] = None) -> None:
        """分发收到的 LSP 消息。"""
        if generation is not None:
            with self._condition:
                if generation != self._generation:
                    return
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
        method = msg.get("method")
        params = msg.get("params")
        if method == "textDocument/clangd.fileStatus":
            if not isinstance(params, dict):
                return
            uri = params.get("uri")
            state = params.get("state")
            if not isinstance(uri, str) or not isinstance(state, str):
                return
            with self._condition:
                self._file_status[uri] = (state, time.monotonic())
                self._condition.notify_all()
            return
        if method != "$/progress":
            return
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

    def _signal_transport_closed(self, generation: Optional[int] = None) -> None:
        outbound: Optional[queue.Queue[Optional[_OutboundMessage]]]
        with self._condition:
            if generation is not None and generation != self._generation:
                return
            self._running = False
            self._initialized = False
            self._transport_closed = True
            outbound = self._writer_queue
            self._condition.notify_all()
        if outbound is not None:
            try:
                outbound.put_nowait(None)
            except queue.Full:
                pass

    def _has_active_progress_locked(self) -> bool:
        return any(status in {"begin", "report"} for status in self._progress_tokens.values())

    def _stderr_loop(
        self, process: Optional[Any] = None, generation: Optional[int] = None
    ) -> None:
        """后台线程：读取 clangd stderr 日志。"""
        process = self.process if process is None else process
        generation = self._generation if generation is None else generation
        stderr = getattr(process, "stderr", None)
        while stderr is not None:
            with self._condition:
                if generation != self._generation or not self._running:
                    break
            try:
                line = stderr.readline()
                if not line:
                    break
                text = ANSI_ESCAPE.sub("", line.decode("utf-8", errors="ignore")).strip()
                if text and "Indexing" in text:
                    with self._condition:
                        if generation != self._generation:
                            break
                        self._last_progress_time = time.monotonic()
                        self._condition.notify_all()
                    logger.debug("clangd: %s", text)
            except OSError:
                break

    # ── 文档管理 ──

    def open_document(self, file_path: Path) -> bool:
        file_path = Path(file_path).resolve()
        uri = file_path.as_uri()
        with self._documents_lock:
            lease_count = self._opened_documents.get(uri, 0)
            if lease_count:
                self._opened_documents[uri] = lease_count + 1
                return True
            text = self._read_source_text(file_path)
            if text is None:
                return False
            lang = "c" if file_path.suffix in (".c", ".h") else "cpp"
            with self._condition:
                self._file_status.pop(uri, None)
            sent = self.send_notification(
                "textDocument/didOpen",
                {
                    "textDocument": {
                        "uri": uri,
                        "languageId": lang,
                        "version": 1,
                        "text": text,
                    }
                },
            )
            if sent is False:
                return False
            self._opened_documents[uri] = 1
            return True

    def close_document(self, file_path: Path) -> None:
        uri = Path(file_path).resolve().as_uri()
        with self._documents_lock:
            lease_count = self._opened_documents.get(uri, 0)
            if lease_count <= 0:
                return
            if lease_count > 1:
                self._opened_documents[uri] = lease_count - 1
                return
            self.send_notification("textDocument/didClose", {"textDocument": {"uri": uri}})
            self._opened_documents.pop(uri, None)

    def notify_files_deleted(self, file_paths: List[Path]) -> None:
        changes = []
        for file_path in file_paths:
            try:
                uri = Path(file_path).resolve().as_uri()
            except ValueError:
                continue
            with self._documents_lock:
                if self._opened_documents.pop(uri, 0):
                    self.send_notification(
                        "textDocument/didClose", {"textDocument": {"uri": uri}}
                    )
            changes.append({"uri": uri, "type": 3})
        if changes:
            self.send_notification("workspace/didChangeWatchedFiles", {"changes": changes})

    def get_file_status(self, file_path: Path) -> Optional[str]:
        """Return clangd's latest extension status for a file, when available."""
        uri = Path(file_path).resolve().as_uri()
        with self._condition:
            value = self._file_status.get(uri)
            return value[0] if value is not None else None

    def wait_for_file_idle(
        self,
        file_path: Path,
        timeout: float = 0.3,
        *,
        require_notification: bool = False,
    ) -> bool:
        """Wait for clangd fileStatus=idle without penalizing servers lacking the extension."""
        uri = Path(file_path).resolve().as_uri()
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._condition:
            while True:
                status = self._file_status.get(uri)
                if status is None and not require_notification:
                    return True
                if status is not None and status[0].lower() == "idle":
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self._transport_closed:
                    return False
                self._condition.wait(timeout=remaining)

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

    def get_ast(
        self, file_path: Path, range_info: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict]:
        """Query clangd's AST extension without coupling it to extraction policy."""
        params: Dict[str, Any] = {
            "textDocument": {"uri": Path(file_path).resolve().as_uri()}
        }
        if range_info is not None:
            params["range"] = range_info
        result = self.send_request("textDocument/ast", params, timeout=60)
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

    def _lsp_range_to_python(
        self, file_path: Path, range_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Convert an LSP range into Python string offsets using negotiated encoding."""
        source_lines = self._read_source_lines(file_path)
        converted: Dict[str, Any] = dict(range_info)
        for endpoint in ("start", "end"):
            raw_position = range_info.get(endpoint)
            if not isinstance(raw_position, dict):
                continue
            position = dict(raw_position)
            try:
                line = int(position.get("line", 0))
                character = int(position.get("character", 0))
            except (TypeError, ValueError):
                continue
            if source_lines is not None and 0 <= line < len(source_lines):
                position["character"] = self._lsp_offset_to_python_in_text(
                    source_lines[line], character
                )
            else:
                position["character"] = max(0, character)
            converted[endpoint] = position
        return converted

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
        facts = self._collect_tu_facts(file_path, db, tu_id)
        if facts is None:
            return False

        publish_lock = getattr(self, "_base_publish_lock", None)
        if publish_lock is None:
            publish_lock = threading.Lock()
            self._base_publish_lock = publish_lock
        with publish_lock:
            self._publish_tu_facts(db, tu_id, **facts)

        if progress_cb:
            progress_cb(Path(file_path).resolve())
        return True

    def _collect_tu_facts(
        self,
        file_path: Path,
        db: KnowledgeDB,
        tu_id: int,
        *,
        defer_call_queries: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Collect one TU without starting a SQLite write transaction."""
        file_path = Path(file_path).resolve()
        if not self.open_document(file_path):
            logger.warning("Failed to open document: %s", file_path)
            return None
        call_work: List[Tuple[Any, ...]] = []
        collection_complete = False
        try:
            # documentSymbol is itself an AST-dependent request.  clangd queues it
            # behind didOpen processing, so a fixed per-file sleep only adds latency.
            symbols = self.get_document_symbols(file_path)
            if symbols is None:
                logger.debug("No symbols returned for %s", file_path)
                return None

            rel_path = self._project_relative_path(file_path)
            func_rows: List[Tuple[Any, ...]] = []
            call_rows: List[Tuple[Any, ...]] = []
            type_rows: List[Dict[str, Any]] = []
            global_rows: List[Dict[str, Any]] = []
            macro_rows = self._extract_macros(file_path, rel_path)
            include_rows = self._collect_includes(file_path, rel_path)

            for sym in symbols:
                self._process_symbol(
                    sym,
                    file_path,
                    rel_path,
                    tu_id,
                    db,
                    func_rows,
                    call_rows,
                    deferred_types=type_rows,
                    deferred_globals=global_rows,
                    deferred_call_work=call_work,
                )
            collection_complete = True
        finally:
            if not (collection_complete and defer_call_queries and call_work):
                self.close_document(file_path)

        local_function_names: set[str] = set()
        if file_path.suffix.lower() == ".c":
            counts: Dict[str, int] = {}
            for row in func_rows:
                if bool(row[7]):
                    continue
                local_name = str(row[0]).split("::")[-1]
                counts[local_name] = counts.get(local_name, 0) + 1
            local_function_names = {name for name, count in counts.items() if count == 1}
        call_work = [(*work, local_function_names) for work in call_work]
        if not defer_call_queries:
            for work in call_work:
                call_rows.extend(self._extract_deferred_call_edges(work))
            call_work = []

        facts: Dict[str, Any] = {
            "func_rows": func_rows,
            "call_rows": call_rows,
            "type_rows": type_rows,
            "global_rows": global_rows,
            "macro_rows": macro_rows,
            "include_rows": include_rows,
        }
        if call_work:
            facts["_call_work"] = call_work
            facts["_deferred_document_path"] = file_path
        return facts

    @staticmethod
    def _publish_tu_facts(
        db: KnowledgeDB,
        tu_id: int,
        *,
        func_rows: List[Tuple[Any, ...]],
        call_rows: List[Tuple[Any, ...]],
        type_rows: List[Dict[str, Any]],
        global_rows: List[Dict[str, Any]],
        macro_rows: List[Tuple[Any, ...]],
        include_rows: List[Tuple[Any, ...]],
    ) -> None:
        """Publish one completely collected TU through a single DB writer."""

        def write_rows() -> None:
            if func_rows:
                db.insert_functions_batch(func_rows)
            if call_rows:
                db.insert_call_edges_batch(call_rows)
            insert_macros = getattr(db, "insert_macro_definitions_batch", None)
            if macro_rows and callable(insert_macros):
                insert_macros(macro_rows)
            insert_includes = getattr(db, "insert_include_edges_batch", None)
            if include_rows and callable(insert_includes):
                insert_includes(include_rows)
            insert_types_batch = getattr(db, "insert_types_with_members_batch", None)
            if type_rows and callable(insert_types_batch):
                insert_types_batch(
                    [
                        (
                            str(type_row["name"]),
                            str(type_row["kind"]),
                            str(type_row["file_path"]),
                            int(type_row["start_line"]),
                            int(type_row["end_line"]),
                            str(type_row.get("full_definition") or ""),
                            list(type_row.get("members", [])),
                        )
                        for type_row in type_rows
                    ],
                    tu_id,
                )
            else:
                for type_row in type_rows:
                    type_id = db.insert_type(
                        str(type_row["name"]),
                        str(type_row["kind"]),
                        str(type_row["file_path"]),
                        int(type_row["start_line"]),
                        int(type_row["end_line"]),
                        full_definition=str(type_row.get("full_definition") or ""),
                        tu_id=tu_id,
                    )
                    for member_name, member_type, offset_idx in type_row.get("members", []):
                        db.insert_type_member(type_id, member_name, member_type, offset_idx)
            insert_global = getattr(db, "insert_global_variable", None)
            insert_globals_batch = getattr(db, "insert_global_variables_batch", None)
            if global_rows and callable(insert_globals_batch):
                insert_globals_batch(
                    [
                        (
                            str(global_row["name"]),
                            str(global_row["detail"]),
                            str(global_row["file_path"]),
                            int(global_row["line"]),
                            int(bool(global_row["metadata"].get("is_extern"))),
                            str(global_row["metadata"].get("storage_class") or "unknown"),
                            str(global_row["metadata"].get("qualifiers") or ""),
                            str(global_row["metadata"].get("initializer") or ""),
                            str(
                                global_row["metadata"].get("definition_kind")
                                or "unknown"
                            ),
                        )
                        for global_row in global_rows
                    ]
                )
            elif callable(insert_global):
                for global_row in global_rows:
                    metadata = dict(global_row["metadata"])
                    insert_global(
                        str(global_row["name"]),
                        str(global_row["detail"]),
                        str(global_row["file_path"]),
                        int(global_row["line"]),
                        **metadata,
                    )

        replacement = getattr(db, "replace_tu_facts_transaction", None)
        if callable(replacement):
            with replacement(tu_id):
                write_rows()
            return

        # Compatibility for lightweight test doubles and external KnowledgeDB-like
        # implementations.  The real KnowledgeDB always takes the atomic path above.
        purge = getattr(db, "purge_tu_data", None)
        if callable(purge):
            purge(tu_id)
        write_rows()
        mark_indexed = getattr(db, "mark_tu_indexed", None)
        if callable(mark_indexed):
            mark_indexed(tu_id)

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
        *,
        deferred_types: Optional[List[Dict[str, Any]]] = None,
        deferred_globals: Optional[List[Dict[str, Any]]] = None,
        deferred_call_work: Optional[List[Tuple[Any, ...]]] = None,
    ):
        """递归处理单个 LSP DocumentSymbol 节点。"""
        scope = list(scope or [])
        kind = sym.get("kind", 0)
        name = sym.get("name", "")
        range_info = sym.get("range", sym.get("location", {}).get("range", {}))
        if not isinstance(range_info, dict):
            range_info = {}
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
                if deferred_call_work is not None:
                    deferred_call_work.append(
                        (file_path, stored_name, rel_path, start_line, end_line, sym)
                    )
                else:
                    self._extract_call_edges(
                        file_path,
                        stored_name,
                        rel_path,
                        start_line,
                        end_line,
                        call_rows,
                        sym,
                    )

        elif kind in (self.SK_STRUCT, self.SK_CLASS, self.SK_ENUM):
            full_definition = self._source_range_text(file_path, range_info)
            kind_str = self._source_type_kind(
                full_definition,
                kind,
            )
            members = [
                (child.get("name", ""), child.get("detail", ""), idx)
                for idx, child in enumerate(sym.get("children", []))
                if child.get("name", "")
            ]
            if deferred_types is not None:
                deferred_types.append(
                    {
                        "name": name,
                        "kind": kind_str,
                        "file_path": rel_path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "full_definition": full_definition,
                        "members": members,
                    }
                )
            else:
                type_id = db.insert_type(
                    name,
                    kind_str,
                    rel_path,
                    start_line,
                    end_line,
                    full_definition=full_definition,
                    tu_id=tu_id,
                )
                for child_name, child_detail, idx in members:
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
            if deferred_globals is not None:
                deferred_globals.append(
                    {
                        "name": name,
                        "detail": detail,
                        "file_path": rel_path,
                        "line": start_line,
                        "metadata": metadata,
                    }
                )
            elif callable(insert_global):
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
                deferred_types=deferred_types,
                deferred_globals=deferred_globals,
                deferred_call_work=deferred_call_work,
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

        range_info = self._lsp_range_to_python(file_path, range_info)
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

    def _collect_includes(self, file_path: Path, rel_path: str) -> List[Tuple[Any, ...]]:
        """Collect include edges without holding a SQLite write transaction."""
        lines = self._read_source_lines(file_path)
        if lines is None:
            return []
        rows: List[Tuple[Any, ...]] = []
        for line_no, line in enumerate(lines, 1):
            match = re.match(r'\s*#\s*include\s+([<"])([^>"]+)[>"]', line)
            if not match:
                continue
            is_system = 1 if match.group(1) == "<" else 0
            included = match.group(2)
            if not is_system:
                included = self._canonical_included_file(file_path, included)
            rows.append((rel_path, included, line_no, is_system))
        return rows

    def _extract_includes(self, file_path: Path, rel_path: str, db: KnowledgeDB):
        """Compatibility wrapper that writes collected include edges in one batch."""
        rows = self._collect_includes(file_path, rel_path)
        if not rows:
            return
        insert_batch = getattr(db, "insert_include_edges_batch", None)
        if callable(insert_batch):
            insert_batch(rows)
            return
        db._conn.executemany(
            "INSERT OR IGNORE INTO include_edges "
            "(source_file, included_file, line, is_system) VALUES (?, ?, ?, ?)",
            rows,
        )

    def seed_project_file_index(self, file_paths: List[Path]) -> None:
        """Reuse the backend's source walk for quoted-include suffix resolution."""
        path_index: Dict[str, List[Path]] = {}
        for file_path in file_paths:
            try:
                resolved = Path(file_path).resolve()
            except OSError:
                continue
            if resolved.is_file():
                path_index.setdefault(resolved.name, []).append(resolved)
        for paths in path_index.values():
            paths.sort()
        with self._project_file_index_lock:
            self._project_file_index = path_index

    def _canonical_included_file(self, source_file: Path, included: str) -> str:
        clean = str(included or "").replace("\\", "/").strip()
        local_candidate = (source_file.parent / clean).resolve()
        root_candidate = (self.project_root / clean).resolve()
        candidates = [path for path in (local_candidate, root_candidate) if path.exists()]
        if not candidates and clean:
            suffix_parts = Path(clean).parts
            with self._project_file_index_lock:
                path_index = self._project_file_index
                if not isinstance(path_index, dict):
                    path_index = {}
                    for project_path in self.project_root.rglob("*"):
                        if project_path.is_file():
                            resolved = project_path.resolve()
                            path_index.setdefault(resolved.name, []).append(resolved)
                    self._project_file_index = path_index
                basename_candidates = list(path_index.get(Path(clean).name, []))
            candidates = [
                path
                for path in basename_candidates
                if tuple(path.parts[-len(suffix_parts) :]) == suffix_parts
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

    _DERIVED_FILE_WORKER_CAP = 8
    _DERIVED_ADDITIVE_STAT_KEYS = (
        "files_processed",
        "files_skipped_no_candidates",
        "functions_processed",
        "candidates",
        "filtered_local_shadow",
        "filtered_field",
        "filtered_non_call_macro",
        "semantic_requests",
        "semantic_resolved",
        "local_resolved",
        "symbol_info_requests",
        "canonical_groups",
        "references_requests",
        "references_resolved",
        "reference_cache_evictions",
        "definition_requests",
        "definition_timeouts",
    )

    @staticmethod
    def _new_derived_resolution_caches() -> Dict[str, Any]:
        """Create caches shared by every file in one derived-index rebuild."""
        return {
            "_resolution_lock": threading.RLock(),
            "_candidate_canonical_cache_inflight": {},
            "_canonical_group_cache_inflight": {},
            "_declaration_char_cache_inflight": {},
            "_visibility_cache_inflight": {},
            "_reference_cache_inflight": {},
            "reference_cache": OrderedDict(),
            "reference_coordinate_index": {},
            "reference_indexed_keys": set(),
            "candidate_canonical_cache": {},
            "canonical_group_cache": {},
            "declaration_char_cache": {},
            "visibility_cache": {},
        }

    def _derived_worker_count(self, file_count: int) -> int:
        if file_count <= 0:
            return 0
        return min(
            max(1, int(self.max_threads or 1)),
            self._DERIVED_FILE_WORKER_CAP,
            int(file_count),
        )

    def _new_derived_worker_stats(self, index_name: str) -> Dict[str, Any]:
        stats = self._new_derived_stats(index_name, 0, 0)
        stats["_suppress_progress"] = True
        return stats

    @classmethod
    def _merge_derived_stats(
        cls,
        target: Dict[str, Any],
        delta: Dict[str, Any],
    ) -> None:
        for key in cls._DERIVED_ADDITIVE_STAT_KEYS:
            target[key] = int(target.get(key) or 0) + int(delta.get(key) or 0)

        target_reasons = target.setdefault("unresolved_reasons", {})
        for reason, count in dict(delta.get("unresolved_reasons") or {}).items():
            clean_reason = str(reason)
            target_reasons[clean_reason] = int(target_reasons.get(clean_reason) or 0) + int(count)

        samples = list(target.get("unresolved_samples") or [])
        samples.extend(list(delta.get("unresolved_samples") or []))
        samples.sort(key=lambda sample: json.dumps(sample, sort_keys=True, default=str))
        target["unresolved_samples"] = samples[:10]

        target["_definition_latency_sum_ms"] = float(
            target.get("_definition_latency_sum_ms") or 0.0
        ) + float(delta.get("_definition_latency_sum_ms") or 0.0)
        target["_definition_latency_count"] = int(
            target.get("_definition_latency_count") or 0
        ) + int(delta.get("_definition_latency_count") or 0)
        latencies = list(target.get("_definition_latencies_ms") or [])
        latencies.extend(float(value) for value in delta.get("_definition_latencies_ms", []))
        latencies.sort()
        if len(latencies) > 4096:
            last = len(latencies) - 1
            latencies = [latencies[(index * last) // 4095] for index in range(4096)]
        target["_definition_latencies_ms"] = latencies

    def _run_derived_file_jobs(
        self,
        work_items: List[Tuple[str, List[Dict[str, Any]]]],
        worker: Callable[[Tuple[str, List[Dict[str, Any]]]], _DerivedFileResult],
        consume: Callable[[_DerivedFileResult], None],
        metrics: Dict[str, int],
    ) -> None:
        """Run bounded file jobs while keeping result consumption on the caller thread."""
        worker_count = self._derived_worker_count(len(work_items))
        metrics["worker_count"] = worker_count
        metrics["peak_inflight_files"] = 0
        if not work_items:
            return
        if worker_count <= 1:
            metrics["peak_inflight_files"] = 1
            for item in work_items:
                consume(worker(item))
            return

        active = 0
        active_lock = threading.Lock()

        def tracked_worker(
            item: Tuple[str, List[Dict[str, Any]]],
        ) -> _DerivedFileResult:
            nonlocal active
            with active_lock:
                active += 1
                metrics["peak_inflight_files"] = max(
                    int(metrics.get("peak_inflight_files") or 0),
                    active,
                )
            try:
                return worker(item)
            finally:
                with active_lock:
                    active -= 1

        iterator = iter(enumerate(work_items))
        pending: Dict[Future[_DerivedFileResult], int] = {}
        max_pending = max(worker_count, worker_count * 2)
        with ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="ClangDerived",
        ) as executor:

            def submit_next() -> bool:
                try:
                    ordinal, item = next(iterator)
                except StopIteration:
                    return False
                pending[executor.submit(tracked_worker, item)] = ordinal
                return True

            for _ in range(min(max_pending, len(work_items))):
                submit_next()
            try:
                while pending:
                    completed, _remaining = wait(
                        tuple(pending),
                        return_when=FIRST_COMPLETED,
                    )
                    for future in sorted(completed, key=lambda item: pending[item]):
                        pending.pop(future)
                        result = future.result()
                        submit_next()
                        consume(result)
            except BaseException:
                for future in pending:
                    future.cancel()
                raise

    @staticmethod
    def _resolution_cache_lock(
        semantic_context: Dict[str, Any],
    ) -> Optional[Any]:
        lock = semantic_context.get("_resolution_lock")
        return lock if hasattr(lock, "acquire") else None

    def _shared_resolution_cache_get_or_compute(
        self,
        semantic_context: Dict[str, Any],
        cache_name: str,
        key: Any,
        compute: Callable[[], Any],
    ) -> Any:
        """Memoize shared derived facts with per-key single-flight semantics."""
        cache = semantic_context.setdefault(cache_name, {})
        lock = self._resolution_cache_lock(semantic_context)
        if lock is None:
            if key not in cache:
                cache[key] = compute()
            return cache[key]

        inflight_name = f"_{cache_name}_inflight"
        with lock:
            if key in cache:
                return cache[key]
            inflight = semantic_context.setdefault(inflight_name, {})
            future = inflight.get(key)
            owner = not isinstance(future, Future)
            if owner:
                future = Future()
                inflight[key] = future
        assert isinstance(future, Future)
        if not owner:
            return future.result()

        try:
            value = compute()
        except BaseException as exc:
            future.set_exception(exc)
            with lock:
                semantic_context.setdefault(inflight_name, {}).pop(key, None)
            raise
        with lock:
            cache[key] = value
            semantic_context.setdefault(inflight_name, {}).pop(key, None)
        future.set_result(value)
        return value

    def rebuild_function_symbol_refs(
        self,
        db: KnowledgeDB,
        *,
        use_staging: bool = False,
        only_files: Optional[Set[str]] = None,
    ) -> int:
        get_functions = getattr(db, "get_function_records", None)
        get_globals = getattr(db, "get_global_variables", None)
        get_macros = getattr(db, "get_macro_definition_records", None)
        if not callable(get_macros):
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
        if only_files is not None:
            functions = [
                row
                for row in functions
                if str(row.get("file_path") or "") in only_files
            ]
        globals_by_name = self._records_by_name(get_globals())
        macros_by_name = self._records_by_name(get_macros())
        indexed_symbol_names = set(globals_by_name).union(macros_by_name)
        aggregated: Dict[Tuple[str, str, str, str, str, int], str] = {}
        macro_refs: set[Tuple[int, int, int]] = set()

        functions_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for function in functions:
            functions_by_file.setdefault(str(function.get("file_path") or ""), []).append(function)
        include_closures = self._load_include_closures(db, list(functions_by_file))
        shared_resolution_caches = self._new_derived_resolution_caches()
        stats = self._new_derived_stats(
            "function_symbol_context",
            len(functions_by_file),
            len(functions),
        )
        work_items = sorted(functions_by_file.items())
        worker_metrics = {
            "worker_count": self._derived_worker_count(len(work_items)),
            "peak_inflight_files": 0,
        }
        stats.update(worker_metrics)
        logger.info(
            "[symbol-context] rebuild started files=%d functions=%d workers=%d",
            len(functions_by_file),
            len(functions),
            worker_metrics["worker_count"],
        )
        self._store_derived_stats_snapshot(stats)
        staged_count = 0
        index_name = "function_symbol_context"

        def worker(
            item: Tuple[str, List[Dict[str, Any]]],
        ) -> _DerivedFileResult:
            function_file, file_functions = item
            local_stats = self._new_derived_worker_stats(index_name)
            source_path = self._resolve_indexed_source_path(function_file)
            lines = self._read_source_lines(source_path)
            if not lines:
                local_stats["functions_processed"] = len(file_functions)
                local_stats["files_processed"] = 1
                return _DerivedFileResult(stats_by_index={index_name: local_stats})
            if not self._functions_contain_candidate_identifiers(
                file_functions,
                lines,
                indexed_symbol_names,
            ):
                local_stats["functions_processed"] = len(file_functions)
                local_stats["files_skipped_no_candidates"] = 1
                local_stats["files_processed"] = 1
                return _DerivedFileResult(stats_by_index={index_name: local_stats})
            document_opened = False
            try:
                document_opened = bool(self.open_document(source_path))
            except Exception:
                document_opened = False

            file_aggregated: Dict[Tuple[str, str, str, str, str, int], str] = {}
            file_macro_refs: set[Tuple[int, int, int]] = set()
            semantic_context = dict(
                self._get_file_semantic_context(
                    source_path,
                    lines,
                    enabled=document_opened,
                    stats=local_stats,
                )
            )
            semantic_context.update(shared_resolution_caches)
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
                        local_stats,
                    )
                    local_stats["functions_processed"] += 1
            finally:
                if document_opened:
                    try:
                        self.close_document(source_path)
                    except Exception:
                        pass
            local_stats["files_processed"] = 1
            file_rows = [(*key, access) for key, access in sorted(file_aggregated.items())]
            return _DerivedFileResult(
                stats_by_index={index_name: local_stats},
                symbol_rows=file_rows,
                macro_rows=sorted(file_macro_refs),
            )

        def consume(result: _DerivedFileResult) -> None:
            nonlocal staged_count
            self._merge_derived_stats(stats, result.stats_by_index[index_name])
            stats["peak_inflight_files"] = int(
                worker_metrics.get("peak_inflight_files") or 0
            )
            if use_staging:
                assert callable(stage_refs)
                assert callable(stage_macro_refs)
                for offset in range(0, len(result.symbol_rows), 1000):
                    stage_refs(result.symbol_rows[offset : offset + 1000])
                for offset in range(0, len(result.macro_rows), 1000):
                    stage_macro_refs(result.macro_rows[offset : offset + 1000])
                staged_count += len(result.symbol_rows) + len(result.macro_rows)
            else:
                for *raw_key, access in result.symbol_rows:
                    key = cast(
                        Tuple[str, str, str, str, str, int],
                        tuple(raw_key),
                    )
                    aggregated[key] = self._merge_access_kind(
                        aggregated.get(key, "unknown"),
                        str(access),
                    )
                macro_refs.update(result.macro_rows)
            self._log_derived_progress(stats)

        self._run_derived_file_jobs(
            work_items,
            worker,
            consume,
            worker_metrics,
        )
        stats.update(worker_metrics)

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
        only_files: Optional[Set[str]] = None,
    ) -> int:
        """Rebuild direct function type references after all TU facts are current."""
        get_functions = getattr(db, "get_function_records", None)
        get_types = getattr(db, "get_type_definition_records", None)
        if not callable(get_types):
            get_types = getattr(db, "get_all_type_definitions", None)
        replace_refs = getattr(db, "replace_function_type_refs", None)
        stage_refs = getattr(db, "stage_function_type_refs_batch", None)
        required_methods = [get_functions, get_types, stage_refs if use_staging else replace_refs]
        if not all(callable(method) for method in required_methods):
            return 0
        assert callable(get_functions)
        assert callable(get_types)

        functions = [row for row in get_functions() if not row.get("is_declaration")]
        if only_files is not None:
            functions = [
                row
                for row in functions
                if str(row.get("file_path") or "") in only_files
            ]
        type_records = list(get_types())
        types_by_name = self._records_by_name(type_records)
        indexed_type_names = set(types_by_name)
        rows: List[Tuple[Any, ...]] = []
        functions_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for function in functions:
            functions_by_file.setdefault(str(function.get("file_path") or ""), []).append(function)
        include_closures = self._load_include_closures(db, list(functions_by_file))
        shared_resolution_caches = self._new_derived_resolution_caches()
        stats = self._new_derived_stats(
            "function_type_refs",
            len(functions_by_file),
            len(functions),
        )
        work_items = sorted(functions_by_file.items())
        worker_metrics = {
            "worker_count": self._derived_worker_count(len(work_items)),
            "peak_inflight_files": 0,
        }
        stats.update(worker_metrics)
        logger.info(
            "[type-context] rebuild started files=%d functions=%d workers=%d",
            len(functions_by_file),
            len(functions),
            worker_metrics["worker_count"],
        )
        self._store_derived_stats_snapshot(stats)
        staged_count = 0
        index_name = "function_type_refs"

        def worker(
            item: Tuple[str, List[Dict[str, Any]]],
        ) -> _DerivedFileResult:
            function_file, file_functions = item
            local_stats = self._new_derived_worker_stats(index_name)
            source_path = self._resolve_indexed_source_path(function_file)
            lines = self._read_source_lines(source_path)
            if not lines:
                local_stats["functions_processed"] = len(file_functions)
                local_stats["files_processed"] = 1
                return _DerivedFileResult(stats_by_index={index_name: local_stats})
            if not self._functions_contain_candidate_identifiers(
                file_functions,
                lines,
                indexed_type_names,
            ):
                local_stats["functions_processed"] = len(file_functions)
                local_stats["files_skipped_no_candidates"] = 1
                local_stats["files_processed"] = 1
                return _DerivedFileResult(stats_by_index={index_name: local_stats})
            document_opened = False
            try:
                document_opened = bool(self.open_document(source_path))
            except Exception:
                document_opened = False
            semantic_context = dict(
                self._get_file_semantic_context(
                    source_path,
                    lines,
                    enabled=document_opened,
                    stats=local_stats,
                )
            )
            semantic_context.update(shared_resolution_caches)
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
                            indexed_type_names,
                            include_closure,
                            semantic_context,
                            local_stats,
                        )
                    )
                    local_stats["functions_processed"] += 1
            finally:
                if document_opened:
                    try:
                        self.close_document(source_path)
                    except Exception:
                        pass

            deduplicated_file_rows = sorted(
                set(file_rows), key=lambda row: tuple(str(value) for value in row)
            )
            local_stats["files_processed"] = 1
            return _DerivedFileResult(
                stats_by_index={index_name: local_stats},
                type_rows=deduplicated_file_rows,
            )

        def consume(result: _DerivedFileResult) -> None:
            nonlocal staged_count
            self._merge_derived_stats(stats, result.stats_by_index[index_name])
            stats["peak_inflight_files"] = int(
                worker_metrics.get("peak_inflight_files") or 0
            )
            if use_staging:
                assert callable(stage_refs)
                for offset in range(0, len(result.type_rows), 1000):
                    stage_refs(result.type_rows[offset : offset + 1000])
                staged_count += len(result.type_rows)
            else:
                rows.extend(result.type_rows)
            self._log_derived_progress(stats)

        self._run_derived_file_jobs(
            work_items,
            worker,
            consume,
            worker_metrics,
        )
        stats.update(worker_metrics)

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

    def rebuild_function_derived_refs(
        self,
        db: KnowledgeDB,
        *,
        use_staging: bool = False,
        only_files: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Rebuild symbol and type references in one file-major semantic pass."""
        symbol_index = "function_symbol_context"
        type_index = "function_type_refs"
        if not use_staging:
            raise ValueError("combined derived rebuild requires staging")

        get_functions = getattr(db, "get_function_records", None)
        get_globals = getattr(db, "get_global_variables", None)
        get_macros = getattr(db, "get_macro_definition_records", None)
        if not callable(get_macros):
            get_macros = getattr(db, "get_all_macro_definitions", None)
        get_types = getattr(db, "get_type_definition_records", None)
        if not callable(get_types):
            get_types = getattr(db, "get_all_type_definitions", None)
        stage_symbols = getattr(db, "stage_function_symbol_refs_batch", None)
        stage_macros = getattr(db, "stage_function_macro_refs_batch", None)
        stage_types = getattr(db, "stage_function_type_refs_batch", None)
        required = (
            get_functions,
            get_globals,
            get_macros,
            get_types,
            stage_symbols,
            stage_macros,
            stage_types,
        )
        if not all(callable(method) for method in required):
            raise RuntimeError("KnowledgeDB does not support combined derived staging")
        assert callable(get_functions)
        assert callable(get_globals)
        assert callable(get_macros)
        assert callable(get_types)
        assert callable(stage_symbols)
        assert callable(stage_macros)
        assert callable(stage_types)

        functions = [row for row in get_functions() if not row.get("is_declaration")]
        if only_files is not None:
            functions = [
                row
                for row in functions
                if str(row.get("file_path") or "") in only_files
            ]
        functions_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for function in functions:
            functions_by_file.setdefault(str(function.get("file_path") or ""), []).append(
                function
            )
        globals_by_name = self._records_by_name(get_globals())
        macros_by_name = self._records_by_name(get_macros())
        types_by_name = self._records_by_name(list(get_types()))
        indexed_symbol_names = set(globals_by_name).union(macros_by_name)
        indexed_type_names = set(types_by_name)
        include_closures = self._load_include_closures(db, list(functions_by_file))
        shared_resolution_caches = self._new_derived_resolution_caches()
        stats_by_index = {
            symbol_index: self._new_derived_stats(
                symbol_index,
                len(functions_by_file),
                len(functions),
            ),
            type_index: self._new_derived_stats(
                type_index,
                len(functions_by_file),
                len(functions),
            ),
        }
        work_items = sorted(functions_by_file.items())
        worker_metrics = {
            "worker_count": self._derived_worker_count(len(work_items)),
            "peak_inflight_files": 0,
        }
        for stats in stats_by_index.values():
            stats.update(worker_metrics)
            self._store_derived_stats_snapshot(stats)
        counts = {symbol_index: 0, type_index: 0}
        errors: Dict[str, Exception] = {}
        stop_events = {
            symbol_index: threading.Event(),
            type_index: threading.Event(),
        }

        logger.info(
            "[derived-context] combined rebuild started files=%d functions=%d workers=%d",
            len(functions_by_file),
            len(functions),
            worker_metrics["worker_count"],
        )

        def worker(
            item: Tuple[str, List[Dict[str, Any]]],
        ) -> _DerivedFileResult:
            function_file, file_functions = item
            local_stats_by_index = {
                symbol_index: self._new_derived_worker_stats(symbol_index),
                type_index: self._new_derived_worker_stats(type_index),
            }
            local_errors: Dict[str, Exception] = {}
            source_path = self._resolve_indexed_source_path(function_file)
            lines = self._read_source_lines(source_path)
            if not lines:
                for local_stats in local_stats_by_index.values():
                    local_stats["files_processed"] = 1
                    local_stats["functions_processed"] = len(file_functions)
                return _DerivedFileResult(stats_by_index=local_stats_by_index)

            symbol_active = not stop_events[symbol_index].is_set()
            type_active = not stop_events[type_index].is_set()
            symbol_needed = symbol_active and self._functions_contain_candidate_identifiers(
                file_functions, lines, indexed_symbol_names
            )
            type_needed = type_active and self._functions_contain_candidate_identifiers(
                file_functions, lines, indexed_type_names
            )
            if symbol_active and not symbol_needed:
                local_stats_by_index[symbol_index]["files_skipped_no_candidates"] = 1
            if type_active and not type_needed:
                local_stats_by_index[type_index]["files_skipped_no_candidates"] = 1

            document_opened = False
            if symbol_needed or type_needed:
                try:
                    document_opened = bool(self.open_document(source_path))
                except Exception:
                    document_opened = False
            semantic_context: Dict[str, Any] = {}
            if symbol_needed or type_needed:
                semantic_stats = (
                    local_stats_by_index[symbol_index]
                    if symbol_needed
                    else local_stats_by_index[type_index]
                )
                semantic_before = int(semantic_stats.get("semantic_requests") or 0)
                semantic_context = dict(
                    self._get_file_semantic_context(
                        source_path,
                        lines,
                        enabled=document_opened,
                        stats=semantic_stats,
                    )
                )
                semantic_delta = max(
                    0,
                    int(semantic_stats.get("semantic_requests") or 0) - semantic_before,
                )
                if symbol_needed and type_needed:
                    local_stats_by_index[type_index]["semantic_requests"] += semantic_delta
                semantic_context.update(shared_resolution_caches)

            file_symbols: Dict[Tuple[str, str, str, str, str, int], str] = {}
            file_macros: set[Tuple[int, int, int]] = set()
            file_types: List[Tuple[Any, ...]] = []
            include_closure = include_closures.get(function_file, [function_file])
            try:
                for function in file_functions:
                    if symbol_needed and not stop_events[symbol_index].is_set():
                        try:
                            self._collect_function_symbol_refs(
                                function,
                                function_file,
                                source_path,
                                lines,
                                globals_by_name,
                                macros_by_name,
                                file_symbols,
                                file_macros,
                                include_closure,
                                semantic_context,
                                local_stats_by_index[symbol_index],
                            )
                        except Exception as exc:
                            local_errors.setdefault(symbol_index, exc)
                            stop_events[symbol_index].set()
                            symbol_needed = False
                    if type_needed and not stop_events[type_index].is_set():
                        try:
                            file_types.extend(
                                self._collect_function_type_refs(
                                    function,
                                    function_file,
                                    source_path,
                                    lines,
                                    types_by_name,
                                    indexed_type_names,
                                    include_closure,
                                    semantic_context,
                                    local_stats_by_index[type_index],
                                )
                            )
                        except Exception as exc:
                            local_errors.setdefault(type_index, exc)
                            stop_events[type_index].set()
                            type_needed = False
            finally:
                if document_opened:
                    try:
                        self.close_document(source_path)
                    except Exception:
                        pass

            for local_stats in local_stats_by_index.values():
                local_stats["functions_processed"] = len(file_functions)
                local_stats["files_processed"] = 1
            return _DerivedFileResult(
                stats_by_index=local_stats_by_index,
                symbol_rows=[(*key, access) for key, access in sorted(file_symbols.items())],
                macro_rows=sorted(file_macros),
                type_rows=sorted(
                    set(file_types),
                    key=lambda row: tuple(str(value) for value in row),
                ),
                errors=local_errors,
            )

        def record_error(index_name: str, exc: Exception) -> None:
            if index_name not in errors:
                errors[index_name] = exc
            stop_events[index_name].set()

        def consume(result: _DerivedFileResult) -> None:
            for index_name, local_stats in result.stats_by_index.items():
                self._merge_derived_stats(stats_by_index[index_name], local_stats)
                stats_by_index[index_name]["peak_inflight_files"] = int(
                    worker_metrics.get("peak_inflight_files") or 0
                )
            for index_name, exc in result.errors.items():
                record_error(index_name, exc)

            if symbol_index not in errors and not stop_events[symbol_index].is_set():
                try:
                    for offset in range(0, len(result.symbol_rows), 1000):
                        stage_symbols(result.symbol_rows[offset : offset + 1000])
                    for offset in range(0, len(result.macro_rows), 1000):
                        stage_macros(result.macro_rows[offset : offset + 1000])
                    counts[symbol_index] += len(result.symbol_rows) + len(result.macro_rows)
                except Exception as exc:
                    record_error(symbol_index, exc)
            if type_index not in errors and not stop_events[type_index].is_set():
                try:
                    for offset in range(0, len(result.type_rows), 1000):
                        stage_types(result.type_rows[offset : offset + 1000])
                    counts[type_index] += len(result.type_rows)
                except Exception as exc:
                    record_error(type_index, exc)
            for index_stats in stats_by_index.values():
                self._log_derived_progress(index_stats)

        self._run_derived_file_jobs(
            work_items,
            worker,
            consume,
            worker_metrics,
        )
        for index_stats in stats_by_index.values():
            index_stats.update(worker_metrics)

        for index_name, stats in stats_by_index.items():
            stats["rows"] = counts[index_name]
            if index_name in errors:
                self._record_unresolved(
                    stats,
                    "rebuild_failed",
                    {"error": str(errors[index_name])[:500]},
                )
            self._finish_derived_stats(stats)
        return {"counts": counts, "errors": errors}

    def _collect_function_type_refs(
        self,
        function: Dict[str, Any],
        function_file: str,
        source_path: Path,
        lines: List[str],
        types_by_name: Dict[str, List[Dict[str, Any]]],
        indexed_type_names: set[str],
        include_closure: List[str],
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> List[Tuple[Any, ...]]:
        function_id = int(function.get("id") or 0)
        if function_id <= 0:
            return []
        candidates = self._direct_function_type_candidates(function, lines, indexed_type_names)
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
            r"(?:^|[;{}])\s*"
            r"(?:(?:const|volatile|static|register|auto|signed|unsigned|short|long|_Atomic)"
            r"\b[ \t]*)*"
            r"(?:(?:struct|union|enum|class)[ \t]+)?(?P<type>[A-Za-z_]\w*)"
            r"(?P<middle>(?:[\s*&]|const\b|volatile\b)+)"
            r"(?P<var>[A-Za-z_]\w*)[ \t]*(?=[=;,{\[])"
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

    def _functions_contain_candidate_identifiers(
        self,
        functions: List[Dict[str, Any]],
        lines: List[str],
        candidate_names: set[str],
    ) -> bool:
        """Cheaply skip semanticTokens for files whose functions have no candidates."""
        if not candidate_names:
            return False
        for function in functions:
            start_line = max(1, int(function.get("start_line") or 1))
            end_line = min(
                len(lines),
                max(start_line, int(function.get("end_line") or start_line)),
            )
            for raw_line in lines[start_line - 1 : end_line]:
                masked = self._mask_c_comments_and_literals(raw_line)
                for token in re.finditer(r"\b[A-Za-z_]\w*\b", masked):
                    if token.group(0) in candidate_names:
                        return True
        return False

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

    _DERIVED_SEMANTIC_CACHE_MAX_FILES = 64
    _DERIVED_SEMANTIC_CACHE_MAX_BYTES = 128 * 1024 * 1024
    _DERIVED_SEMANTIC_BYTES_PER_TOKEN = 512
    _DERIVED_REFERENCE_CACHE_MAX_ENTRIES = 256
    _DERIVED_REFERENCE_CACHE_MAX_LOCATIONS = 500_000

    @classmethod
    def _trim_derived_semantic_cache(
        cls,
        cache: OrderedDict[Tuple[str, int, int], Dict[str, Any]],
    ) -> None:
        estimated_bytes = sum(
            max(0, int(context.get("_semantic_cache_estimated_bytes") or 0))
            for context in cache.values()
        )
        while cache and (
            len(cache) > cls._DERIVED_SEMANTIC_CACHE_MAX_FILES
            or estimated_bytes > cls._DERIVED_SEMANTIC_CACHE_MAX_BYTES
        ):
            _key, evicted = cache.popitem(last=False)
            estimated_bytes -= max(
                0,
                int(evicted.get("_semantic_cache_estimated_bytes") or 0),
            )

    def end_derived_rebuild_session(self) -> None:
        """Release per-file semantic facts retained across sibling rebuilds."""
        self._derived_session_active = False
        with self._derived_cache_lock:
            cache = getattr(self, "_semantic_context_cache", None)
            if isinstance(cache, OrderedDict):
                self._trim_derived_semantic_cache(cache)

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
            "files_skipped_no_candidates": 0,
            "functions_total": int(functions_total),
            "functions_processed": 0,
            "candidates": 0,
            "filtered_local_shadow": 0,
            "filtered_field": 0,
            "filtered_non_call_macro": 0,
            "semantic_requests": 0,
            "semantic_resolved": 0,
            "local_resolved": 0,
            "symbol_info_requests": 0,
            "canonical_groups": 0,
            "references_requests": 0,
            "references_resolved": 0,
            "reference_cache_evictions": 0,
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
        if bool(stats.get("_suppress_progress")):
            return
        now = time.monotonic()
        last_log = float(stats.get("_last_log_monotonic") or 0.0)
        if not force and last_log and now - last_log < 5.0:
            return
        stats["_last_log_monotonic"] = now
        logger.info(
            "[%s] files=%d/%d functions=%d/%d candidates=%d "
            "filtered(shadow=%d field=%d macro_non_call=%d) "
            "semantic(req=%d resolved=%d) local=%d "
            "references(req=%d resolved=%d) definitions(req=%d timeout=%d) unresolved=%d",
            stats.get("index_name"),
            int(stats.get("files_processed") or 0),
            int(stats.get("files_total") or 0),
            int(stats.get("functions_processed") or 0),
            int(stats.get("functions_total") or 0),
            int(stats.get("candidates") or 0),
            int(stats.get("filtered_local_shadow") or 0),
            int(stats.get("filtered_field") or 0),
            int(stats.get("filtered_non_call_macro") or 0),
            int(stats.get("semantic_requests") or 0),
            int(stats.get("semantic_resolved") or 0),
            int(stats.get("local_resolved") or 0),
            int(stats.get("references_requests") or 0),
            int(stats.get("references_resolved") or 0),
            int(stats.get("definition_requests") or 0),
            int(stats.get("definition_timeouts") or 0),
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
        stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        try:
            stat = source_path.stat()
            cache_key = (str(source_path.resolve()), int(stat.st_mtime_ns), int(stat.st_size))
        except OSError:
            cache_key = (str(source_path.resolve()), 0, 0)
        with self._derived_cache_lock:
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
            "reference_coordinate_index": {},
            "reference_indexed_keys": set(),
            "candidate_canonical_cache": {},
            "canonical_group_cache": {},
            "definition_cache": {},
            "declaration_char_cache": {},
            "visibility_cache": {},
            "_semantic_cache_estimated_bytes": 1024,
        }
        can_query = enabled and (self.process is not None or "get_semantic_tokens" in self.__dict__)
        getter = getattr(self, "get_semantic_tokens", None)
        if can_query and callable(getter):
            if stats is not None:
                stats["semantic_requests"] = int(stats.get("semantic_requests") or 0) + 1
            try:
                response = getter(source_path)
            except Exception:
                response = None
            data = response.get("data") if isinstance(response, dict) else None
            if isinstance(data, list):
                context["available"] = True
                context["tokens_by_line"] = self._decode_semantic_tokens(data, lines)
                context["tokens_by_position"] = {
                    (line, int(token.get("start") or 0)): token
                    for line, tokens in context["tokens_by_line"].items()
                    for token in tokens
                }
                token_count = sum(len(tokens) for tokens in context["tokens_by_line"].values())
                context["_semantic_cache_estimated_bytes"] = max(
                    1024,
                    token_count * self._DERIVED_SEMANTIC_BYTES_PER_TOKEN,
                    len(data) * 8,
                )

        with self._derived_cache_lock:
            cached = cache.get(cache_key)
            if isinstance(cached, dict):
                cache.move_to_end(cache_key)
                return cached
            cache[cache_key] = context
            cache.move_to_end(cache_key)
            self._trim_derived_semantic_cache(cache)
            return context

    def _decode_semantic_tokens(
        self,
        data: List[Any],
        source_lines: Optional[List[str]] = None,
    ) -> Dict[int, List[Dict[str, Any]]]:
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
            if not source_line and isinstance(source_lines, list):
                if 0 <= current_line < len(source_lines):
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
        semantic_context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        candidate_key = tuple(self._candidate_identity(candidate) for candidate in candidates)
        cache_key = (str(function_file), candidate_key)

        def compute() -> List[Dict[str, Any]]:
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

        if semantic_context is None:
            return compute()
        return cast(
            List[Dict[str, Any]],
            self._shared_resolution_cache_get_or_compute(
                semantic_context,
                "visibility_cache",
                cache_key,
                compute,
            ),
        )

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

    @classmethod
    def _candidate_list_identity(
        cls,
        candidates: List[Dict[str, Any]],
    ) -> Tuple[Tuple[Any, ...], ...]:
        return tuple(cls._candidate_identity(candidate) for candidate in candidates)

    def get_symbol_info(
        self,
        file_path: Path,
        line: int,
        character: int = 0,
    ) -> Optional[Dict[str, Any]]:
        """Return clangd's stable USR/symbol ID for the symbol at one coordinate."""
        result = self.send_request(
            "textDocument/symbolInfo",
            {
                "textDocument": {"uri": file_path.as_uri()},
                "position": {
                    "line": int(line),
                    "character": self._python_offset_to_lsp(file_path, line, character),
                },
            },
            timeout=30,
        )
        if isinstance(result, dict):
            return cast(Dict[str, Any], result)
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return cast(Dict[str, Any], result[0])
        return None

    def _candidate_canonical_identity(
        self,
        candidate: Dict[str, Any],
        *,
        kind: str,
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> Tuple[Any, ...]:
        identity = self._candidate_identity(candidate)
        cache_key = (kind, identity)
        fallback = ("candidate", kind, identity)

        def compute() -> Tuple[Any, ...]:
            can_query = self.process is not None or "get_symbol_info" in self.__dict__
            getter = getattr(self, "get_symbol_info", None)
            declaration = self._candidate_declaration_position(candidate, semantic_context)
            if not can_query or not callable(getter) or declaration is None:
                return fallback
            declaration_path, declaration_line, declaration_character = declaration
            stats["symbol_info_requests"] = int(stats.get("symbol_info_requests") or 0) + 1
            try:
                info = getter(
                    declaration_path,
                    max(0, declaration_line - 1),
                    max(0, declaration_character),
                )
            except Exception:
                info = None
            if isinstance(info, list):
                info = info[0] if info and isinstance(info[0], dict) else None
            usr = str(info.get("usr") or "") if isinstance(info, dict) else ""
            symbol_id = str(info.get("id") or "") if isinstance(info, dict) else ""
            return (
                ("usr", kind, usr)
                if usr
                else (("symbol_id", kind, symbol_id) if symbol_id else fallback)
            )

        return cast(
            Tuple[Any, ...],
            self._shared_resolution_cache_get_or_compute(
                semantic_context,
                "candidate_canonical_cache",
                cache_key,
                compute,
            ),
        )

    @classmethod
    def _canonical_candidate_representative(
        cls,
        candidates: List[Dict[str, Any]],
        kind: str,
    ) -> Dict[str, Any]:
        def priority(candidate: Dict[str, Any]) -> Tuple[Any, ...]:
            if kind == "global":
                quality = (
                    int(str(candidate.get("definition_kind") or "") == "definition"),
                    int(not bool(candidate.get("is_extern"))),
                    int(bool(str(candidate.get("initializer") or ""))),
                )
            elif kind == "type":
                start_line = int(candidate.get("start_line") or 0)
                end_line = int(candidate.get("end_line") or start_line)
                definition = str(candidate.get("full_definition") or "")
                quality = (
                    int(bool(candidate.get("has_definition")) or "{" in definition),
                    int(end_line > start_line),
                    int(bool(definition)),
                )
            else:
                quality = (0, 0, 0)
            return tuple(-value for value in quality) + tuple(
                str(value) for value in cls._candidate_identity(candidate)
            )

        return min(candidates, key=priority)

    def _canonical_candidate_groups(
        self,
        candidates: List[Dict[str, Any]],
        *,
        kind: str,
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> List[Tuple[Tuple[Any, ...], Dict[str, Any], List[Dict[str, Any]]]]:
        if not candidates:
            return []
        cache_key = (kind, self._candidate_list_identity(candidates))

        def compute() -> List[Tuple[Tuple[Any, ...], Dict[str, Any], List[Dict[str, Any]]]]:
            grouped: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
            if len(candidates) == 1 or kind == "macro":
                for candidate in candidates:
                    identity = ("candidate", kind, self._candidate_identity(candidate))
                    grouped[identity] = [candidate]
            else:
                for candidate in candidates:
                    identity = self._candidate_canonical_identity(
                        candidate,
                        kind=kind,
                        semantic_context=semantic_context,
                        stats=stats,
                    )
                    grouped.setdefault(identity, []).append(candidate)
            result = [
                (identity, self._canonical_candidate_representative(members, kind), members)
                for identity, members in grouped.items()
            ]
            stats["canonical_groups"] = int(stats.get("canonical_groups") or 0) + len(result)
            return result

        return cast(
            List[Tuple[Tuple[Any, ...], Dict[str, Any], List[Dict[str, Any]]]],
            self._shared_resolution_cache_get_or_compute(
                semantic_context,
                "canonical_group_cache",
                cache_key,
                compute,
            ),
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
        visible = self._visible_candidates(
            candidates, function_file, include_closure, semantic_context
        )
        if self._semantic_token_proves_kind(semantic_token, kind):
            semantic_candidates = visible or candidates
            if len(semantic_candidates) == 1:
                stats["semantic_resolved"] += 1
                stats["local_resolved"] += 1
                return semantic_candidates[0]
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
            semantic_context,
        )
        visible_macros = self._visible_candidates(
            macro_candidates,
            function_file,
            include_closure,
            semantic_context,
        )
        if self._semantic_token_proves_kind(semantic_token, "global"):
            semantic_globals = visible_globals or global_candidates
            if len(semantic_globals) == 1:
                stats["semantic_resolved"] += 1
                stats["local_resolved"] += 1
                return "global", semantic_globals[0]
        if self._semantic_token_proves_kind(semantic_token, "macro"):
            semantic_macros = visible_macros or macro_candidates
            if len(semantic_macros) == 1:
                stats["semantic_resolved"] += 1
                stats["local_resolved"] += 1
                return "macro", semantic_macros[0]
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
        visible = self._visible_candidates(
            candidates, function_file, include_closure, semantic_context
        )
        if self._semantic_token_proves_kind(token, "type"):
            semantic_types = visible or candidates
            if len(semantic_types) == 1:
                stats["semantic_resolved"] += 1
                stats["local_resolved"] += 1
                return semantic_types[0], ""
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
        groups = self._canonical_candidate_groups(
            candidates,
            kind=kind,
            semantic_context=semantic_context,
            stats=stats,
        )
        representatives: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for canonical_key, representative, _members in groups:
            representatives[canonical_key] = representative
            self._candidate_reference_locations(
                representative,
                kind=kind,
                semantic_context=semantic_context,
                stats=stats,
                canonical_key=canonical_key,
            )
        coordinate = self._reference_coordinate(
            kind,
            self._project_relative_path(source_path),
            line,
            character,
        )
        resolution_lock = self._resolution_cache_lock(semantic_context)
        if resolution_lock is None:
            coordinate_index = semantic_context.setdefault("reference_coordinate_index", {})
            matched_keys = coordinate_index.get(coordinate)
        else:
            with resolution_lock:
                coordinate_index = semantic_context.setdefault(
                    "reference_coordinate_index", {}
                )
                raw_matched = coordinate_index.get(coordinate)
                matched_keys = set(raw_matched) if isinstance(raw_matched, set) else raw_matched
        if not isinstance(matched_keys, set) or len(matched_keys) != 1:
            return None
        return representatives.get(next(iter(matched_keys)))

    @staticmethod
    def _reference_file_key(file_path: str) -> str:
        value = str(file_path or "").replace("\\", "/")
        while value.startswith("./"):
            value = value[2:]
        return value.casefold() if os.name == "nt" else value

    @classmethod
    def _reference_coordinate(
        cls,
        kind: str,
        file_path: str,
        line: int,
        character: int,
    ) -> Tuple[str, str, int, int]:
        return (
            str(kind),
            cls._reference_file_key(file_path),
            int(line),
            int(character),
        )

    def _candidate_reference_locations(
        self,
        candidate: Dict[str, Any],
        *,
        kind: str,
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
        canonical_key: Optional[Tuple[Any, ...]] = None,
    ) -> set[Tuple[str, int, int]]:
        cache_key = (
            kind,
            (
                canonical_key
                if canonical_key is not None
                else ("candidate", kind, self._candidate_identity(candidate))
            ),
        )
        resolution_lock = self._resolution_cache_lock(semantic_context)

        def normalized_cache() -> OrderedDict[Any, set[Tuple[str, int, int]]]:
            cache_value = semantic_context.get("reference_cache")
            if not isinstance(cache_value, OrderedDict):
                cache_value = OrderedDict(cache_value if isinstance(cache_value, dict) else {})
                semantic_context["reference_cache"] = cache_value
            return cast(OrderedDict[Any, set[Tuple[str, int, int]]], cache_value)

        if resolution_lock is None:
            cache = normalized_cache()
            if cache_key in cache:
                cached_locations = cache[cache_key]
                cache.move_to_end(cache_key)
                self._index_reference_locations(
                    cache_key,
                    cached_locations,
                    kind=kind,
                    canonical_key=cast(Tuple[Any, ...], cache_key[1]),
                    semantic_context=semantic_context,
                )
                return cached_locations
            owner = True
            future: Optional[Future[set[Tuple[str, int, int]]]] = None
        else:
            with resolution_lock:
                cache = normalized_cache()
                if cache_key in cache:
                    cached_locations = cache[cache_key]
                    cache.move_to_end(cache_key)
                    self._index_reference_locations(
                        cache_key,
                        cached_locations,
                        kind=kind,
                        canonical_key=cast(Tuple[Any, ...], cache_key[1]),
                        semantic_context=semantic_context,
                    )
                    return cached_locations
                inflight = semantic_context.setdefault("_reference_cache_inflight", {})
                existing_future = inflight.get(cache_key)
                owner = not isinstance(existing_future, Future)
                if owner:
                    future = Future()
                    inflight[cache_key] = future
                else:
                    future = cast(Future[set[Tuple[str, int, int]]], existing_future)
            if not owner:
                assert future is not None
                return future.result()

        try:
            declaration = self._candidate_declaration_position(candidate, semantic_context)
            raw_locations: Optional[List[Dict[str, Any]]] = None
            if declaration is not None:
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
            raw_by_file: Dict[str, set[Tuple[int, int]]] = {}
            uri_path_cache: Dict[str, str] = {}
            for location in raw_locations or []:
                if not isinstance(location, dict):
                    continue
                uri = str(location.get("uri") or location.get("targetUri") or "")
                target_file = uri_path_cache.get(uri)
                if target_file is None:
                    target_file = self._uri_to_project_path(uri)
                    uri_path_cache[uri] = target_file
                range_info = location.get("range") or location.get("targetSelectionRange") or {}
                start = range_info.get("start", {}) if isinstance(range_info, dict) else {}
                if target_file and isinstance(start, dict):
                    target_line_zero = int(start.get("line") or 0)
                    target_character = int(start.get("character") or 0)
                    raw_by_file.setdefault(target_file, set()).add(
                        (target_line_zero, target_character)
                    )
            locations: set[Tuple[str, int, int]] = set()
            for target_file, raw_positions in raw_by_file.items():
                target_path = self._resolve_indexed_source_path(target_file)
                target_lines = self._read_source_lines(target_path)
                for target_line_zero, target_character in raw_positions:
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
        except BaseException as exc:
            if resolution_lock is not None:
                assert future is not None
                future.set_exception(exc)
                with resolution_lock:
                    semantic_context.setdefault("_reference_cache_inflight", {}).pop(
                        cache_key, None
                    )
            raise

        if resolution_lock is None:
            cache = normalized_cache()
            cache[cache_key] = locations
            cache.move_to_end(cache_key)
            self._index_reference_locations(
                cache_key,
                locations,
                kind=kind,
                canonical_key=cast(Tuple[Any, ...], cache_key[1]),
                semantic_context=semantic_context,
            )
            self._trim_reference_resolution_cache(semantic_context, stats)
            return locations

        with resolution_lock:
            cache = normalized_cache()
            cache[cache_key] = locations
            cache.move_to_end(cache_key)
            self._index_reference_locations(
                cache_key,
                locations,
                kind=kind,
                canonical_key=cast(Tuple[Any, ...], cache_key[1]),
                semantic_context=semantic_context,
            )
            self._trim_reference_resolution_cache(semantic_context, stats)
            semantic_context.setdefault("_reference_cache_inflight", {}).pop(cache_key, None)
        assert future is not None
        future.set_result(locations)
        return locations

    def _trim_reference_resolution_cache(
        self,
        semantic_context: Dict[str, Any],
        stats: Dict[str, Any],
    ) -> None:
        def trim() -> None:
            cache = semantic_context.get("reference_cache")
            if not isinstance(cache, OrderedDict):
                return
            location_count = sum(len(locations) for locations in cache.values())
            coordinate_index = semantic_context.setdefault("reference_coordinate_index", {})
            indexed = semantic_context.setdefault("reference_indexed_keys", set())
            while len(cache) > 1 and (
                len(cache) > self._DERIVED_REFERENCE_CACHE_MAX_ENTRIES
                or location_count > self._DERIVED_REFERENCE_CACHE_MAX_LOCATIONS
            ):
                evicted_key, locations = cache.popitem(last=False)
                location_count -= len(locations)
                kind = str(evicted_key[0])
                canonical_key = cast(Tuple[Any, ...], evicted_key[1])
                for target_file, target_line, target_character in locations:
                    coordinate = self._reference_coordinate(
                        kind,
                        target_file,
                        target_line,
                        target_character,
                    )
                    matched = coordinate_index.get(coordinate)
                    if not isinstance(matched, set):
                        continue
                    matched.discard(canonical_key)
                    if not matched:
                        coordinate_index.pop(coordinate, None)
                indexed.discard(evicted_key)
                stats["reference_cache_evictions"] = int(
                    stats.get("reference_cache_evictions") or 0
                ) + 1

        resolution_lock = self._resolution_cache_lock(semantic_context)
        if resolution_lock is None:
            trim()
        else:
            with resolution_lock:
                trim()

    def _index_reference_locations(
        self,
        cache_key: Tuple[Any, ...],
        locations: set[Tuple[str, int, int]],
        *,
        kind: str,
        canonical_key: Tuple[Any, ...],
        semantic_context: Dict[str, Any],
    ) -> None:
        def index_locations() -> None:
            indexed = semantic_context.setdefault("reference_indexed_keys", set())
            if cache_key in indexed:
                return
            coordinate_index = semantic_context.setdefault("reference_coordinate_index", {})
            for target_file, target_line, target_character in locations:
                coordinate = self._reference_coordinate(
                    kind,
                    target_file,
                    target_line,
                    target_character,
                )
                coordinate_index.setdefault(coordinate, set()).add(canonical_key)
            indexed.add(cache_key)

        resolution_lock = self._resolution_cache_lock(semantic_context)
        if resolution_lock is None:
            index_locations()
        else:
            with resolution_lock:
                index_locations()

    def _candidate_declaration_position(
        self,
        candidate: Dict[str, Any],
        semantic_context: Dict[str, Any],
    ) -> Optional[Tuple[Path, int, int]]:
        identity = self._candidate_identity(candidate)

        def compute() -> Optional[Tuple[Path, int, int]]:
            file_path = str(candidate.get("file_path") or "")
            name = str(candidate.get("name") or "")
            start_line = int(candidate.get("line") or candidate.get("start_line") or 0)
            end_line = int(candidate.get("end_line") or start_line)
            if not file_path or not name or start_line <= 0:
                return None
            path = self._resolve_indexed_source_path(file_path)
            source_lines = self._read_source_lines(path)
            if not source_lines:
                return None
            last_line = min(len(source_lines), max(start_line, min(end_line, start_line + 20)))
            pattern = re.compile(rf"\b{re.escape(name)}\b")
            for declaration_line in range(start_line, last_line + 1):
                match = pattern.search(
                    self._mask_c_comments_and_literals(source_lines[declaration_line - 1])
                )
                if match:
                    return (path, declaration_line, match.start())
            return None

        return cast(
            Optional[Tuple[Path, int, int]],
            self._shared_resolution_cache_get_or_compute(
                semantic_context,
                "declaration_char_cache",
                identity,
                compute,
            ),
        )

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
        self._consume_thread_request_timeout("textDocument/definition")
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
        if self._consume_thread_request_timeout("textDocument/definition"):
            stats["definition_timeouts"] += 1
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
        index_barrier: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, int]:
        """Extract changed TUs with bounded cross-file LSP concurrency."""
        from concurrent.futures import ThreadPoolExecutor

        stats = {"total": len(file_list), "success": 0, "failed": 0, "skipped": 0}
        prescanned_tus = prescanned_tus or {}
        started_at = time.monotonic()
        changed_tu_count = 0
        index_barrier_completed = False
        tracked_methods = (
            "textDocument/documentSymbol",
            "textDocument/prepareCallHierarchy",
            "callHierarchy/outgoingCalls",
            "textDocument/definition",
        )
        request_metrics_before = {
            method: self.get_request_metrics(method) for method in tracked_methods
        }

        for i in range(0, len(file_list), batch_size):
            batch = file_list[i : i + batch_size]
            logger.info(
                "Processing batch %d/%d (%d files)",
                i // batch_size + 1,
                (len(file_list) + batch_size - 1) // batch_size,
                len(batch),
            )

            work_items: List[Tuple[Path, int]] = []
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
                work_items.append((fp, int(tu_id)))

            worker_count = min(
                max(1, int(self.max_threads or 1)),
                8,
                max(1, len(work_items)),
            )

            batch_transaction = getattr(db, "replace_tu_facts_batch_transaction", None)
            collect_then_publish = callable(batch_transaction)

            def extract_one(
                item: Tuple[Path, int],
            ) -> Tuple[Path, int, Optional[Dict[str, Any]], bool, Optional[Exception]]:
                fp, tu_id = item
                try:
                    if collect_then_publish:
                        facts = self._collect_tu_facts(
                            fp,
                            db,
                            tu_id,
                            defer_call_queries=True,
                        )
                        return fp, tu_id, facts, facts is not None, None
                    return fp, tu_id, None, bool(self.extract_tu(fp, db, tu_id, None)), None
                except Exception as exc:
                    return fp, tu_id, None, False, exc

            if work_items:
                changed_tu_count += len(work_items)
                if worker_count == 1:
                    results: Iterable[
                        Tuple[
                            Path,
                            int,
                            Optional[Dict[str, Any]],
                            bool,
                            Optional[Exception],
                        ]
                    ] = map(
                        extract_one,
                        work_items,
                    )
                else:
                    executor = ThreadPoolExecutor(
                        max_workers=worker_count,
                        thread_name_prefix="ClangExtract",
                    )
                    results = executor.map(extract_one, work_items)
                try:
                    collected = list(results)
                    call_tasks: List[Tuple[Any, ...]] = []
                    deferred_documents: List[Path] = []
                    for _fp, _tu_id, facts, ok, _error in collected:
                        if ok and facts is not None:
                            call_tasks.extend(facts.pop("_call_work", []))
                            deferred_path = facts.pop("_deferred_document_path", None)
                            if deferred_path is not None:
                                deferred_documents.append(Path(deferred_path))
                    try:
                        if call_tasks:
                            if not index_barrier_completed and index_barrier is not None:
                                if not index_barrier():
                                    raise TimeoutError(
                                        "clangd indexing did not complete before call extraction"
                                    )
                                index_barrier_completed = True
                            call_worker_count = min(
                                max(1, int(self.max_threads or 1)),
                                8,
                                len(call_tasks),
                            )
                            if call_worker_count == 1:
                                call_results: Iterable[List[Tuple[Any, ...]]] = map(
                                    self._extract_deferred_call_edges,
                                    call_tasks,
                                )
                                materialized_call_results = list(call_results)
                            else:
                                call_executor = ThreadPoolExecutor(
                                    max_workers=call_worker_count,
                                    thread_name_prefix="ClangCalls",
                                )
                                try:
                                    materialized_call_results = list(
                                        call_executor.map(
                                            self._extract_deferred_call_edges,
                                            call_tasks,
                                        )
                                    )
                                finally:
                                    call_executor.shutdown(
                                        wait=True,
                                        cancel_futures=False,
                                    )
                            rows_by_file: Dict[str, List[Tuple[Any, ...]]] = {}
                            for work, extracted_rows in zip(
                                call_tasks,
                                materialized_call_results,
                            ):
                                rows_by_file.setdefault(
                                    str(Path(work[0]).resolve()),
                                    [],
                                ).extend(extracted_rows)
                            for fp, _tu_id, facts, ok, _error in collected:
                                if ok and facts is not None:
                                    facts["call_rows"].extend(
                                        rows_by_file.get(str(fp.resolve()), [])
                                    )
                    finally:
                        for document_path in deferred_documents:
                            self.close_document(document_path)
                    if collect_then_publish:
                        assert callable(batch_transaction)
                        published: List[Path] = []
                        try:
                            with batch_transaction():
                                for fp, tu_id, facts, ok, error in collected:
                                    if error is not None:
                                        logger.error("Failed to collect %s: %s", fp, error)
                                    if not ok or facts is None:
                                        stats["failed"] += 1
                                        continue
                                    try:
                                        self._publish_tu_facts(db, tu_id, **facts)
                                    except Exception as exc:
                                        logger.error("Failed to publish %s: %s", fp, exc)
                                        stats["failed"] += 1
                                        continue
                                    published.append(fp)
                        except Exception as exc:
                            logger.error("Failed to commit TU batch: %s", exc)
                            stats["failed"] += len(published)
                            published.clear()
                        stats["success"] += len(published)
                        if progress_cb:
                            for fp in published:
                                progress_cb(fp)
                    else:
                        for fp, _tu_id, _facts, ok, error in collected:
                            if error is not None:
                                logger.error("Failed to extract %s: %s", fp, error)
                            if ok:
                                stats["success"] += 1
                                if progress_cb:
                                    progress_cb(fp)
                            else:
                                stats["failed"] += 1
                finally:
                    if worker_count != 1:
                        executor.shutdown(wait=True, cancel_futures=False)

            logger.info(
                "Batch complete. Progress: %d extracted, %d skipped, %d failed",
                stats["success"],
                stats["skipped"],
                stats["failed"],
            )

        elapsed_seconds = max(0.0, time.monotonic() - started_at)
        self._last_base_stats = {
            "files_total": len(file_list),
            "files_changed": changed_tu_count,
            "files_extracted": stats["success"],
            "files_skipped": stats["skipped"],
            "files_failed": stats["failed"],
            "max_workers": min(max(1, int(self.max_threads or 1)), 8),
            "elapsed_seconds": round(elapsed_seconds, 3),
            "lsp_requests": {
                method: {
                    "count": max(
                        0,
                        int(self.get_request_metrics(method).get("count") or 0)
                        - int(request_metrics_before[method].get("count") or 0),
                    ),
                    "timeouts": max(
                        0,
                        int(self.get_request_metrics(method).get("timeouts") or 0)
                        - int(request_metrics_before[method].get("timeouts") or 0),
                    ),
                    "average_latency_ms": round(
                        float(
                            self.get_request_metrics(method).get("average_latency_ms")
                            or 0.0
                        ),
                        3,
                    ),
                    "p95_latency_ms": round(
                        float(
                            self.get_request_metrics(method).get("p95_latency_ms") or 0.0
                        ),
                        3,
                    ),
                }
                for method in tracked_methods
            },
        }
        logger.info(
            "Base TU extraction finished files=%d changed=%d success=%d failed=%d "
            "elapsed=%.3fs lsp_requests=%s",
            len(file_list),
            changed_tu_count,
            stats["success"],
            stats["failed"],
            elapsed_seconds,
            self._last_base_stats["lsp_requests"],
        )

        return stats

    def get_last_base_stats(self) -> Dict[str, Any]:
        """Return the latest base extraction progress/RPC snapshot."""
        value = getattr(self, "_last_base_stats", {})
        return dict(value) if isinstance(value, dict) else {}

    def _extract_call_edges(
        self,
        file_path: Path,
        caller_name: str,
        caller_file: str,
        start_line: int,
        end_line: int,
        call_rows: List[Tuple[Any, ...]],
        sym: Optional[Dict[str, Any]] = None,
        known_local_functions: Optional[set[str]] = None,
    ):
        """Extract call edges, preferring clangd's AST-backed call hierarchy."""
        hierarchy_count = self._extract_call_edges_from_call_hierarchy(
            file_path, caller_name, caller_file, start_line, call_rows, sym
        )
        if hierarchy_count is not None:
            return

        self._extract_call_edges_by_regex(
            file_path,
            caller_name,
            caller_file,
            start_line,
            end_line,
            call_rows,
            known_local_functions=known_local_functions,
        )

    def _extract_deferred_call_edges(
        self,
        work: Tuple[Any, ...],
    ) -> List[Tuple[Any, ...]]:
        """Resolve one function's call edges for the batch-wide LSP worker pool."""
        (
            file_path,
            caller_name,
            caller_file,
            start_line,
            end_line,
            sym,
            known_local_functions,
        ) = work
        rows: List[Tuple[Any, ...]] = []
        try:
            self._extract_call_edges(
                Path(file_path),
                str(caller_name),
                str(caller_file),
                int(start_line),
                int(end_line),
                rows,
                cast(Optional[Dict[str, Any]], sym),
                cast(set[str], known_local_functions),
            )
        except Exception as exc:
            logger.debug("Failed to extract deferred calls in %s: %s", caller_name, exc)
        return rows

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
            position = self._symbol_position(sym, start_line, file_path)
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
        *,
        known_local_functions: Optional[set[str]] = None,
    ):
        """Fallback call extraction for clangd versions without call hierarchy."""
        try:
            lines = self._read_source_lines(file_path)
            if lines is None:
                return
            body = "".join(lines[start_line - 1 : end_line])
            masked_body = self._mask_c_comments_and_literals(body)
            masked_source = self._read_masked_source(file_path) or ""
            function_pointer_names = self._function_pointer_names_for_file(
                file_path,
                masked_source,
            )
            local_functions = known_local_functions or set()

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
                if (callee, call_line) in seen:
                    continue

                last_newline = prefix.rfind("\n")
                if last_newline == -1:
                    char_offset = len(prefix)
                else:
                    char_offset = len(prefix) - last_newline - 1

                call_type, callee_kind = self._regex_call_classification(
                    masked_body,
                    masked_source,
                    callee,
                    match_start_idx,
                    has_definition=False,
                    function_pointer_names=function_pointer_names,
                )
                callee_file = ""
                defs: Optional[List[Any]] = None
                if call_type != "indirect" and callee in local_functions:
                    callee_file = caller_file
                    call_type, callee_kind = "direct", "function"
                elif call_type != "indirect":
                    defs = self.get_definition(file_path, call_line - 1, char_offset)
                    if defs and isinstance(defs, list):
                        first_definition = defs[0] if defs else {}
                        if isinstance(first_definition, dict):
                            uri = first_definition.get("targetUri") or first_definition.get(
                                "uri", ""
                            )
                            callee_file = self._uri_to_project_path(str(uri))
                    call_type, callee_kind = self._regex_call_classification(
                        masked_body,
                        masked_source,
                        callee,
                        match_start_idx,
                        has_definition=bool(defs),
                        function_pointer_names=function_pointer_names,
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
                call_rows.append(
                    (
                        caller_name,
                        caller_file,
                        callee,
                        "",
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
        function_pointer_names: Optional[set[str]] = None,
    ) -> Tuple[str, str]:
        prefix = masked_body[:match_start_idx]
        if re.search(r"(?:\.|->)\s*$", prefix):
            return "indirect", "function_pointer_field"
        if (
            callee in function_pointer_names
            if function_pointer_names is not None
            else self._source_declares_function_pointer(masked_source, callee)
        ):
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

    def _read_masked_source(self, file_path: Path) -> Optional[str]:
        """Return one cached comment/literal-masked source text per file version."""
        cache_key = self._source_cache_key(file_path)
        if cache_key is None:
            return None
        with self._source_text_cache_lock:
            cached = self._masked_source_cache.get(cache_key)
            if cached is not None:
                self._masked_source_cache.move_to_end(cache_key)
                return cached
        text = self._read_source_text(file_path)
        if text is None:
            return None
        masked = self._mask_c_comments_and_literals(text)
        if self._source_cache_key(file_path) != cache_key:
            return masked
        with self._source_text_cache_lock:
            self._masked_source_cache[cache_key] = masked
            self._masked_source_cache.move_to_end(cache_key)
            while len(self._masked_source_cache) > self._source_text_cache_limit:
                self._masked_source_cache.popitem(last=False)
        return masked

    def _function_pointer_names_for_file(
        self,
        file_path: Path,
        masked_source: str,
    ) -> set[str]:
        """Index function-pointer declarators once instead of rescanning per call."""
        cache_key = self._source_cache_key(file_path)
        if cache_key is not None:
            with self._source_text_cache_lock:
                cached = self._function_pointer_name_cache.get(cache_key)
                if cached is not None:
                    self._function_pointer_name_cache.move_to_end(cache_key)
                    return cached
        names = {
            match.group(1)
            for match in re.finditer(
                r"\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\(",
                masked_source,
            )
        }
        typedef_names = {
            match.group(1)
            for match in re.finditer(
                r"\btypedef\b[^;]*?\(\s*\*\s*([a-zA-Z_]\w*)\s*\)\s*\([^;]*\)\s*;",
                masked_source,
                flags=re.DOTALL,
            )
        }
        for type_name in typedef_names:
            for declaration in re.finditer(
                rf"\b{re.escape(type_name)}\b(?P<body>[^;{{}}]*);",
                masked_source,
            ):
                names.update(re.findall(r"\b[a-zA-Z_]\w*\b", declaration.group("body")))
        if cache_key is not None and self._source_cache_key(file_path) == cache_key:
            with self._source_text_cache_lock:
                self._function_pointer_name_cache[cache_key] = names
                self._function_pointer_name_cache.move_to_end(cache_key)
                while len(self._function_pointer_name_cache) > self._source_text_cache_limit:
                    self._function_pointer_name_cache.popitem(last=False)
        return names

    def _symbol_position(
        self,
        sym: Optional[Dict[str, Any]],
        start_line: int,
        file_path: Optional[Path] = None,
    ) -> Dict[str, int]:
        if sym:
            range_info = sym.get("selectionRange") or sym.get("range") or {}
            if file_path is not None and isinstance(range_info, dict):
                range_info = self._lsp_range_to_python(file_path, range_info)
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
        cache_key = self._source_cache_key(file_path)
        if cache_key is None:
            return None
        with self._source_text_cache_lock:
            cached = self._source_lines_cache.get(cache_key)
            if cached is not None:
                self._source_lines_cache.move_to_end(cache_key)
                return cached

        text = self._read_source_text(file_path)
        if text is None:
            return None
        lines = text.splitlines(True)
        if self._source_cache_key(file_path) != cache_key:
            return lines
        with self._source_text_cache_lock:
            self._source_lines_cache[cache_key] = lines
            self._source_lines_cache.move_to_end(cache_key)
            while len(self._source_lines_cache) > self._source_text_cache_limit:
                self._source_lines_cache.popitem(last=False)
        return lines

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
