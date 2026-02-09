"""
LSP Client for communicating with clangd via JSON-RPC.
"""

import json
import logging
import os
import sys
import subprocess
import threading
import time
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

logger = logging.getLogger(__name__)

# ANSI escape sequence regex for stripping colors/formatting
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

class LSPClient:
    """
    Minimal LSP Client to interact with clangd.
    """
    def __init__(self, project_root: Path, clangd_path: str = "clangd", compile_commands_path: Optional[Path] = None):
        self.project_root = Path(project_root).resolve()
        self.clangd_path = clangd_path
        self.compile_commands_path = compile_commands_path
        self.process: Optional[subprocess.Popen] = None
        self._id_counter = 0
        self._responses: Dict[int, Any] = {}
        self._lock = threading.Lock()
        self._io_lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._running = False
        self._initialized = False
        self._last_progress_time = time.time()
        self._last_msg = ""
        self._opened_documents: Dict[str, int] = {}

    def open_document(
        self,
        file_path: Path,
        language_id: Optional[str] = None,
        text: Optional[str] = None,
    ) -> bool:
        """Ensure a document is opened in the LSP server."""
        uri = file_path.as_uri()
        if uri in self._opened_documents:
            return True
        try:
            if text is None:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
        except Exception as exc:
            logger.debug("Failed to read %s for LSP open: %s", file_path, exc)
            return False
        if not language_id:
            language_id = "c" if file_path.suffix == ".c" else "cpp"
        self.send_notification(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": uri,
                    "languageId": language_id,
                    "version": 1,
                    "text": text,
                }
            },
        )
        self._opened_documents[uri] = 1
        return True

    def start(self) -> bool:
        """Initialize the LSP server and wait for the response."""
        if self.process:
            return True
        try:
            # --header-insertion=never to avoid messy auto-includes during auditing
            # --background-index to ensure large projects are indexed in BCK
            # --pch-storage=memory for speed
            cmd = [
                self.clangd_path,
                "-log=verbose",
                "--header-insertion=never",
                "--background-index",
                "--pch-storage=memory"
            ]
            if self.compile_commands_path:
                cmd.append(f"--compile-commands-dir={self.compile_commands_path}")
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.project_root),
                bufsize=0
            )
            self._running = True
            # 2. Start reader and stderr threads
            self._reader_thread = threading.Thread(target=self._read_loop, name="LSPReader", daemon=True)
            self._reader_thread.start()
            
            self._stderr_thread = threading.Thread(target=self._stderr_loop, name="LSPStderr", daemon=True)
            self._stderr_thread.start()
            
            # Give it a tiny bit of time to see if it crashes immediately or succeeds starting
            time.sleep(0.5)
            if self.process.poll() is not None:
                ret = self.process.poll()
                return False
                
            # Send 'initialize' request without hard timeout for large projects
            logger.info(f"Initializing LSP for project: {self.project_root} (this may take a long time for 1M+ lines)")
            print(f"  [LSP] Initializing clangd for {self.project_root.name}...", flush=True)
            
            # Use a reasonable timeout for initialization
            resp = self.send_request("initialize", {
                "processId": os.getpid(),
                "rootPath": str(self.project_root),
                "rootUri": self.project_root.as_uri(),
                "capabilities": {
                    "window": {
                        "workDoneProgress": True
                    },
                    "textDocument": {
                        "definition": {"dynamicRegistration": True},
                        "references": {"dynamicRegistration": True},
                        "documentSymbol": {"hierarchicalDocumentSymbolSupport": True},
                        "hover": {"contentFormat": ["markdown", "plaintext"]}
                    },
                    "workspace": {
                        "symbol": {"dynamicRegistration": True}
                    }
                },
                "initializationOptions": {
                    "clangdFileStatus": True,
                    "backgroundIndex": True
                }
            }, timeout=60) 
            
            if resp:
                self.send_notification("initialized", {})
                self._initialized = True
                logger.info("LSP Client initialized successfully")
                
                # Wait for initial indexing to finish (or at least provide feedback)
                # We don't block forever here, but we allow the background thread to show progress
                print(f"  [LSP] Project indexing started for {self.project_root.name}...")
                return True
            else:
                logger.error("Failed to initialize LSP Client (timeout or error)")
                return False
        except Exception as e:
            logger.error(f"Failed to start clangd: {e}")
            return False

    def wait_for_indexing(self, timeout: int = 60, idle_threshold: float = 3.0) -> bool:
        """Wait until indexing is finished (no progress for a threshold)."""
        if not self._initialized:
            return False
        
        print(f"  [LSP] Waiting for indexing to start/settle (threshold: {idle_threshold}s)...")
        start_time = time.time()
        
        # 1. Wait for at least some initial progress to appear (or a short timeout)
        activity_detected = False
        initial_wait = 5.0
        while time.time() - start_time < initial_wait:
            if time.time() - self._last_progress_time < 0.5:
                activity_detected = True
                break
            time.sleep(0.1)
            
        # 2. Now wait for it to settle
        while time.time() - start_time < timeout:
            if time.time() - self._last_progress_time > idle_threshold:
                # No progress for a while, assume done
                if activity_detected:
                    print("\n  [LSP] Indexing settled.")
                else:
                    print("\n  [LSP] Indexing settled (no activity detected).")
                return True
            time.sleep(0.5)
        
        print("\n  [LSP] Indexing wait timed out.")
        return False

    def stop(self):
        """Stop the clangd process."""
        self._running = False
        if self.process:
            self.send_notification("exit", {})
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self._reader_thread:
            self._reader_thread.join(timeout=1)
        if self._stderr_thread:
            self._stderr_thread.join(timeout=1)

    def _read_loop(self):
        """Background thread to read JSON-RPC messages from stdout."""
        import os
        buffer = b""
        fd = None
        pending_length: Optional[int] = None
        while self._running and self.process and self.process.stdout:
            try:
                if fd is None:
                    fd = self.process.stdout.fileno()

                try:
                    chunk = os.read(fd, 4096)
                except (OSError, ValueError):
                    return
                if not chunk:
                    return

                buffer += chunk

                while True:
                    if pending_length is None:
                        header_end = buffer.find(b"\r\n\r\n")
                        if header_end == -1:
                            if len(buffer) > 1024 * 1024:
                                idx = buffer.rfind(b"Content-Length:")
                                buffer = buffer[idx:] if idx != -1 else b""
                            break

                        header_bytes = buffer[:header_end]
                        buffer = buffer[header_end + 4 :]

                        content_length = 0
                        for line in header_bytes.decode("utf-8", errors="replace").split("\r\n"):
                            if line.startswith("Content-Length:"):
                                try:
                                    content_length = int(line.split(":", 1)[1].strip())
                                except ValueError:
                                    content_length = 0
                                    break

                        if content_length <= 0:
                            logger.warning("Missing Content-Length header, or zero-length message.")
                            continue

                        pending_length = content_length

                    if pending_length is None or len(buffer) < pending_length:
                        break

                    content_bytes = buffer[:pending_length]
                    buffer = buffer[pending_length:]
                    pending_length = None

                    content = content_bytes.decode("utf-8", errors="replace")
                    try:
                        stripped = content.lstrip()
                        if not stripped:
                            continue
                        if stripped[0] not in "{[":
                            logger.debug("Non-JSON LSP payload ignored: %r", content[:200])
                            continue
                        message = json.loads(stripped)
                    except json.JSONDecodeError as exc:
                        logger.warning(f"JSON parse error: {exc}")
                        continue

                    if "id" in message:
                        msg_id = message["id"]
                        with self._lock:
                            self._responses[msg_id] = message
                    else:
                        # Notification or logging
                        method = message.get("method", "")
                        params = message.get("params", {})

                        if method == "window/logMessage":
                            msg_text = params.get("message", "")
                            logger.debug(f"[clangd] {msg_text}")
                            # Display indexing progress for user
                            # More inclusive check for progress
                            if any(
                                k in msg_text
                                for k in [
                                    "Indexing",
                                    "Building",
                                    "Parsing",
                                    "Checking",
                                    "Loading",
                                    "Scanning",
                                    "%",
                                ]
                            ):
                                if msg_text != self._last_msg:
                                    sys.stdout.write(f"\r  [LSP] {msg_text[:80]:<80}")
                                    sys.stdout.flush()
                                    self._last_msg = msg_text
                                self._last_progress_time = time.time()
                        elif method == "$/progress":
                            # Handle work done progress
                            value = params.get("value", {})
                            kind = value.get("kind", "")
                            if kind == "begin":
                                title = value.get("title", "Processing")
                                print(f"\n  [LSP] {title}...", flush=True)
                            elif kind == "report":
                                message_text = value.get("message", "")
                                percentage = value.get("percentage")
                                if percentage is not None:
                                    print(
                                        f"\r  [LSP] {message_text} ({percentage}%)",
                                        end="",
                                        flush=True,
                                    )
                                else:
                                    print(
                                        f"\r  [LSP] {message_text:<60}",
                                        end="",
                                        flush=True,
                                    )
                                self._last_progress_time = time.time()
                            elif kind == "end":
                                message_text = value.get("message", "Done")
                                print(f"\r  [LSP] {message_text:<60}", flush=True)
                        elif method == "textDocument/clangd.fileStatus":
                            # clangd-specific file status (shows TU analysis progress)
                            state = params.get("state", "")
                            uri = params.get("uri", "")
                            if state and uri:
                                filename = uri.split("/")[-1]
                                # Map states to more descriptive TU analysis messages
                                msg = f"{state}: {filename}"
                                if msg != self._last_msg:
                                    sys.stdout.write(f"\r  [LSP] {msg:<80}")
                                    sys.stdout.flush()
                                    self._last_msg = msg
                                self._last_progress_time = time.time()

            except Exception as e:
                if self._running:
                    logger.error(f"Error in LSP read loop: {e}")
                break

    def _stderr_loop(self):
        """Background thread to read from stderr (raw clangd logs)."""
        buffer = []
        while self._running and self.process and self.process.stderr:
            try:
                # Use os.read to bypass Python's io buffering and get bytes immediately
                fd = self.process.stderr.fileno()
                try:
                    chunk = os.read(fd, 1)
                except (OSError, ValueError):
                    break
                    
                if not chunk:
                    break
                
                char = chunk.decode("utf-8", errors="replace")
                if char == '\r' or char == '\n':
                    msg = "".join(buffer).strip()
                    buffer = []
                    
                    if msg:
                        # Strip ANSI escape codes (colors)
                        msg = ANSI_ESCAPE.sub('', msg)
                        
                        # Generic clangd log lines often contain useful progress
                        if any(k in msg for k in ["Indexing", "Building", "Parsing", "Scanning", "Checking", "Loading", "[", "%"]):
                            clean_msg = msg
                            if "]" in msg:
                                parts = msg.split("]", 1)
                                if len(parts) > 1:
                                    clean_msg = parts[1].strip()
                            
                            if clean_msg and clean_msg != self._last_msg:
                                # Standard carriage return for progress
                                sys.stdout.write(f"\r  [LSP] {clean_msg[:80]:<80}")
                                sys.stdout.flush()
                                self._last_msg = clean_msg
                                self._last_progress_time = time.time()
                else:
                    buffer.append(char)
                    if len(buffer) > 1024:
                        buffer = buffer[-1024:]
            except Exception:
                break

    def send_request(self, method: str, params: Any, timeout: Optional[int] = 30) -> Optional[Any]:
        """Send a JSON-RPC request and wait for the response."""
        if not self.process or not self.process.stdin:
            return None
        
        with self._lock:
            msg_id = self._id_counter
            self._id_counter += 1
            
        message = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": method,
            "params": params
        }
        
        content = json.dumps(message)
        header = f"Content-Length: {len(content)}\r\n\r\n"
        
        try:
            with self._io_lock:
                self.process.stdin.write(header.encode("utf-8"))
                self.process.stdin.write(content.encode("utf-8"))
                self.process.stdin.flush()
        except Exception as e:
            logger.error(f"Failed to send LSP request: {e}")
            return None
            
        # Wait for response
        start_time = time.time()
        deadline = start_time + timeout if timeout is not None else float('inf')
        
        while time.time() < deadline:
            with self._lock:
                if msg_id in self._responses:
                    resp = self._responses.pop(msg_id)
                    if "error" in resp:
                        logger.error(f"LSP error for {method}: {resp['error']}")
                        return None
                    return resp.get("result")
            
            # If progress is being made, extend the deadline (if not infinite already)
            if timeout is not None and time.time() - self._last_progress_time < 2.0:
                # Progress was detected recently, extend deadline
                deadline = time.time() + timeout
                
            time.sleep(0.1)
            
        logger.error(f"LSP request {method} timed out after {timeout}s (even with progress resets)")
        return None

    def send_notification(self, method: str, params: Any):
        """Send a JSON-RPC notification."""
        if not self.process or not self.process.stdin:
            return
            
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params
        }
        
        content = json.dumps(message)
        header = f"Content-Length: {len(content)}\r\n\r\n"
        
        try:
            with self._io_lock:
                self.process.stdin.write(header.encode("utf-8"))
                self.process.stdin.write(content.encode("utf-8"))
                self.process.stdin.flush()
        except Exception as e:
            logger.error(f"Failed to send LSP notification: {e}")

    def get_definition(self, file_path: Path, line: int, character: int) -> List[Dict[str, Any]]:
        """textDocument/definition"""
        params = {
            "textDocument": {"uri": file_path.as_uri()},
            "position": {"line": line - 1, "character": character}
        }
        result = self.send_request("textDocument/definition", params)
        if not result:
            return []
        if isinstance(result, dict):
            return [result]
        return result

    def get_references(self, file_path: Path, line: int, character: int) -> List[Dict[str, Any]]:
        """textDocument/references"""
        params = {
            "textDocument": {"uri": file_path.as_uri()},
            "position": {"line": line - 1, "character": character},
            "context": {"includeDeclaration": True}
        }
        result = self.send_request("textDocument/references", params)
        return result if result else []

    def get_type_definition(self, file_path: Path, line: int, character: int) -> List[Dict[str, Any]]:
        """textDocument/typeDefinition"""
        params = {
            "textDocument": {"uri": file_path.as_uri()},
            "position": {"line": line - 1, "character": character}
        }
        result = self.send_request("textDocument/typeDefinition", params)
        if not result:
            return []
        if isinstance(result, dict):
            return [result]
        return result

    def get_document_symbols(self, file_path: Path) -> List[Dict[str, Any]]:
        """textDocument/documentSymbol"""
        self.open_document(file_path)
        params = {
            "textDocument": {"uri": file_path.as_uri()}
        }
        result = self.send_request("textDocument/documentSymbol", params)
        if result:
            return result
        for attempt in range(2):
            logger.info(
                "Retrying documentSymbol for %s (attempt %d/2)",
                file_path,
                attempt + 1,
            )
            time.sleep(2 ** attempt)
            result = self.send_request("textDocument/documentSymbol", params)
            if result:
                return result
        return []

    def get_workspace_symbols(self, query: str) -> List[Dict[str, Any]]:
        """workspace/symbol"""
        params = {"query": query}
        result = self.send_request("workspace/symbol", params)
        return result if result else []

    def get_hover(self, file_path: Path, line: int, character: int) -> Optional[Dict[str, Any]]:
        """textDocument/hover"""
        params = {
            "textDocument": {"uri": file_path.as_uri()},
            "position": {"line": line - 1, "character": character}
        }
        return self.send_request("textDocument/hover", params)
