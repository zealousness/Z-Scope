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
    def __init__(self, project_root: Path, clangd_path: str = "clangd"):
        self.project_root = Path(project_root).resolve()
        self.clangd_path = clangd_path
        self.process: Optional[subprocess.Popen] = None
        self._id_counter = 0
        self._responses: Dict[int, Any] = {}
        self._lock = threading.Lock()
        self._reader_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._running = False
        self._initialized = False
        self._last_progress_time = time.time()
        self._last_msg = ""

    def start(self) -> bool:
        """Start the clangd process."""
        try:
            # --header-insertion=never to avoid messy auto-includes during auditing
            # --background-index to ensure large projects are indexed in BCK
            # --pch-storage=memory for speed
            cmd = [
                self.clangd_path,
                "-log=verbose",
                "--header-insertion=never",
                "--background-index",
                "--pch-storage=memory",
                f"--project-root={self.project_root}"
            ]
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.project_root),
                bufsize=0
            )
            self._running = True
            self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
            self._reader_thread.start()
            
            self._stderr_thread = threading.Thread(target=self._stderr_loop, daemon=True)
            self._stderr_thread.start()
            
            # Send 'initialize' request without hard timeout for large projects
            logger.info(f"Initializing LSP for project: {self.project_root} (this may take a long time for 1M+ lines)")
            print(f"  [LSP] Initializing clangd for {self.project_root.name}...")
            
            # Using timeout=0 or None to indicate infinite wait during initialization
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
            }, timeout=None) 
            
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
        while self._running and self.process and self.process.stdout:
            try:
                # Robust LSP header parsing
                line = self.process.stdout.readline()
                if not line:
                    break
                
                content_length = None
                line_str = line.decode("utf-8", errors="replace").strip()
                
                if line_str.startswith("Content-Length:"):
                    content_length = int(line_str.split(":")[1].strip())
                    
                    # Read remaining headers until empty line
                    while True:
                        header_line = self.process.stdout.readline().decode("utf-8", errors="replace").strip()
                        if not header_line:
                            break
                        if header_line.startswith("Content-Length:"):
                            content_length = int(header_line.split(":")[1].strip())
                    
                    if content_length is not None:
                        content = self.process.stdout.read(content_length).decode("utf-8", errors="replace")
                        message = json.loads(content)
                        
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
                                if any(k in msg_text for k in ["Indexing", "Building", "Parsing", "Checking", "Loading", "Scanning", "%"]):
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
                                        print(f"\r  [LSP] {message_text} ({percentage}%)", end="", flush=True)
                                    else:
                                        print(f"\r  [LSP] {message_text:<60}", end="", flush=True)
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
        params = {
            "textDocument": {"uri": file_path.as_uri()}
        }
        result = self.send_request("textDocument/documentSymbol", params)
        return result if result else []

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
