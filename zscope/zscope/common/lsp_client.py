"""
LSP Client for communicating with clangd via JSON-RPC.
"""

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

logger = logging.getLogger(__name__)

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
        self._running = False
        self._initialized = False
        self._last_progress_time = time.time()

    def start(self) -> bool:
        """Start the clangd process."""
        try:
            # --header-insertion=never to avoid messy auto-includes during auditing
            # --background-index to ensure large projects are indexed in BCK
            # --pch-storage=memory for speed
            cmd = [
                self.clangd_path,
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
            
            # Send 'initialize' request with a longer timeout for large projects
            # but we use send_request which handles its own timeout.
            # For 1M+ lines, even 'initialize' might take some time if clangd does heavy lifting upfront.
            logger.info(f"Initializing LSP for project: {self.project_root}")
            resp = self.send_request("initialize", {
                "processId": os.getpid(),
                "rootPath": str(self.project_root),
                "rootUri": self.project_root.as_uri(),
                "capabilities": {
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
                    "clangdFileStatus": True
                }
            }, timeout=60) # Increased base timeout for initialize
            
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

    def _read_loop(self):
        """Background thread to read JSON-RPC messages from stdout."""
        while self._running and self.process and self.process.stdout:
            try:
                line = self.process.stdout.readline()
                if not line:
                    break
                
                line = line.decode("utf-8")
                if line.startswith("Content-Length:"):
                    length = int(line.split(":")[1].strip())
                    # Skip empty line after header
                    self.process.stdout.readline()
                    
                    content = self.process.stdout.read(length).decode("utf-8")
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
                            if "Indexing" in msg_text or "Building" in msg_text or "%" in msg_text:
                                print(f"\r  [LSP] {msg_text[:80]:<80}", end="", flush=True)
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
                            # clangd-specific file status
                            state = params.get("state", "")
                            uri = params.get("uri", "")
                            if state and uri:
                                filename = uri.split("/")[-1]
                                print(f"\r  [LSP] {state}: {filename:<50}", end="", flush=True)
                                self._last_progress_time = time.time()
            except Exception as e:
                if self._running:
                    logger.error(f"Error in LSP read loop: {e}")
                break

    def send_request(self, method: str, params: Any, timeout: int = 30) -> Optional[Any]:
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
        deadline = start_time + timeout
        
        while time.time() < deadline:
            with self._lock:
                if msg_id in self._responses:
                    resp = self._responses.pop(msg_id)
                    if "error" in resp:
                        logger.error(f"LSP error for {method}: {resp['error']}")
                        return None
                    return resp.get("result")
            
            # If progress is being made, extend the deadline
            if time.time() - self._last_progress_time < 2.0:
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
