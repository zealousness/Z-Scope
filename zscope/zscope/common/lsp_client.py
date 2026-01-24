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
            
            # Send 'initialize' request
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
            })
            
            if resp:
                self.send_notification("initialized", {})
                self._initialized = True
                logger.info("LSP Client initialized successfully")
                return True
            else:
                logger.error("Failed to initialize LSP Client")
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
                        if message.get("method") == "window/logMessage":
                            logger.debug(f"LSP Log: {message.get('params', {}).get('message')}")
                        elif message.get("method") == "$/progress":
                            # Could track indexing progress here
                            pass
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
        while time.time() - start_time < timeout:
            with self._lock:
                if msg_id in self._responses:
                    resp = self._responses.pop(msg_id)
                    if "error" in resp:
                        logger.error(f"LSP error for {method}: {resp['error']}")
                        return None
                    return resp.get("result")
            time.sleep(0.1)
            
        logger.error(f"LSP request {method} timed out after {timeout}s")
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
