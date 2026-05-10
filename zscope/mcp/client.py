"""Minimal MCP stdio client used by local integrations and tests."""

from __future__ import annotations

import json
import subprocess
from itertools import count
from typing import Any, Dict, List, Optional, cast


class McpClientError(RuntimeError):
    pass


class StdioMcpClient:
    """Tiny JSON-RPC client for Z-SCOPE's local MCP server."""

    def __init__(self, command: List[str]):
        self.command = command
        self._ids = count(1)
        self.process: Optional[subprocess.Popen] = None

    def __enter__(self) -> "StdioMcpClient":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def start(self) -> None:
        if self.process:
            return
        self.process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise McpClientError("MCP client is not started.")
        request_id = next(self._ids)
        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
        self._write(request)
        response = self._read()
        if "error" in response:
            raise McpClientError(response["error"].get("message", "MCP error"))
        result = response.get("result", {})
        return cast(Dict[str, Any], result)

    def close(self) -> None:
        if not self.process:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.process = None

    def _write(self, payload: Dict[str, Any]) -> None:
        assert self.process and self.process.stdin
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.process.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
        self.process.stdin.write(body)
        self.process.stdin.flush()

    def _read(self) -> Dict[str, Any]:
        assert self.process and self.process.stdout
        first = self.process.stdout.readline()
        if not first:
            raise McpClientError("MCP server closed stdout.")
        if not first.lower().startswith(b"content-length:"):
            return cast(Dict[str, Any], json.loads(first.decode("utf-8")))
        length = int(first.split(b":", 1)[1].strip())
        while True:
            header = self.process.stdout.readline()
            if header in (b"\r\n", b"\n", b""):
                break
        body = self.process.stdout.read(length)
        return cast(Dict[str, Any], json.loads(body.decode("utf-8")))
