"""A small stdio JSON-RPC server exposing Z-SCOPE MCP primitives."""

from __future__ import annotations

import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Optional, cast

from .._version import __version__
from ..common.cancellation import CancellationToken, bind_cancellation_token
from ..config.config import ConfigLoader
from .provider import ZScopeMcpProvider, MCP_PROFILES

LATEST_PROTOCOL_VERSION = "2025-06-18"
LEGACY_PROTOCOL_VERSION = "2024-11-05"


def handle_jsonrpc_request(
    provider: ZScopeMcpProvider,
    request: Dict[str, Any],
    *,
    remote_experimental: bool = False,
) -> Optional[Dict[str, Any]]:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}

    try:
        result: Dict[str, Any]
        if method == "initialize":
            requested_protocol = str(params.get("protocolVersion") or LATEST_PROTOCOL_VERSION)
            negotiated_protocol = (
                LEGACY_PROTOCOL_VERSION
                if requested_protocol == LEGACY_PROTOCOL_VERSION
                else LATEST_PROTOCOL_VERSION
            )
            provider.protocol_version = negotiated_protocol
            result = {
                "protocolVersion": negotiated_protocol,
                "serverInfo": {
                    "name": "zscope-mcp",
                    "version": __version__,
                },
                "capabilities": {
                    "resources": {},
                    "prompts": {},
                    "tools": {},
                },
            }
            if remote_experimental:
                result["serverInfo"]["experimental"] = True
                result["_meta"] = {
                    "zscope/remoteExperimental": True,
                    "zscope/transportNotes": (
                        "Remote Streamable HTTP support is experimental. "
                        "Use a trusted network and explicit tool/resource policy."
                    ),
                }
        elif method == "ping":
            result = {}
        elif method == "resources/list":
            result = {"resources": provider.list_resources()}
        elif method == "resources/read":
            result = provider.read_resource(params["uri"])
        elif method == "prompts/list":
            result = {"prompts": provider.list_prompts()}
        elif method == "prompts/get":
            result = provider.get_prompt(params["name"], params.get("arguments"))
        elif method == "tools/list":
            result = {"tools": provider.list_tools(provider.protocol_version)}
        elif method == "tools/call":
            structured = provider.call_tool(params["name"], params.get("arguments"))
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            structured,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    }
                ],
                "isError": structured.get("success") is False,
            }
            if provider.protocol_version != LEGACY_PROTOCOL_VERSION:
                result["structuredContent"] = structured
        elif method and method.startswith("notifications/"):
            return None
        else:
            return jsonrpc_error(request_id, -32601, f"Method not found: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        return jsonrpc_error(
            request_id,
            -32000,
            (
                str(exc)
                if getattr(provider, "profile", "default") == "default"
                else "Request denied or unavailable in this profile"
            ),
        )


def jsonrpc_error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class JsonRpcStdioServer:
    """JSONL stdio with legacy framing and cooperative read-only cancellation."""

    def __init__(self, provider: ZScopeMcpProvider):
        self.provider = provider
        self._framing = "jsonl"
        self._write_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[Any, CancellationToken] = {}

    def serve_forever(self) -> None:
        # A single worker preserves session order and bounds concurrent access.
        # The reader remains available for cancellation of read-only queries.
        executor = (
            ThreadPoolExecutor(max_workers=1)
            if getattr(self.provider, "profile", "default") != "default"
            else None
        )
        try:
            while True:
                try:
                    request = self._read_message()
                except (ValueError, UnicodeError):
                    self._write_message(jsonrpc_error(None, -32700, "Invalid JSON-RPC message"))
                    continue
                if request is None:
                    break
                if not isinstance(request, dict):
                    self._write_message(
                        jsonrpc_error(None, -32600, "JSON-RPC request must be an object")
                    )
                    continue
                if executor is not None:
                    if request.get("method") == "notifications/cancelled":
                        params = request.get("params")
                        target = params.get("requestId") if isinstance(params, dict) else None
                        if isinstance(target, (str, int)):
                            with self._pending_lock:
                                token = self._pending.get(target)
                                if token is not None:
                                    token.cancel("client_cancelled")
                        continue
                    if str(request.get("method", "")).startswith("notifications/"):
                        continue
                    request_id = request.get("id")
                    if not isinstance(request_id, (str, int)):
                        self._write_message(jsonrpc_error(None, -32600, "A request id is required"))
                        continue
                    with self._pending_lock:
                        if request_id in self._pending or len(self._pending) >= 32:
                            self._write_message(
                                jsonrpc_error(
                                    request_id, -32600, "Duplicate id or request queue full"
                                )
                            )
                            continue
                        token = CancellationToken()
                        self._pending[request_id] = token
                    executor.submit(self._run_readonly, request, token, self._framing)
                    continue
                response = self._handle(request)
                if response is not None:
                    self._write_message(response)
        except BaseException:
            with self._pending_lock:
                for token in self._pending.values():
                    token.cancel("session_closed")
            raise
        finally:
            if executor is not None:
                executor.shutdown(wait=True)
            self.provider.close()

    def _run_readonly(
        self, request: Dict[str, Any], token: CancellationToken, framing: str
    ) -> None:
        request_id = request["id"]
        try:
            with bind_cancellation_token(token):
                response = None if token.is_cancelled() else self._handle(request)
                if token.is_cancelled():
                    response = jsonrpc_error(request_id, -32800, "Request cancelled")
                if response is not None:
                    self._write_message(response, framing=framing)
        finally:
            with self._pending_lock:
                self._pending.pop(request_id, None)

    def _handle(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return handle_jsonrpc_request(self.provider, request)

    def _read_message(self) -> Optional[Dict[str, Any]]:
        first = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if not first:
            return None
        if len(first) > 1024 * 1024:
            while first and not first.endswith(b"\n"):
                first = sys.stdin.buffer.readline(65536)
            raise ValueError("message too large")
        if first.lower().startswith(b"content-length:"):
            self._framing = "content-length"
            length = int(first.split(b":", 1)[1].strip())
            if not 0 <= length <= 1024 * 1024:
                raise ValueError("message too large")
            while True:
                header = sys.stdin.buffer.readline()
                if header in (b"\r\n", b"\n", b""):
                    break
            body = sys.stdin.buffer.read(length)
            return cast(Dict[str, Any], json.loads(body.decode("utf-8")))
        line = first.decode("utf-8").strip()
        self._framing = "jsonl"
        if not line:
            return None
        return cast(Dict[str, Any], json.loads(line))

    def _write_message(self, payload: Dict[str, Any], *, framing: str | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        with self._write_lock:
            if (framing or self._framing) == "content-length":
                sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
                sys.stdout.buffer.write(body)
            else:
                sys.stdout.buffer.write(body + b"\n")
            sys.stdout.buffer.flush()

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
        return jsonrpc_error(request_id, code, message)


def run_stdio_server(
    config_path: str,
    *,
    scan_depth: Optional[str] = None,
    profile: str = "default",
) -> None:
    config = ConfigLoader.load(
        config_path,
        scan_depth=scan_depth,
        read_only=profile != "default",
    )
    provider = ZScopeMcpProvider(config, config_path=Path(config_path), profile=profile)
    JsonRpcStdioServer(provider).serve_forever()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the local Z-SCOPE MCP stdio server.")
    parser.add_argument("--config", "-c", default="zscope.yaml", help="Path to zscope.yaml")
    parser.add_argument("--scan-depth", choices=("fast", "balanced", "deep"), default=None)
    parser.add_argument(
        "--profile", choices=MCP_PROFILES, default="default", help="Server-enforced access profile"
    )
    args = parser.parse_args()
    run_stdio_server(
        args.config,
        scan_depth=args.scan_depth,
        profile=args.profile,
    )


if __name__ == "__main__":
    main()
