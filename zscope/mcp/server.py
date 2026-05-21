"""A small stdio JSON-RPC server exposing Z-SCOPE MCP primitives."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional, cast

from ..config.config import ConfigLoader
from .provider import ZScopeMcpProvider


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
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "zscope-mcp",
                    "version": "0.1.0",
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
        elif method == "resources/list":
            result = {"resources": provider.list_resources()}
        elif method == "resources/read":
            result = provider.read_resource(params["uri"])
        elif method == "prompts/list":
            result = {"prompts": provider.list_prompts()}
        elif method == "prompts/get":
            result = provider.get_prompt(params["name"], params.get("arguments"))
        elif method == "tools/list":
            result = {"tools": provider.list_tools()}
        elif method == "tools/call":
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            provider.call_tool(params["name"], params.get("arguments")),
                            ensure_ascii=False,
                            indent=2,
                        ),
                    }
                ]
            }
        elif method and method.startswith("notifications/"):
            return None
        else:
            return jsonrpc_error(request_id, -32601, f"Method not found: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        return jsonrpc_error(request_id, -32000, str(exc))


def jsonrpc_error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class JsonRpcStdioServer:
    """Content-Length framed JSON-RPC server with newline JSON fallback."""

    def __init__(self, provider: ZScopeMcpProvider):
        self.provider = provider

    def serve_forever(self) -> None:
        try:
            while True:
                request = self._read_message()
                if request is None:
                    break
                response = self._handle(request)
                if response is not None:
                    self._write_message(response)
        finally:
            self.provider.close()

    def _handle(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return handle_jsonrpc_request(self.provider, request)

    def _read_message(self) -> Optional[Dict[str, Any]]:
        first = sys.stdin.buffer.readline()
        if not first:
            return None
        if first.lower().startswith(b"content-length:"):
            length = int(first.split(b":", 1)[1].strip())
            while True:
                header = sys.stdin.buffer.readline()
                if header in (b"\r\n", b"\n", b""):
                    break
            body = sys.stdin.buffer.read(length)
            return cast(Dict[str, Any], json.loads(body.decode("utf-8")))
        line = first.decode("utf-8").strip()
        if not line:
            return None
        return cast(Dict[str, Any], json.loads(line))

    def _write_message(self, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode("ascii"))
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
        return jsonrpc_error(request_id, code, message)


def run_stdio_server(config_path: str) -> None:
    config = ConfigLoader.load(config_path)
    provider = ZScopeMcpProvider(config)
    JsonRpcStdioServer(provider).serve_forever()


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run the local Z-SCOPE MCP stdio server.")
    parser.add_argument("--config", "-c", default="zscope.yaml", help="Path to zscope.yaml")
    args = parser.parse_args()
    run_stdio_server(args.config)


if __name__ == "__main__":
    main()
