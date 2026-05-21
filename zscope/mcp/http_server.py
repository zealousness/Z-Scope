"""Experimental Streamable HTTP transport for Z-SCOPE MCP."""

from __future__ import annotations

import json
import logging
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Union, cast
from urllib.parse import urlparse

from ..config.config import ConfigLoader
from .provider import ZScopeMcpProvider
from .security import validate_remote_mcp_server_options
from .server import handle_jsonrpc_request, jsonrpc_error

logger = logging.getLogger(__name__)

JsonRpcPayload = Union[Dict[str, Any], List[Dict[str, Any]]]

PROTOCOL_VERSION = "2024-11-05"
EXPERIMENTAL_HEADER_VALUE = "streamable-http"


class ZScopeStreamableHttpServer(ThreadingHTTPServer):
    """HTTP server carrying a shared MCP provider instance."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        provider: ZScopeMcpProvider,
        *,
        endpoint: str = "/mcp",
        auth_token: str = "",
        client_allowlist: Optional[Sequence[str]] = None,
    ) -> None:
        super().__init__(server_address, ZScopeMcpHttpHandler)
        self.provider = provider
        self.endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        self.auth_token = auth_token
        self.client_allowlist = {
            str(item).strip()
            for item in (client_allowlist or ())
            if str(item).strip()
        }

    def server_close(self) -> None:
        try:
            self.provider.close()
        finally:
            super().server_close()


class ZScopeMcpHttpHandler(BaseHTTPRequestHandler):
    """Request/response Streamable HTTP handler for JSON-RPC MCP messages."""

    server: ZScopeStreamableHttpServer

    def do_OPTIONS(self) -> None:
        if not self._is_mcp_endpoint():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorize_request():
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_common_headers()
        self.send_header("Allow", "POST, OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/healthz"}:
            self._send_json(
                HTTPStatus.OK,
                {
                    "name": "zscope-mcp",
                    "transport": "streamable-http",
                    "experimental": True,
                    "endpoint": self.server.endpoint,
                    "protocolVersion": PROTOCOL_VERSION,
                },
            )
            return
        if self._is_mcp_endpoint():
            self._send_json(
                HTTPStatus.METHOD_NOT_ALLOWED,
                {
                    "error": (
                        "This experimental Z-SCOPE MCP endpoint currently accepts "
                        "JSON-RPC requests via POST."
                    )
                },
                extra_headers={"Allow": "POST, OPTIONS"},
            )
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._is_mcp_endpoint():
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorize_request():
            return

        try:
            payload = self._read_json_payload()
            response = self._handle_payload(payload)
        except json.JSONDecodeError as exc:
            response = jsonrpc_error(None, -32700, f"Parse error: {exc}")
        except ValueError as exc:
            response = jsonrpc_error(None, -32600, str(exc))

        if response is None:
            self.send_response(HTTPStatus.ACCEPTED)
            self._send_common_headers()
            self.end_headers()
            return

        accept = self.headers.get("Accept", "")
        if "text/event-stream" in accept:
            self._send_sse_response(response)
        else:
            self._send_json(HTTPStatus.OK, response)

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("MCP HTTP %s - %s", self.address_string(), format % args)

    def _is_mcp_endpoint(self) -> bool:
        return urlparse(self.path).path == self.server.endpoint

    def _authorize_request(self) -> bool:
        client_host = str(self.client_address[0] if self.client_address else "")
        allowlist = self.server.client_allowlist
        if allowlist and client_host not in allowlist:
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "client not allowed"})
            return False

        expected_token = self.server.auth_token
        if expected_token:
            auth_header = self.headers.get("Authorization", "")
            if auth_header != f"Bearer {expected_token}":
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "missing or invalid bearer token"},
                    extra_headers={"WWW-Authenticate": "Bearer"},
                )
                return False
        return True

    def _read_json_payload(self) -> JsonRpcPayload:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid Content-Length header") from exc
        if length <= 0:
            raise ValueError("HTTP MCP requests must include a JSON-RPC body")
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8"))
        if isinstance(payload, dict):
            return cast(Dict[str, Any], payload)
        if isinstance(payload, list) and all(isinstance(item, dict) for item in payload):
            return cast(List[Dict[str, Any]], payload)
        raise ValueError("JSON-RPC payload must be an object or an array of objects")

    def _handle_payload(self, payload: JsonRpcPayload) -> Optional[JsonRpcPayload]:
        if isinstance(payload, list):
            responses: List[Dict[str, Any]] = []
            for item in payload:
                response = handle_jsonrpc_request(
                    self.server.provider,
                    item,
                    remote_experimental=True,
                )
                if response is not None:
                    responses.append(response)
            return responses or None
        return handle_jsonrpc_request(
            self.server.provider,
            payload,
            remote_experimental=True,
        )

    def _send_json(
        self,
        status: HTTPStatus,
        payload: Union[Dict[str, Any], List[Dict[str, Any]]],
        *,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_common_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_sse_response(self, payload: JsonRpcPayload) -> None:
        data = json.dumps(payload, ensure_ascii=False)
        body = f"event: message\ndata: {data}\n\n".encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self._send_common_headers()
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_common_headers(self) -> None:
        self.send_header("MCP-Protocol-Version", PROTOCOL_VERSION)
        self.send_header("X-ZScope-Experimental-MCP", EXPERIMENTAL_HEADER_VALUE)
        self.send_header("Cache-Control", "no-store")


def create_http_server(
    host: str,
    port: int,
    provider: ZScopeMcpProvider,
    *,
    endpoint: str = "/mcp",
    auth_token: str = "",
    client_allowlist: Optional[Sequence[str]] = None,
) -> ZScopeStreamableHttpServer:
    return ZScopeStreamableHttpServer(
        (host, port),
        provider,
        endpoint=endpoint,
        auth_token=auth_token,
        client_allowlist=client_allowlist,
    )


def run_http_server(
    config_path: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    endpoint: str = "/mcp",
    auth_token_env: str = "",
    client_allowlist: Optional[Sequence[str]] = None,
) -> None:
    auth_token = os.environ.get(auth_token_env, "") if auth_token_env else ""
    errors = validate_remote_mcp_server_options(
        host=host,
        auth_token_env=auth_token_env,
        auth_token=auth_token,
        client_allowlist=client_allowlist or (),
    )
    if errors:
        raise ValueError("; ".join(errors))
    config = ConfigLoader.load(config_path)
    provider = ZScopeMcpProvider(config)
    server = create_http_server(
        host,
        port,
        provider,
        endpoint=endpoint,
        auth_token=auth_token,
        client_allowlist=client_allowlist,
    )
    actual_host, actual_port = server.server_address[:2]
    logger.warning(
        "Starting experimental Z-SCOPE remote MCP Streamable HTTP server on http://%s:%s%s",
        actual_host,
        actual_port,
        endpoint,
    )
    logger.warning(
        "Remote MCP is experimental; use loopback binding or explicit token/allowlist controls."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping Z-SCOPE remote MCP server.")
    finally:
        server.server_close()
