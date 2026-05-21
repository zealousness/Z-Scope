"""HTTP server lifecycle wrapper for the Z-SCOPE dashboard."""

from __future__ import annotations

import socketserver
from pathlib import Path
from typing import Type


class DashboardHttpServer:
    """Own the dashboard bind address and serve_forever lifecycle."""

    def __init__(
        self,
        *,
        handler_class: Type[socketserver.BaseRequestHandler],
        web_dir: Path,
        host: str = "0.0.0.0",
        port: int = 8000,
    ):
        self.handler_class = handler_class
        self.web_dir = web_dir
        self.host = host
        self.port = port

    def display_url(self) -> str:
        if self.host in {"", "0.0.0.0"}:
            return f"http://localhost:{self.port} (bound to all interfaces)"
        return f"http://{self.host}:{self.port}"

    def serve_forever(self) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)
        with socketserver.TCPServer((self.host, self.port), self.handler_class) as httpd:
            print(f"Z-SCOPE Dashboard available at {self.display_url()}")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nShutting down server...")
                httpd.server_close()
