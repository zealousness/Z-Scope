"""HTTP server lifecycle wrapper for the Z-SCOPE dashboard."""

from __future__ import annotations

import socket
import socketserver
from pathlib import Path
from typing import List, Optional, Type

ALL_INTERFACE_HOSTS = {"", "0.0.0.0", "::"}


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
        if self.host in ALL_INTERFACE_HOSTS:
            return f"{', '.join(self.display_urls())} (bound to all interfaces)"
        return self.display_urls()[0]

    def display_urls(self) -> List[str]:
        if self.host in ALL_INTERFACE_HOSTS:
            urls = [f"http://localhost:{self.port}"]
            local_ip = self._detect_local_ip()
            if local_ip and local_ip not in {"127.0.0.1", "0.0.0.0", "::1"}:
                urls.append(f"http://{self._format_host(local_ip)}:{self.port}")
            return urls
        return [f"http://{self._format_host(self.host)}:{self.port}"]

    @staticmethod
    def _format_host(host: str) -> str:
        if ":" in host and not host.startswith("["):
            return f"[{host}]"
        return host

    @staticmethod
    def _detect_local_ip() -> Optional[str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                return str(sock.getsockname()[0])
        except OSError:
            try:
                return socket.gethostbyname(socket.gethostname())
            except OSError:
                return None

    def serve_forever(self) -> None:
        self.web_dir.mkdir(parents=True, exist_ok=True)
        with socketserver.TCPServer((self.host, self.port), self.handler_class) as httpd:
            print(f"Z-SCOPE Dashboard available at {self.display_url()}")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nShutting down server...")
                httpd.server_close()
