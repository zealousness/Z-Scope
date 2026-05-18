"""Security helpers for current and future remote MCP transports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence
from urllib.parse import urlsplit


WEAK_REMOTE_SCOPES = {"*", "all", "admin", "root", "write", "read_write"}


@dataclass
class RemoteMcpSecurityConfig:
    """Validation envelope for future HTTP/SSE MCP server connections."""

    url: str
    transport: str = "http"
    audience: str = ""
    resource: str = ""
    scopes: Sequence[str] = field(default_factory=tuple)
    oauth_token_env: str = ""
    forward_user_token: bool = False

    @classmethod
    def from_mapping(cls, data: Dict[str, Any]) -> "RemoteMcpSecurityConfig":
        return cls(
            url=str(data.get("url") or ""),
            transport=str(data.get("transport") or "http"),
            audience=str(data.get("audience") or ""),
            resource=str(data.get("resource") or ""),
            scopes=tuple(str(scope) for scope in data.get("scopes") or ()),
            oauth_token_env=str(data.get("oauth_token_env") or ""),
            forward_user_token=bool(data.get("forward_user_token")),
        )

    def validate(self) -> List[str]:
        errors: List[str] = []
        parsed = urlsplit(self.url)
        transport = self.transport.lower()
        is_remote_http = transport in {"http", "https", "sse", "streamable-http"}
        if is_remote_http and parsed.scheme != "https":
            errors.append("remote MCP HTTP transports require an https:// URL")
        if self.forward_user_token:
            errors.append("remote MCP must not forward an ambient user token")
        if self.oauth_token_env and not (self.audience or self.resource):
            errors.append("OAuth tokens require audience or resource binding")
        if self.oauth_token_env and not self.scopes:
            errors.append("OAuth tokens require explicit least-privilege scopes")
        for scope in self.scopes:
            lowered = scope.lower()
            if lowered in WEAK_REMOTE_SCOPES or lowered.endswith(":*"):
                errors.append(f"scope '{scope}' is too broad for remote MCP")
        return errors


def validate_remote_mcp_security(data: Dict[str, Any]) -> List[str]:
    """Return validation errors for a future remote MCP server config."""

    return RemoteMcpSecurityConfig.from_mapping(data).validate()
