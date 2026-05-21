from zscope.mcp.security import (
    is_loopback_bind_host,
    validate_remote_mcp_server_options,
)


def test_loopback_bind_host_detection() -> None:
    assert is_loopback_bind_host("127.0.0.1")
    assert is_loopback_bind_host("::1")
    assert is_loopback_bind_host("localhost")
    assert not is_loopback_bind_host("0.0.0.0")


def test_remote_mcp_bind_requires_token_env_and_client_allowlist() -> None:
    errors = validate_remote_mcp_server_options(host="0.0.0.0")

    assert "remote MCP HTTP binds require --mcp-auth-token-env" in errors
    assert "remote MCP HTTP binds require --mcp-client-allowlist" in errors


def test_remote_mcp_bind_accepts_explicit_controls() -> None:
    assert (
        validate_remote_mcp_server_options(
            host="0.0.0.0",
            auth_token_env="ZSCOPE_MCP_TOKEN",
            auth_token="secret",
            client_allowlist=["127.0.0.1"],
        )
        == []
    )
