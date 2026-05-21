import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

from zscope.config.config import AnalysisConfig, IndexingConfig, LLMConfig, ProjectConfig, ZScopeConfig
from zscope.tools.policy import ToolPolicy
from zscope.tools.runtime import ToolsRuntime
from zscope.mcp.http_server import create_http_server
from zscope.mcp.provider import ZScopeMcpProvider


class FakeCodeIndex:
    def list_functions(self, pattern=None, limit=100000):
        return ["api_entry"][:limit]

    def resolve_existing_file(self, file_path):
        return None

    def close(self):
        pass


class FakeSnapshotStore:
    def list_snapshots(self):
        return []


def _config(tmp_path: Path) -> ZScopeConfig:
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(knowledge_db_path=str(tmp_path / "missing.db")),
        analysis=AnalysisConfig(snapshot_dir=str(tmp_path / "snapshots")),
        project=ProjectConfig(project_root=tmp_path, source_root=tmp_path),
    )


def _provider(tmp_path: Path) -> ZScopeMcpProvider:
    code_index = FakeCodeIndex()
    snapshots = FakeSnapshotStore()
    policy = ToolPolicy(allowed_tools={"list_known_functions"})
    runtime = ToolsRuntime(code_index, snapshots, tool_policy=policy)
    return ZScopeMcpProvider(
        _config(tmp_path),
        code_index=code_index,
        snapshot_store=snapshots,
        tools_runtime=runtime,
        tool_policy=policy,
    )


def _request(url: str, payload=None, headers=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers=headers or {"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return response, response.read().decode("utf-8")


def test_streamable_http_initialize_marks_remote_mcp_experimental(tmp_path: Path) -> None:
    server = create_http_server("127.0.0.1", 0, _provider(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]

    try:
        response, body = _request(
            f"http://{host}:{port}/mcp",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            },
        )
        payload = json.loads(body)

        assert response.headers["X-ZScope-Experimental-MCP"] == "streamable-http"
        assert payload["result"]["serverInfo"]["experimental"] is True
        assert payload["result"]["_meta"]["zscope/remoteExperimental"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_streamable_http_tools_list_uses_provider_policy(tmp_path: Path) -> None:
    server = create_http_server("127.0.0.1", 0, _provider(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]

    try:
        _, body = _request(
            f"http://{host}:{port}/mcp",
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            },
        )
        names = {
            tool["function"]["name"]
            for tool in json.loads(body)["result"]["tools"]
        }

        assert names == {"list_known_functions"}
    finally:
        server.shutdown()
        server.server_close()


def test_streamable_http_can_return_sse_for_post_response(tmp_path: Path) -> None:
    server = create_http_server("127.0.0.1", 0, _provider(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]

    try:
        response, body = _request(
            f"http://{host}:{port}/mcp",
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "initialize",
                "params": {},
            },
            headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
        )

        assert response.headers["Content-Type"].startswith("text/event-stream")
        assert body.startswith("event: message\n")
        assert '"jsonrpc": "2.0"' in body
    finally:
        server.shutdown()
        server.server_close()


def test_streamable_http_health_endpoint_reports_experimental_status(tmp_path: Path) -> None:
    server = create_http_server("127.0.0.1", 0, _provider(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]

    try:
        response, body = _request(f"http://{host}:{port}/healthz")
        payload = json.loads(body)

        assert response.headers["X-ZScope-Experimental-MCP"] == "streamable-http"
        assert payload["transport"] == "streamable-http"
        assert payload["experimental"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_streamable_http_get_mcp_is_method_not_allowed(tmp_path: Path) -> None:
    server = create_http_server("127.0.0.1", 0, _provider(tmp_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]

    try:
        try:
            _request(f"http://{host}:{port}/mcp")
        except urllib.error.HTTPError as exc:
            assert exc.code == 405
            assert exc.headers["Allow"] == "POST, OPTIONS"
        else:
            raise AssertionError("GET /mcp should return 405")
    finally:
        server.shutdown()
        server.server_close()


def test_streamable_http_auth_token_is_required_when_configured(tmp_path: Path) -> None:
    server = create_http_server("127.0.0.1", 0, _provider(tmp_path), auth_token="secret")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    payload = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "initialize",
        "params": {},
    }

    try:
        try:
            _request(f"http://{host}:{port}/mcp", payload)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
            assert exc.headers["WWW-Authenticate"] == "Bearer"
        else:
            raise AssertionError("MCP HTTP should require bearer auth")

        response, body = _request(
            f"http://{host}:{port}/mcp",
            payload,
            headers={"Content-Type": "application/json", "Authorization": "Bearer secret"},
        )

        assert response.status == 200
        assert json.loads(body)["result"]["serverInfo"]["name"] == "zscope-mcp"
    finally:
        server.shutdown()
        server.server_close()


def test_streamable_http_client_allowlist_blocks_unlisted_clients(tmp_path: Path) -> None:
    server = create_http_server(
        "127.0.0.1",
        0,
        _provider(tmp_path),
        client_allowlist=["192.0.2.10"],
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]

    try:
        try:
            _request(
                f"http://{host}:{port}/mcp",
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "initialize",
                    "params": {},
                },
            )
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
        else:
            raise AssertionError("MCP HTTP should reject clients outside allowlist")
    finally:
        server.shutdown()
        server.server_close()
