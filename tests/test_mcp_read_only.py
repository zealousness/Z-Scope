from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from zscope.cli.cli import main as cli
from zscope.config.config import ConfigLoader
from zscope.mcp.provider import ZScopeMcpProvider
from zscope.mcp.server import handle_jsonrpc_request
from zscope.tools.policy import ToolPolicy


def project(root, *, indexed=False, language="c_cpp"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "demo.c").write_text("int run(void) { return 1; } // needle\n", encoding="utf-8")
    config = {
        "config_version": 3,
        "llms": {
            "default": {
                "base_urls": ["http://localhost/v1"],
                "models": ["unused"],
                "api_key": "unused",
            }
        },
        "project": {"targets": [{"id": "main", **({"compile_commands": "build/compile_commands.json"} if language == "c_cpp" else {})}], "language": language},
        "scan": {"task": ""},
        "indexing": {"backend": "unified" if language == "c_cpp" else "java_unified"},
        "concurrency": {
            "entry_workers": 1,
            "validator_workers": 1,
            "investigator_workers": 1,
            "evidence_completion_workers": 1,
            "index_workers": 1,
            "llm_max_inflight": 1,
        },
    }
    if language == "c_cpp":
        config["concurrency"]["svf_workers"] = 1
    config_path = root / "zscope.yaml"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    if indexed:
        folder = root / ".zscope_knowledge"
        folder.mkdir()
        with sqlite3.connect(folder / "code_knowledge.db") as conn:
            conn.execute(
                "CREATE TABLE functions (name TEXT, file_path TEXT, start_line INT, end_line INT, signature TEXT, is_declaration INT)"
            )
            conn.execute('INSERT INTO functions VALUES ("run", "demo.c", 1, 1, "int run(void)", 0)')
    return config_path


def state(root):
    return {
        p.relative_to(root).as_posix(): (
            p.stat().st_mtime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest(),
        )
        for p in root.rglob("*")
        if p.is_file()
    }


@pytest.mark.parametrize("profile", ["read_only", "candidate_blind"])
@pytest.mark.parametrize("language", ["c_cpp", "java"])
def test_profile_startup_and_calls_do_not_start_backends_or_write(
    tmp_path, monkeypatch, profile, language
):
    path = project(tmp_path, indexed=True, language=language)

    def prohibited(*args, **kwargs):
        pytest.fail("mutating constructor/LLM/provider invoked")

    monkeypatch.setattr("zscope.retrieval.code_index.CodeIndex.__init__", prohibited)
    monkeypatch.setattr("zscope.snapshots.store.SnapshotStore.__init__", prohibited)
    monkeypatch.setattr("zscope.config.user_config_store.UserConfigStore.__init__", prohibited)
    monkeypatch.setattr("zscope.framework.llm_client.LLMClient.chat_completion", prohibited)
    monkeypatch.setattr("zscope.rules.extensions.preflight_rules", prohibited)
    before = state(tmp_path)
    config = ConfigLoader.load(str(path), read_only=True)
    provider = ZScopeMcpProvider(
        config, config_path=path, profile=profile, tool_policy=ToolPolicy.allow_all()
    )
    names = {t["name"] for t in provider.list_tools()}
    assert "zscope.scan.run" not in names
    assert ("zscope.findings.query" in names) == (profile == "read_only")
    assert all(t["annotations"]["readOnlyHint"] for t in provider.list_tools())
    found = provider.call_tool("zscope.code.search", {"query": "run"})
    assert found["status"] == "partial"
    symbol = found["data"]["symbols"][0]["symbol_id"]
    assert (
        provider.call_tool("zscope.semantic.context", {"kind": "function", "symbol_id": symbol})[
            "status"
        ]
        == "unavailable"
    )
    assert (
        provider.call_tool(
            "zscope.semantic.context",
            {"kind": "function", "symbol_id": symbol, "refresh_policy": "ensure_current"},
        )["status"]
        == "forbidden"
    )
    for name in ("zscope.scan.run", "zscope.knowledge.query", "run_scan"):
        assert provider.call_tool(name, {})["status"] == "forbidden"
    assert (
        provider.call_tool("zscope.code.read", {"file_path": "demo.c", "start_line": 1})["status"]
        == "ok"
    )
    assert (
        provider.call_tool(
            "zscope.code.read", {"file_path": "demo.c", "start_line": 1, "cwd": "/etc"}
        )["status"]
        == "invalid_request"
    )
    assert (
        provider.call_tool("zscope.graph.query", {"symbol_id": symbol, "relation": "call"})[
            "status"
        ]
        == "unavailable"
    )
    provider.close()
    assert state(tmp_path) == before


def test_profile_intersects_user_policy_and_blocks_direct_runtime(tmp_path):
    config = ConfigLoader.load(str(project(tmp_path)), read_only=True)
    provider = ZScopeMcpProvider(
        config,
        profile="candidate_blind",
        tool_policy=ToolPolicy(allowed_tools={"zscope.code.search", "zscope.scan.run"}),
    )
    assert [t["name"] for t in provider.list_tools()] == ["zscope.code.search"]
    assert (
        provider.call_tool("zscope.code.read", {"file_path": "demo.c", "start_line": 1})["status"]
        == "forbidden"
    )
    assert (
        provider.tools_runtime.execute_tool("query_static_findings", {}, enforce_policy=False)[
            "status"
        ]
        == "forbidden"
    )
    assert provider.list_resources() == []
    assert provider.list_prompts() == []
    for uri in (
        "zscope://reports/latest",
        "zscope://snapshots/list",
        "zscope://knowledge/stats",
        "zscope://config",
    ):
        with pytest.raises(PermissionError):
            provider.read_resource(uri)
    with pytest.raises(PermissionError):
        provider.get_prompt("zscope.entry_discovery")


def test_review_profile_reports_are_separate_from_blind_corpus(tmp_path):
    config = ConfigLoader.load(str(project(tmp_path)), read_only=True)
    (tmp_path / "report.json").write_text('{"findings": ["PRIVATE_VERDICT"]}')
    review = ZScopeMcpProvider(config, profile="read_only")
    assert "PRIVATE_VERDICT" in str(review.read_resource("zscope://reports/latest"))
    result = review.call_tool("zscope.code.search", {"scope": "text", "query": "PRIVATE_VERDICT"})
    assert result["data"]["matches"] == []
    assert (
        review.call_tool("zscope.code.read", {"file_path": "report.json", "start_line": 1})[
            "status"
        ]
        == "forbidden"
    )


@pytest.mark.parametrize("protocol", ["2024-11-05", "2025-06-18"])
@pytest.mark.parametrize("profile", ["read_only", "candidate_blind"])
def test_real_stdio_process_smoke_and_clean_stdout(tmp_path, protocol, profile):
    root = tmp_path / "project 中文 spaces"
    path = project(root)
    before = state(root)

    def req(i, method, params):
        return {"jsonrpc": "2.0", "id": i, "method": method, "params": params}

    messages = [
        req(1, "initialize", {"protocolVersion": protocol}),
        req(2, "tools/list", {}),
        req(
            3,
            "tools/call",
            {"name": "zscope.code.search", "arguments": {"scope": "text", "query": "needle"}},
        ),
        req(
            4,
            "tools/call",
            {"name": "zscope.code.read", "arguments": {"file_path": "demo.c", "start_line": 1}},
        ),
        req(5, "tools/call", {"name": "zscope.semantic.context", "arguments": {"kind": "summary"}}),
        req(6, "tools/call", {"name": "zscope.scan.run", "arguments": {}}),
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 100}},
        req(
            7,
            "tools/call",
            {"name": "zscope.code.search", "arguments": {"scope": "files", "query": "demo"}},
        ),
    ]
    process = subprocess.run(
        [sys.executable, "-m", "zscope.mcp.server", "--config", str(path), "--profile", profile],
        input="{broken\n" + "".join(json.dumps(x) + "\n" for x in messages),
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    assert responses[0]["error"]["code"] == -32700
    by_id = {item["id"]: item for item in responses[1:]}
    assert by_id[1]["result"]["protocolVersion"] == protocol
    tools = by_id[2]["result"]["tools"]
    assert len(tools) == (7 if profile == "read_only" else 5)
    expected_names = {
        "zscope.code.search",
        "zscope.code.read",
        "zscope.semantic.context",
        "zscope.graph.query",
        "zscope.flow.trace",
        "zscope.findings.query",
    }
    if profile == "read_only":
        expected_names.add("zscope.config.prepare")
    else:
        expected_names.remove("zscope.findings.query")
    assert {tool["name"] for tool in tools} == expected_names
    assert ("zscope.config.prepare" in expected_names) == (profile == "read_only")
    assert ("outputSchema" in tools[0]) == (protocol == "2025-06-18")

    def body(i):
        result = by_id[i]["result"]
        assert ("structuredContent" in result) == (protocol == "2025-06-18")
        return json.loads(result["content"][0]["text"])

    hit = body(3)["data"]["matches"][0]
    assert hit["file"] == "demo.c" and hit["line"] == 1
    assert "needle" in body(4)["data"]["source"]["code"]
    assert body(5)["status"] == "unavailable"
    assert body(6)["status"] == "forbidden"
    assert body(7)["data"]["matches"][0]["file"] == "demo.c"
    assert state(root) == before


def test_legacy_content_length_and_process_cancellation(tmp_path):
    path = project(tmp_path)
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}).encode()
    data = b"Content-Length: " + str(len(request)).encode() + b"\r\n\r\n" + request
    command = [
        sys.executable,
        "-m",
        "zscope.mcp.server",
        "--config",
        str(path),
        "--profile",
        "candidate_blind",
    ]
    result = subprocess.run(command, input=data, capture_output=True, timeout=30)
    assert result.returncode == 0
    header, body = result.stdout.split(b"\r\n\r\n", 1)
    assert int(header.split(b":")[1]) == len(body)
    assert json.loads(body)["id"] == 1
    before = state(tmp_path)
    process = subprocess.Popen(
        command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        process.stdin.write(json.dumps({"id": 1, "method": "initialize"}).encode() + b"\n")
        process.stdin.flush()
        assert json.loads(process.stdout.readline())["id"] == 1
        process.terminate()
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)
    assert state(tmp_path) == before


def test_cli_profile_routes_before_normal_preflight(tmp_path, monkeypatch):
    path = project(tmp_path)
    captured = {}
    monkeypatch.setattr(
        "zscope.mcp.server.run_stdio_server",
        lambda config, **kw: captured.update(config=config, **kw),
    )
    result = CliRunner().invoke(
        cli, ["-c", str(path), "--mcp-stdio", "--mcp-profile", "candidate_blind"]
    )
    assert result.exit_code == 0, result.output
    assert captured["profile"] == "candidate_blind"
    assert result.output == ""
    invalid = CliRunner().invoke(
        cli, ["-c", str(path), "--mcp-stdio", "--mcp-profile", "read_only", "--build-index"]
    )
    assert invalid.exit_code != 0


def test_cancellation_interrupts_owned_request_and_session_recovers():
    import queue
    import threading
    from zscope.common.cancellation import current_cancellation_token
    from zscope.mcp.server import JsonRpcStdioServer

    started = threading.Event()
    closed = threading.Event()
    incoming = queue.Queue()
    outgoing = queue.Queue()

    class Provider:
        profile = "candidate_blind"

        def call_tool(self, name, arguments):
            token = current_cancellation_token()
            started.set()
            assert token.wait(5), "cancellation was not delivered to running work"
            token.raise_if_cancelled()

        def close(self):
            closed.set()

    class Server(JsonRpcStdioServer):
        def _read_message(self):
            return incoming.get(timeout=10)

        def _write_message(self, payload, **kwargs):
            outgoing.put(payload)

    server = Server(Provider())
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    try:
        incoming.put(
            {"id": 1, "method": "tools/call", "params": {"name": "search", "arguments": {}}}
        )
        assert started.wait(5)
        incoming.put({"method": "notifications/cancelled", "params": {"requestId": 1}})
        assert outgoing.get(timeout=5)["error"]["code"] == -32800
        incoming.put({"id": 2, "method": "ping"})
        assert outgoing.get(timeout=5) == {"jsonrpc": "2.0", "id": 2, "result": {}}
    finally:
        incoming.put(None)
        worker.join(timeout=10)
    assert not worker.is_alive()
    assert closed.is_set()


def test_http_profile_preserves_auth_and_server_enforced_denial(tmp_path):
    import threading
    import urllib.error
    import urllib.request
    from zscope.mcp.http_server import create_http_server

    config = ConfigLoader.load(str(project(tmp_path)), read_only=True)
    provider = ZScopeMcpProvider(config, profile="candidate_blind")
    server = create_http_server(
        "127.0.0.1", 0, provider, auth_token="local-test", client_allowlist=["127.0.0.1"]
    )
    worker = threading.Thread(target=server.serve_forever)
    worker.start()
    url = f"http://127.0.0.1:{server.server_address[1]}/mcp"
    payload = json.dumps(
        {"id": 1, "method": "tools/call", "params": {"name": "zscope.scan.run", "arguments": {}}}
    ).encode()
    try:
        request = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(request, timeout=5)
        assert denied.value.code == 401
        request.add_header("Authorization", "Bearer local-test")
        with urllib.request.urlopen(request, timeout=5) as response:
            result = json.load(response)["result"]
        assert result["structuredContent"]["status"] == "forbidden"
    finally:
        server.shutdown()
        worker.join(timeout=5)
        server.server_close()
    assert not worker.is_alive()
