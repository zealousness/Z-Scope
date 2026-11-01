from pathlib import Path
import json

import pytest

from zscope.config.config import (
    AnalysisConfig,
    IndexingConfig,
    LLMConfig,
    ProjectConfig,
    ZScopeConfig,
)
from zscope.tools.policy import ToolPolicy, deny_sensitive_paths_hook
from zscope.tools.runtime import ToolsRuntime
from zscope.mcp.provider import ZScopeMcpProvider
from zscope.mcp.server import handle_jsonrpc_request
from zscope.mcp.security import validate_remote_mcp_security


class FakeCodeIndex:
    backend_name = "unified"
    language = "c_cpp"
    _index_epoch = 1
    _function_index = {
        "api_entry": {
            "name": "api_entry",
            "qualified_name": "api_entry",
            "signature": "void api_entry(void)",
            "file": "src/api.c",
            "start_line": 1,
            "end_line": 3,
        }
    }

    def list_functions(self, pattern=None, limit=100000, offset=0):
        return [f"func_{idx}" for idx in range(20)][:limit]

    def resolve_existing_file(self, file_path):
        return None

    def close(self):
        pass


class FakeSnapshotStore:
    snapshot_dir = Path(".")

    def list_snapshots(self):
        return []


def _config(tmp_path: Path) -> ZScopeConfig:
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    return ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(knowledge_db_path=str(tmp_path / "missing.db")),
        analysis=AnalysisConfig(snapshot_dir=str(tmp_path / "snapshots")),
        project=ProjectConfig(project_root=tmp_path),
    )


def _provider(
    tmp_path: Path,
    policy: ToolPolicy,
    *,
    max_result_chars: int = 100000,
) -> ZScopeMcpProvider:
    code_index = FakeCodeIndex()
    snapshots = FakeSnapshotStore()
    runtime = ToolsRuntime(code_index, snapshots, tool_policy=policy)
    return ZScopeMcpProvider(
        _config(tmp_path),
        code_index=code_index,
        snapshot_store=snapshots,
        tools_runtime=runtime,
        tool_policy=policy,
        max_result_chars=max_result_chars,
    )


def test_mcp_resource_policy_blocks_unlisted_resource(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_resources={"zscope://config"}))

    assert [resource["uri"] for resource in provider.list_resources()] == ["zscope://config"]
    with pytest.raises(PermissionError):
        provider.read_resource("zscope://knowledge/functions")


def test_mcp_config_resource_exposes_effective_depth_and_usage(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_resources={"zscope://config"}))
    provider.config.scan.depth = "deep"
    provider.config.scan_token_usage_ledger = None

    resource = provider.read_resource("zscope://config")
    payload = json.loads(resource["contents"][0]["text"])

    assert payload["scan"]["depth"] == "deep"
    assert payload["llm_usage"]["depth"] == "deep"
    assert "max_tokens" not in payload["llm_usage"]


def test_mcp_tool_policy_blocks_unlisted_tool(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.knowledge.query"}))

    result = provider.call_tool("zscope.entries.discover", {"max_candidates": 1})

    assert result["success"] is False
    assert result["policy_decision"] == "deny"


def test_mcp_lists_and_accepts_only_namespaced_tools(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.knowledge.query"}))

    names = {tool["name"] for tool in provider.list_tools()}
    result = provider.call_tool("zscope.knowledge.query", {"sql": "SELECT 1"})

    assert "zscope.knowledge.query" in names
    assert all("function" not in tool for tool in provider.list_tools())
    assert result["success"] is False
    assert result.get("policy_decision") is None
    assert "Knowledge DB not found" in result["error"]


def test_mcp_scan_tools_forward_strict_arguments_to_the_jobs_adapter(tmp_path: Path) -> None:
    # Boundary test only: it verifies the provider forwards the strict MCP
    # arguments to the shared jobs adapter verbatim.  The adapter itself is
    # exercised against the real persistent service in test_mcp_jobs.py.
    code_index = FakeCodeIndex()
    snapshots = FakeSnapshotStore()
    policy = ToolPolicy(allowed_tools={"zscope.scan.run", "zscope.scan.status"})
    runtime = ToolsRuntime(code_index, snapshots, tool_policy=policy)
    calls = []

    class RecordingAdapter:
        def start(self, arguments):
            calls.append(("start", arguments))
            return {
                "success": True,
                "data": {
                    "schema": "zscope.scan-jobs.v1",
                    "job": {
                        "job_id": "job_1",
                        "run_id": "run_1",
                        "revision": 1,
                        "input_revision": "ab" * 32,
                    },
                },
            }

        def status(self, arguments):
            calls.append(("status", arguments))
            return {
                "success": True,
                "data": {"schema": "zscope.scan-jobs.v1", "job": {"job_id": "job_1"}},
            }

    provider = ZScopeMcpProvider(
        _config(tmp_path),
        code_index=code_index,
        snapshot_store=snapshots,
        tools_runtime=runtime,
        tool_policy=policy,
        jobs_adapter=RecordingAdapter(),
    )

    names = {tool["name"] for tool in provider.list_tools()}
    run = provider.call_tool("zscope.scan.run", {"request_id": "req-1", "scan_depth": "balanced"})
    status = provider.call_tool("zscope.scan.status", {"job_id": "job_1"})

    assert {"zscope.scan.run", "zscope.scan.status"} <= names
    assert calls == [
        ("start", {"request_id": "req-1", "scan_depth": "balanced"}),
        ("status", {"job_id": "job_1"}),
    ]
    assert run["success"] is True
    assert run["data"]["job"]["input_revision"] == "ab" * 32
    assert status["data"]["job"]["job_id"] == "job_1"


def test_mcp_exposes_only_readonly_wiki_status_and_query(tmp_path: Path, monkeypatch) -> None:
    provider = _provider(
        tmp_path,
        ToolPolicy(allowed_tools={"zscope.wiki.status", "zscope.wiki.query"}),
    )
    provider.config.project.wiki.document_exclude = ["legacy/**"]
    calls = []
    monkeypatch.setattr(
        "zscope.mcp.provider.wiki_status",
        lambda project_root, *, state_dir: calls.append(("status", project_root, state_dir))
        or {"available": False},
    )

    def fake_query(project_root, **kwargs):
        calls.append(("query", project_root, kwargs))
        return {"schema_version": "zscope.validator-project-knowledge.v1"}

    monkeypatch.setattr("zscope.mcp.provider.wiki_query", fake_query)

    names = {tool["name"] for tool in provider.list_tools()}
    status = provider.call_tool("zscope.wiki.status")
    query = provider.call_tool(
        "zscope.wiki.query",
        {
            "subjects": ["parse_byte"],
            "fact_kind": "input_range",
            "candidate_file": "src/parser.c",
            "max_tokens": 512,
        },
    )

    assert names == {"zscope.wiki.status", "zscope.wiki.query"}
    assert status == {"success": True, "data": {"available": False}}
    assert query["success"] is True
    assert calls[0][0] == "status"
    assert calls[1][0] == "query"
    assert calls[1][2]["subjects"] == ["parse_byte"]
    assert calls[1][2]["overrides"]["exclude"] == ["legacy/**"]
    assert "project_root" not in calls[1][2]
    assert not any("build" in name or "rollback" in name for name in names)


def test_mcp_wiki_query_rejects_invalid_arguments_but_allows_large_explicit_budget(
    tmp_path: Path,
) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.wiki.query"}))

    missing_subject = provider.call_tool("zscope.wiki.query", {})
    large_budget = provider.call_tool(
        "zscope.wiki.query",
        {"subjects": ["parse_byte"], "max_tokens": 3501},
    )
    too_small_budget = provider.call_tool(
        "zscope.wiki.query",
        {"subjects": ["parse_byte"], "max_tokens": 255},
    )

    assert missing_subject["success"] is False
    assert "subjects" in missing_subject["error"]
    assert large_budget["success"] is True
    assert too_small_budget["success"] is False
    assert "max_tokens" in too_small_budget["error"]


def test_mcp_wiki_query_rejects_unsafe_path_before_control_call(
    tmp_path: Path,
    monkeypatch,
) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.wiki.query"}))
    called = False

    def fake_query(*_args, **_kwargs):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr("zscope.mcp.provider.wiki_query", fake_query)
    result = provider.call_tool(
        "zscope.wiki.query",
        {"subjects": ["parse_byte"], "candidate_file": "../secret.md"},
    )

    assert result["success"] is False
    assert "candidate_file" in result["error"]
    assert called is False


def test_mcp_wiki_control_does_not_expose_internal_exception_text(
    tmp_path: Path,
    monkeypatch,
) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.wiki.query"}))
    monkeypatch.setattr(
        "zscope.mcp.provider.wiki_query",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("secret /home/private/wiki")),
    )

    result = provider.call_tool(
        "zscope.wiki.query",
        {"subjects": ["parse_byte"]},
    )

    assert result == {
        "success": False,
        "error": "Wiki control operation is unavailable.",
    }


def test_mcp_sensitive_path_hook_blocks_secret_file_tool(tmp_path: Path) -> None:
    provider = _provider(
        tmp_path,
        ToolPolicy(
            allowed_tools={"zscope.code.read"},
            pre_hooks=[deny_sensitive_paths_hook],
        ),
    )

    result = provider.call_tool(
        "zscope.code.read",
        {"file_path": "zscope.local.env", "start_line": 1, "end_line": 1},
    )

    assert result["success"] is False
    assert result["status"] == "forbidden"
    assert "sensitive path" in result["error"]["message"]


def test_mcp_query_knowledge_rejects_unsafe_sql_before_db_access(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.knowledge.query"}))

    result = provider.call_tool(
        "zscope.knowledge.query",
        {"sql": "SELECT 1; DROP TABLE functions"},
    )

    assert result["success"] is False
    assert "Multiple SQL statements" in result["error"]


def test_mcp_resource_read_supports_pagination(tmp_path: Path) -> None:
    provider = _provider(
        tmp_path,
        ToolPolicy(allowed_resources={"zscope://knowledge/functions"}),
    )

    result = provider.read_resource("zscope://knowledge/functions?limit=3&offset=4")
    text = result["contents"][0]["text"]

    assert '"func_4"' in text
    assert '"func_6"' in text
    assert '"returned": 3' in text
    assert '"has_more": true' in text


def test_mcp_resource_read_truncates_oversized_payload(tmp_path: Path) -> None:
    provider = _provider(
        tmp_path,
        ToolPolicy(allowed_resources={"zscope://knowledge/functions"}),
        max_result_chars=1000,
    )
    provider.code_index.list_functions = lambda pattern=None, limit=100000: [
        f"func_{idx}_" + ("x" * 200) for idx in range(20)
    ][:limit]

    result = provider.read_resource("zscope://knowledge/functions?limit=20")
    text = result["contents"][0]["text"]

    assert '"truncated": true' in text
    assert "request a smaller page" in text


def test_mcp_post_hook_runs_after_tool_result(tmp_path: Path) -> None:
    calls = []

    def post_hook(payload):
        calls.append(payload)
        return None

    provider = _provider(
        tmp_path,
        ToolPolicy(
            allowed_tools={"zscope.code.search"},
            post_hooks=[post_hook],
        ),
    )

    result = provider.call_tool("zscope.code.search", {"query": "api"})

    assert result["success"] is True
    assert calls
    assert calls[0]["actor"] == "mcp"
    assert calls[0]["name"] == "zscope.code.search"


def test_mcp_analysis_tool_rejects_non_object_arguments(tmp_path: Path) -> None:
    provider = _provider(
        tmp_path,
        ToolPolicy(allowed_tools={"zscope.code.search"}),
    )

    result = provider.call_tool("zscope.code.search", [])  # type: ignore[arg-type]

    assert result["success"] is False
    assert result["status"] == "invalid_request"
    assert result["error"]["path"] == "$"


def test_mcp_provider_uses_configured_audit_log_without_explicit_policy(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.analysis.tool_audit_log = "tool_audit.jsonl"
    provider = ZScopeMcpProvider(
        config,
        code_index=FakeCodeIndex(),
        snapshot_store=FakeSnapshotStore(),
    )

    result = provider.call_tool("zscope.code.search", {"query": "api", "limit": 1})

    audit_log = tmp_path / "tool_audit.jsonl"
    assert result["success"] is True
    assert audit_log.exists()
    events = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert any(event["name"] == "zscope.code.search" for event in events)


def test_remote_mcp_security_validation_requires_https_audience_and_scopes() -> None:
    errors = validate_remote_mcp_security(
        {
            "url": "http://example.test/mcp",
            "transport": "streamable-http",
            "oauth_token_env": "MCP_TOKEN",
            "forward_user_token": True,
            "scopes": ["*"],
        }
    )

    assert any("https" in error for error in errors)
    assert any("ambient user token" in error for error in errors)
    assert any("audience or resource" in error for error in errors)
    assert any("too broad" in error for error in errors)


def _seed_knowledge_db(tmp_path: Path) -> Path:
    import sqlite3

    db_path = tmp_path / "knowledge.db"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE functions (name TEXT)")
        conn.executemany(
            "INSERT INTO functions (name) VALUES (?)",
            [(f"func_{index:02d}",) for index in range(12)],
        )
    return db_path


def _knowledge_provider(
    tmp_path: Path,
    policy: ToolPolicy,
    db_path: Path,
) -> ZScopeMcpProvider:
    llm = LLMConfig(api_key="test", base_url="http://localhost", models=["test"])
    config = ZScopeConfig(
        llm=llm,
        llms={"default": llm},
        indexing=IndexingConfig(knowledge_db_path=str(db_path)),
        analysis=AnalysisConfig(snapshot_dir=str(tmp_path / "snapshots")),
        project=ProjectConfig(project_root=tmp_path),
    )
    code_index = FakeCodeIndex()
    snapshots = FakeSnapshotStore()
    runtime = ToolsRuntime(code_index, snapshots, tool_policy=policy)
    return ZScopeMcpProvider(
        config,
        code_index=code_index,
        snapshot_store=snapshots,
        tools_runtime=runtime,
        tool_policy=policy,
    )


def test_mcp_query_knowledge_pages_with_offset_and_has_more(tmp_path: Path) -> None:
    db_path = _seed_knowledge_db(tmp_path)
    provider = _knowledge_provider(
        tmp_path,
        ToolPolicy(allowed_tools={"zscope.knowledge.query"}),
        db_path,
    )
    sql = "SELECT name FROM functions ORDER BY name"

    page = provider.call_tool("zscope.knowledge.query", {"sql": sql, "limit": 5, "offset": 2})
    last_page = provider.call_tool("zscope.knowledge.query", {"sql": sql, "limit": 5, "offset": 10})

    data = page["data"]
    assert [row["name"] for row in data["rows"]] == [f"func_{index:02d}" for index in range(2, 7)]
    assert data["count"] == 5
    assert data["offset"] == 2
    assert data["has_more"] is True
    assert "offset=7" in data["note"]
    assert last_page["data"]["rows"] == [{"name": "func_10"}, {"name": "func_11"}]
    assert last_page["data"]["has_more"] is False


def test_mcp_query_knowledge_respects_user_limit_clause(tmp_path: Path) -> None:
    db_path = _seed_knowledge_db(tmp_path)
    provider = _knowledge_provider(
        tmp_path,
        ToolPolicy(allowed_tools={"zscope.knowledge.query"}),
        db_path,
    )

    bounded = provider.call_tool(
        "zscope.knowledge.query", {"sql": "SELECT name FROM functions ORDER BY name LIMIT 3"}
    )
    paged = provider.call_tool(
        "zscope.knowledge.query",
        {"sql": "SELECT name FROM functions ORDER BY name LIMIT 3", "offset": 2},
    )

    assert bounded["data"]["count"] == 3
    assert bounded["data"]["has_more"] is False
    assert [row["name"] for row in bounded["data"]["rows"]] == [
        "func_00",
        "func_01",
        "func_02",
    ]
    assert [row["name"] for row in paged["data"]["rows"]] == ["func_02"]


def test_mcp_analysis_result_over_limit_keeps_valid_envelope(tmp_path: Path) -> None:
    provider = _provider(
        tmp_path,
        ToolPolicy(allowed_tools={"zscope.code.search"}),
        max_result_chars=1000,
    )
    provider.code_index._function_index = {
        f"func_{index}": {
            "name": f"func_{index}_" + "x" * 200,
            "qualified_name": f"func_{index}_" + "x" * 200,
            "signature": "void f(void)",
            "file": f"src/f{index}.c",
            "start_line": index + 1,
            "end_line": index + 2,
        }
        for index in range(20)
    }

    result = provider.call_tool("zscope.code.search", {"query": "func_", "limit": 20})

    assert result["success"] is True
    assert result["status"] == "partial"
    assert result["page"]["has_more"] is True
    assert any("1000-character" in item for item in result["warnings"])


def test_mcp_modern_protocol_exposes_native_output_and_structured_content(
    tmp_path: Path,
) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.code.search"}))
    initialized = handle_jsonrpc_request(
        provider,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
    )
    listed = handle_jsonrpc_request(
        provider,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    called = handle_jsonrpc_request(
        provider,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "zscope.code.search",
                "arguments": {"query": "api_entry", "match_mode": "exact"},
            },
        },
    )

    assert initialized["result"]["protocolVersion"] == "2025-06-18"
    schema = listed["result"]["tools"][0]
    assert schema["name"] == "zscope.code.search"
    assert "inputSchema" in schema and "outputSchema" in schema
    assert schema["annotations"]["readOnlyHint"] is True
    result = called["result"]
    assert result["structuredContent"]["success"] is True
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    assert result["isError"] is False


def test_mcp_legacy_protocol_keeps_native_names_but_uses_text_results(
    tmp_path: Path,
) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.code.search"}))
    initialized = handle_jsonrpc_request(
        provider,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        },
    )
    listed = handle_jsonrpc_request(
        provider,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    called = handle_jsonrpc_request(
        provider,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "zscope.code.search",
                "arguments": {},
            },
        },
    )

    assert initialized["result"]["protocolVersion"] == "2024-11-05"
    schema = listed["result"]["tools"][0]
    assert schema["name"] == "zscope.code.search"
    assert "function" not in schema and "outputSchema" not in schema
    assert "structuredContent" not in called["result"]
    assert called["result"]["isError"] is True
    assert json.loads(called["result"]["content"][0]["text"])["status"] == "invalid_request"
