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
from zscope.mcp.security import validate_remote_mcp_security


class FakeCodeIndex:
    def list_functions(self, pattern=None, limit=100000):
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
        project=ProjectConfig(project_root=tmp_path, source_root=tmp_path),
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
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"query_knowledge"}))

    result = provider.call_tool("discover_entries", {"max_candidates": 1})

    assert result["success"] is False
    assert result["policy_decision"] == "deny"


def test_mcp_lists_and_accepts_namespaced_tool_alias(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.knowledge.query"}))

    names = {tool["function"]["name"] for tool in provider.list_tools()}
    result = provider.call_tool("zscope.knowledge.query", {"sql": "SELECT 1"})

    assert "zscope.knowledge.query" in names
    assert "query_knowledge" not in names
    assert result["success"] is False
    assert result.get("policy_decision") is None
    assert "Knowledge DB not found" in result["error"]


def test_mcp_scan_tool_forwards_only_depth_override(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"zscope.scan.run"}))
    calls = []
    provider.scan_request_service = type(
        "Service",
        (),
        {
            "start": staticmethod(
                lambda **kwargs: calls.append(kwargs)
                or {
                    "scan_id": "scan-1",
                    "status": "running",
                    "effective_scan": {
                        "depth": "balanced",
                    },
                    "llm_usage": {"consumed_tokens": 0},
                }
            )
        },
    )()

    names = {tool["function"]["name"] for tool in provider.list_tools()}
    result = provider.call_tool(
        "zscope.scan.run",
        {"scan_depth": "balanced"},
    )

    assert "zscope.scan.run" in names
    assert calls == [{"scan_depth": "balanced"}]
    assert result["success"] is True
    assert result["data"]["effective_scan"]["depth"] == "balanced"


def test_mcp_sensitive_path_hook_blocks_secret_file_tool(tmp_path: Path) -> None:
    provider = _provider(
        tmp_path,
        ToolPolicy(
            allowed_tools={"get_file_snippet"},
            pre_hooks=[deny_sensitive_paths_hook],
        ),
    )

    result = provider.call_tool(
        "get_file_snippet",
        {"file_path": "zscope.local.env", "start_line": 1, "end_line": 1},
    )

    assert result["success"] is False
    assert result["policy_decision"] == "deny"
    assert "sensitive path" in result["error"]


def test_mcp_query_knowledge_rejects_unsafe_sql_before_db_access(tmp_path: Path) -> None:
    provider = _provider(tmp_path, ToolPolicy(allowed_tools={"query_knowledge"}))

    result = provider.call_tool(
        "query_knowledge",
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
            allowed_tools={"list_known_functions"},
            post_hooks=[post_hook],
        ),
    )

    result = provider.call_tool("list_known_functions", {"limit": 2})

    assert result["success"] is True
    assert calls
    assert calls[0]["actor"] == "mcp"
    assert calls[0]["name"] == "list_known_functions"


def test_mcp_provider_uses_configured_audit_log_without_explicit_policy(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.analysis.tool_audit_log = "tool_audit.jsonl"
    provider = ZScopeMcpProvider(
        config,
        code_index=FakeCodeIndex(),
        snapshot_store=FakeSnapshotStore(),
    )

    result = provider.call_tool("list_known_functions", {"limit": 1})

    audit_log = tmp_path / "tool_audit.jsonl"
    assert result["success"] is True
    assert audit_log.exists()
    events = [json.loads(line) for line in audit_log.read_text(encoding="utf-8").splitlines()]
    assert any(event["name"] == "list_known_functions" for event in events)


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
