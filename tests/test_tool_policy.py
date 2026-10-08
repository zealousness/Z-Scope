import json
from pathlib import Path

from zscope.tools.policy import ToolPolicy, deny_sensitive_paths_hook
from zscope.tools.runtime import ToolsRuntime


class FakeCodeIndex:
    def list_functions(self, pattern=None, limit=50, offset=0):
        return ["api_entry"][:limit]

    def resolve_existing_file(self, file_path):
        return None


class FakeSnapshotStore:
    pass


def test_tool_policy_allowlist_blocks_unlisted_tool() -> None:
    policy = ToolPolicy(allowed_tools={"search_code"})
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    blocked = runtime.execute_tool("read_code", {"file_path": "demo.c", "start_line": 1})
    allowed = runtime.execute_tool("search_code", {"query": "api_entry"})

    assert blocked["success"] is False
    assert blocked["status"] == "forbidden"
    assert "allowlist" in blocked["error"]["message"]
    assert allowed["success"] is True
    assert allowed["status"] == "not_found"


def test_prompt_injection_cannot_expand_tool_allowlist() -> None:
    policy = ToolPolicy(allowed_tools={"search_code"})
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    result = runtime.execute_tool(
        "read_code",
        {"file_path": "ignore-prior-instructions.c", "start_line": 1},
        actor="simulated-llm",
    )

    assert result["success"] is False
    assert result["status"] == "forbidden"
    assert policy.audit_events[-1].actor == "simulated-llm"


def test_tool_policy_strict_schema_rejects_unknown_arguments() -> None:
    policy = ToolPolicy.allow_all(strict_schema=True)
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    result = runtime.execute_tool(
        "search_code",
        {"query": "api", "unexpected": True},
    )

    assert result["success"] is False
    assert result["status"] == "invalid_request"
    assert result["error"]["path"] == "unexpected"
    assert "unknown field" in result["error"]["message"]


def test_sensitive_path_pre_hook_blocks_secret_file_before_validation() -> None:
    policy = ToolPolicy(
        allowed_tools={"read_code"},
        pre_hooks=[deny_sensitive_paths_hook],
    )
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    result = runtime.execute_tool(
        "read_code",
        {"file_path": ".env", "start_line": 1, "end_line": 1},
    )

    assert result["success"] is False
    assert result["status"] == "forbidden"
    assert "sensitive path" in result["error"]["message"]


def test_read_code_file_range_uses_explicit_location(tmp_path) -> None:
    source = tmp_path / "demo.c"
    source.write_text("one\ntwo\nthree\n", encoding="utf-8")

    class SnippetCodeIndex(FakeCodeIndex):
        def __init__(self):
            self.line_count_calls = 0
            self.snippet_calls = 0

        def resolve_existing_file(self, file_path):
            assert file_path == "demo.c"
            return source

        def get_file_line_count(self, file_path):
            assert Path(file_path) == source
            self.line_count_calls += 1
            return 3

        def get_file_snippet(self, file_path, start_line, end_line, **_kwargs):
            self.snippet_calls += 1
            return {
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "code": "1 | one\n2 | two\n",
                "total_lines": 3,
                "truncated": False,
            }

    code_index = SnippetCodeIndex()
    runtime = ToolsRuntime(code_index, FakeSnapshotStore(), tool_policy=ToolPolicy.allow_all())

    result = runtime.execute_tool(
        "read_code",
        {"file_path": "demo.c", "start_line": 1, "end_line": 2},
    )

    assert result["success"] is True
    assert code_index.line_count_calls == 0
    assert code_index.snippet_calls == 1
    schema = next(
        schema["function"]
        for schema in runtime.get_tools_schema()
        if schema["function"]["name"] == "read_code"
    )
    assert "max_lines" in schema["parameters"]["properties"]
    assert "default_max_lines" not in schema["parameters"]["properties"]
    assert schema["parameters"]["additionalProperties"] is False


def test_read_code_size_limit_preserves_valid_json_and_whole_lines(tmp_path) -> None:
    source = tmp_path / "wide.c"
    source.write_text("x" * 70_000 + "\n", encoding="utf-8")

    class WideLineCodeIndex(FakeCodeIndex):
        project_root = tmp_path
        source_root = tmp_path

        def resolve_existing_file(self, file_path):
            return source if file_path == "wide.c" else None

        def get_file_snippet(self, file_path, start_line, end_line, **_kwargs):
            del end_line
            return {
                "file": file_path,
                "start_line": start_line,
                "end_line": start_line,
                "code": f"{start_line} | " + ("x" * 70_000) + "\n",
                "total_lines": 1,
                "truncated": False,
            }

    runtime = ToolsRuntime(WideLineCodeIndex(), FakeSnapshotStore())
    result = runtime.execute_tool(
        "read_code",
        {"file_path": "wide.c", "start_line": 1, "end_line": 1},
    )

    assert result["success"] is True
    assert result["status"] == "partial"
    assert len(json.dumps(result, ensure_ascii=False)) <= 60_000
    assert result["data"]["source"]["code"] == ""
    assert result["data"]["source"]["next_start_line"] == 1
    assert "exceeds" in " ".join(result["warnings"])


def test_tool_policy_redacts_sensitive_audit_arguments() -> None:
    policy = ToolPolicy(denied_tools={"search_code"})
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    runtime.execute_tool("search_code", {"api_key": "secret-value"})

    assert policy.audit_events
    assert policy.audit_events[-1].args_summary["api_key"] == "[redacted]"


def test_tool_policy_redacts_sensitive_audit_results() -> None:
    policy = ToolPolicy.allow_all()

    policy.run_post_hooks(
        "tool",
        "remote_mcp_probe",
        {},
        result={
            "success": False,
            "error": "Authorization: Bearer secret-value failed",
            "data": {"token": "secret-value", "count": 1},
        },
    )

    assert policy.audit_events[-1].result_summary["data.token"] == "[redacted]"
    assert (
        policy.audit_events[-1].result_summary["error"] == "Authorization: Bearer [redacted] failed"
    )
    assert "secret-value" not in json.dumps(policy.audit_events[-1].to_dict())


def test_tool_policy_ask_mode_blocks_until_approved() -> None:
    policy = ToolPolicy(ask_tools={"search_code"})
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    result = runtime.execute_tool("search_code", {"query": "api"})

    assert result["success"] is False
    assert result["status"] == "forbidden"
    assert "requires approval" in result["error"]["message"]


def test_tool_policy_post_hook_runs_after_successful_tool() -> None:
    calls = []

    def post_hook(payload):
        calls.append(payload)
        return None

    policy = ToolPolicy(
        allowed_tools={"search_code"},
        post_hooks=[post_hook],
    )
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    result = runtime.execute_tool("search_code", {"query": "api"}, actor="unit-test")

    assert result["success"] is True
    assert calls
    assert calls[0]["name"] == "search_code"
    assert calls[0]["actor"] == "unit-test"
    assert calls[0]["result"]["success"] is True
    assert calls[0]["duration_ms"] >= 0
    assert policy.audit_events[-1].action == "post"


def test_tool_policy_writes_jsonl_audit_log_with_redaction(tmp_path) -> None:
    audit_log = tmp_path / "tool_audit.jsonl"
    policy = ToolPolicy(
        denied_tools={"search_code"},
        audit_log_path=audit_log,
    )
    runtime = ToolsRuntime(FakeCodeIndex(), FakeSnapshotStore(), tool_policy=policy)

    runtime.execute_tool("search_code", {"api_key": "secret-value"})

    lines = audit_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["action"] == "deny"
    assert event["args_summary"]["api_key"] == "[redacted]"
    assert "secret-value" not in lines[0]
