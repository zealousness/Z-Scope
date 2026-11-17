"""Regression cases found during the core-tool submission review."""

from copy import deepcopy
import json

import pytest

from zscope.agents.base import ToolCallingAgent
from zscope.common.cancellation import CancellationError
from zscope.framework.base import validate_function_arguments
from zscope.tools.contracts import (
    OUTPUT_SCHEMA,
    ContractTool,
    ToolContract,
    object_schema,
    tool_result,
)
from zscope.tools.policy import ToolPolicy
from zscope.tools.runtime import ToolsRuntime


def test_published_contracts_cannot_change_later_validation():
    contract = ToolContract(
        "example", "Example", object_schema({"count": {"type": "integer"}}), object_schema({})
    )
    wire = contract.openai_schema()
    wire["function"]["parameters"]["properties"]["count"]["type"] = "string"
    mcp = contract.mcp_schema("example")
    mcp["inputSchema"]["additionalProperties"] = True
    mcp["outputSchema"]["additionalProperties"] = True
    assert validate_function_arguments(contract.input_schema, {"count": "wrong"})
    assert contract.input_schema["additionalProperties"] is False
    assert contract.output_schema["additionalProperties"] is False


def test_audit_redacts_structured_error_and_hook_reason(tmp_path):
    policy = ToolPolicy(audit_log_path=tmp_path / "audit.jsonl")
    result = tool_result(
        status="internal_error",
        error={
            "code": "backend_error",
            "message": "Authorization: Bearer private-value failed",
            "path": None,
            "retryable": False,
        },
    )
    policy.run_post_hooks("tool", "read_code", {}, result=result)
    policy._audit("tool", "read_code", "deny", "token=private-value", {}, "test")
    assert "private-value" not in (tmp_path / "audit.jsonl").read_text()
    assert result["error"]["message"].endswith("private-value failed")


@pytest.mark.parametrize("items", [[{"x": 1, "y": 2}, {"y": 2, "x": 1}], [1, 1.0]])
def test_unique_items_uses_json_equality(items):
    schema = object_schema({"items": {"type": "array", "uniqueItems": True}})
    assert validate_function_arguments(schema, {"items": items})
    assert validate_function_arguments(schema, {"items": [True, 1]}) is None


def test_trimming_is_bounded_preserves_page_and_does_not_mutate_provider(monkeypatch):
    raw = tool_result(
        data={"matches": [{"text": "x" * 1000} for _ in range(500)]},
        page={
            "offset": 4,
            "limit": 500,
            "returned": 500,
            "total": 600,
            "has_more": True,
            "next_offset": 504,
        },
    )
    original = deepcopy(raw)
    dumps = json.dumps
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return dumps(*args, **kwargs)

    monkeypatch.setattr("zscope.tools.runtime.json.dumps", counted)
    result = ToolsRuntime._enforce_result_limit(raw, 4000)
    assert calls < 25
    assert raw == original
    assert len(dumps(result, ensure_ascii=False)) <= 4000
    assert result["data"]["matches"]
    assert result["page"]["next_offset"] == 4 + len(result["data"]["matches"])
    assert result["coverage"]["level"] == result["status"] == "partial"


def test_source_trim_preserves_whole_lines_and_continuation():
    raw = tool_result(
        data={
            "source": {
                "code": "line\n" * 500,
                "start_line": 10,
                "end_line": 509,
                "truncated": False,
                "next_start_line": None,
            },
            "definition": {"complete": True},
        }
    )
    original = deepcopy(raw)
    result = ToolsRuntime._enforce_result_limit(raw, 1000)
    source = result["data"]["source"]
    count = len(source["code"].splitlines())
    assert 0 < count < 500
    assert source["code"] == "line\n" * count
    assert source["end_line"] == 9 + count
    assert source["next_start_line"] == 10 + count
    assert result["data"]["definition"]["complete"] is False
    assert len(json.dumps(result, ensure_ascii=False)) <= 1000
    assert raw == original


class LargeRead(ContractTool):
    def __init__(self):
        super().__init__(ToolContract("read_code", "Read", object_schema({}), OUTPUT_SCHEMA))
        self.calls = 0

    def execute(self, arguments):
        self.calls += 1
        return tool_result(data={"source": {"code": "x\n" * 40_000, "start_line": 1}})


def test_cached_read_still_obeys_limit_after_cache_diagnostics_are_added():
    tool = LargeRead()
    runtime = ToolsRuntime(object(), object(), tools=[tool])
    cold = runtime.execute_tool("read_code", {})
    cached = runtime.execute_tool("read_code", {})
    assert tool.calls == 1
    for result in (cold, cached):
        assert result["data"]["source"]["code"]
        assert len(json.dumps(result, ensure_ascii=False)) <= 60_000


def test_provider_exception_body_does_not_reach_logs_or_model(caplog):
    class BrokenRead(LargeRead):
        def execute(self, arguments):
            raise RuntimeError("Authorization: Bearer private-value")

    runtime = ToolsRuntime(object(), object(), tools=[BrokenRead()])
    result = runtime.execute_tool("read_code", {})
    assert result["status"] == "internal_error"
    assert "RuntimeError" in result["error"]["message"]
    assert "private-value" not in json.dumps(result) + caplog.text


class ToolAgent(ToolCallingAgent):
    def run(self, input_data):
        raise NotImplementedError


def test_agent_and_runtime_share_safe_failures_and_propagate_cancellation(caplog):
    class BrokenRead(LargeRead):
        def execute(self, arguments):
            raise RuntimeError("Authorization: Bearer private-value")

    tool = BrokenRead()
    agent = ToolAgent(name="test", description="", llm_client=None, tools=[tool])
    runtime = ToolsRuntime(object(), object(), tools=[tool])
    assert agent._tool_executor("read_code", {}) == runtime.execute_tool("read_code", {})
    assert "private-value" not in caplog.text

    def cancelled(arguments):
        raise CancellationError("stopped")

    tool.execute = cancelled
    for executor in (agent._tool_executor, runtime.execute_tool):
        with pytest.raises(CancellationError):
            executor("read_code", {})


@pytest.mark.parametrize("separator", ["\u2028", "\v", "\f"])
def test_cached_definition_suffix_keeps_physical_source_lines(separator):
    runtime = ToolsRuntime(object(), object(), tools=[])
    runtime._read_code_cache.append(
        (
            {"symbol_id": "example", "start_line": 2, "end_line": 4},
            tool_result(
                data={
                    "symbol": {"location": {"start_line": 2}},
                    "source": {
                        "start_line": 2,
                        "end_line": 4,
                        "code": f'void f() {{\n  print("a{separator}b");\n}}\n',
                        "definition_end_line": 4,
                        "truncated": False,
                    },
                    "definition": {"complete": True},
                }
            ),
        )
    )
    result = runtime._cached_read_code({"symbol_id": "example", "start_line": 3, "end_line": 4})
    assert result["data"]["source"]["code"] == f'  print("a{separator}b");\n}}\n'
    assert result["data"]["definition"]["complete"] is False
    assert result["status"] == "ok"
