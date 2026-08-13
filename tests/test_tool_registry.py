from typing import Any, Dict

from zscope.agents.base import ToolCallingAgent
from zscope.core.analysis.analyzer import Analyzer
from zscope.framework.base import AgentResponse, BaseTool
from zscope.tools.call_graph import GetCallGraphTool
from zscope.tools.policy import ToolPolicy
from zscope.tools.registry import build_tool_registry
from zscope.tools.runtime import ToolsRuntime

EXPECTED_TOOL_NAMES = [
    "get_function_impl",
    "get_function_info",
    "get_function_snapshot",
    "get_security_semantics",
    "list_known_functions",
    "get_file_snippet",
    "get_callers",
    "get_type_info",
    "get_call_graph",
    "get_data_flow",
    "find_function_pointers",
    "query_pointer_alias",
    "verify_taint_reachability",
    "get_deep_call_context",
]


class EmptyCodeIndex:
    backend_name = "unified"


class EmptySnapshotStore:
    pass


class RecordingTool(BaseTool):
    def __init__(self, name: str, result: Dict[str, Any]) -> None:
        super().__init__(name=name, description=f"Description for {name}")
        self.result = result
        self.calls = []

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append(dict(arguments))
        return self.result

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "integer"}},
                    "required": ["value"],
                },
            },
        }


class MinimalAgent(ToolCallingAgent):
    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        return AgentResponse(success=True, data={})


def test_registry_contains_all_builtin_tools_in_stable_order() -> None:
    registry = build_tool_registry(EmptyCodeIndex(), EmptySnapshotStore())

    assert list(registry) == EXPECTED_TOOL_NAMES
    assert all(name == tool.name for name, tool in registry.items())
    assert [tool.get_schema()["function"]["name"] for tool in registry.values()] == (
        EXPECTED_TOOL_NAMES
    )


def test_runtime_schemas_are_generated_by_registered_tools() -> None:
    runtime = ToolsRuntime(EmptyCodeIndex(), EmptySnapshotStore())

    assert runtime.get_tools_schema(apply_policy=False) == [
        tool.get_schema() for tool in runtime._tools_by_name.values()
    ]


def test_runtime_dispatches_through_registered_tool() -> None:
    tool = RecordingTool("record", {"success": True, "data": {"ok": True}})
    runtime = ToolsRuntime(
        EmptyCodeIndex(),
        EmptySnapshotStore(),
        tools=[tool],
    )

    result = runtime.execute_tool("record", {"value": 3})

    assert result == {"success": True, "data": {"ok": True}}
    assert tool.calls == [{"value": 3}]


def test_runtime_and_agent_share_tool_argument_validation() -> None:
    runtime_tool = RecordingTool("record", {"success": True})
    runtime = ToolsRuntime(
        EmptyCodeIndex(),
        EmptySnapshotStore(),
        tools=[runtime_tool],
    )
    agent_tool = RecordingTool("record", {"success": True})
    agent = MinimalAgent(
        name="test_agent",
        description="test",
        llm_client=object(),
        tools=[agent_tool],
    )

    runtime_result = runtime.execute_tool("record", {"value": "bad"})
    agent_result = agent._tool_executor("record", {"value": "bad"})

    assert runtime_result == agent_result
    assert runtime_tool.calls == []
    assert agent_tool.calls == []


def test_runtime_and_agent_reject_non_object_arguments_before_execution() -> None:
    runtime_tool = RecordingTool("record", {"success": True})
    runtime = ToolsRuntime(
        EmptyCodeIndex(),
        EmptySnapshotStore(),
        tools=[runtime_tool],
    )
    agent_tool = RecordingTool("record", {"success": True})
    agent = MinimalAgent(
        name="test_agent",
        description="test",
        llm_client=object(),
        tools=[agent_tool],
    )

    runtime_result = runtime.execute_tool("record", [1, 2])
    agent_result = agent._tool_executor("record", [1, 2])

    assert runtime_result == agent_result
    assert runtime_tool.calls == []
    assert agent_tool.calls == []


def test_runtime_updates_location_and_autofills_file_snippet() -> None:
    info_tool = RecordingTool(
        "get_function_info",
        {
            "success": True,
            "data": {
                "matches": [
                    {
                        "file_path": "src/demo.c",
                        "start_line": 12,
                        "end_line": 30,
                    }
                ]
            },
        },
    )
    info_tool.get_schema = lambda: {
        "type": "function",
        "function": {
            "name": info_tool.name,
            "description": info_tool.description,
            "parameters": {
                "type": "object",
                "properties": {"value": {"type": "integer"}},
                "required": ["value"],
            },
        },
    }
    snippet_tool = RecordingTool(
        "get_file_snippet",
        {"success": True, "data": {"file": "src/demo.c"}},
    )
    snippet_tool.get_schema = lambda: {
        "type": "function",
        "function": {
            "name": snippet_tool.name,
            "description": snippet_tool.description,
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                },
                "required": ["file_path", "start_line"],
            },
        },
    }
    runtime = ToolsRuntime(
        EmptyCodeIndex(),
        EmptySnapshotStore(),
        tools=[info_tool, snippet_tool],
    )

    runtime.execute_tool("get_function_info", {"value": 1})
    result = runtime.execute_tool("get_file_snippet", {})

    assert result["success"] is True
    assert snippet_tool.calls == [{"file_path": "src/demo.c", "start_line": 12}]


def test_runtime_caches_negative_type_info_results() -> None:
    tool = RecordingTool(
        "get_type_info",
        {"success": False, "error": "Type 'missing' not found"},
    )
    tool.get_schema = lambda: {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": {
                "type": "object",
                "properties": {"type_name": {"type": "string"}},
                "required": ["type_name"],
            },
        },
    }
    runtime = ToolsRuntime(
        EmptyCodeIndex(),
        EmptySnapshotStore(),
        tools=[tool],
    )

    first = runtime.execute_tool("get_type_info", {"type_name": "missing"})
    second = runtime.execute_tool("get_type_info", {"type_name": "missing"})

    assert first["success"] is False
    assert second["cached_negative_result"] is True
    assert len(tool.calls) == 1


def test_call_graph_tool_honors_depth_during_registry_dispatch() -> None:
    class GraphCodeIndex:
        def get_callers(self, name, limit=30):
            return []

        def get_callees(self, name, limit=30):
            graph = {
                "root": [{"name": "child", "filename": "child.c"}],
                "child": [{"name": "leaf", "filename": "leaf.c"}],
            }
            return graph.get(name, [])[:limit]

    tool = GetCallGraphTool(GraphCodeIndex())
    runtime = ToolsRuntime(
        GraphCodeIndex(),
        EmptySnapshotStore(),
        tools=[tool],
    )

    result = runtime.execute_tool(
        "get_call_graph",
        {"func_name": "root", "depth": 2, "limit": 10},
    )

    assert [item["name"] for item in result["data"]["callees"]] == [
        "child",
        "leaf",
    ]


def test_analyzer_uses_registry_backend_grouping() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.code_index = EmptyCodeIndex()
    analyzer.snapshot_store = EmptySnapshotStore()
    analyzer.user_config = None

    advanced_tools = analyzer._get_tools(enable_on_demand_snapshots=True)
    advanced_names = [tool.name for tool in advanced_tools]
    analyzer.code_index.backend_name = "regex"
    base_tools = analyzer._get_tools(enable_on_demand_snapshots=False)
    base_names = [tool.name for tool in base_tools]

    assert advanced_names == EXPECTED_TOOL_NAMES
    assert base_names == EXPECTED_TOOL_NAMES[:8]
    assert advanced_tools[2].resolver is not None
    assert base_tools[2].resolver is None
