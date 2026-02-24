from typing import Dict, Any, List
import json
import re
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient

SYSTEM_PROMPT = """You are the Analyst Agent for Z-SCOPE.
Perform structural analysis of a C/C++ project: identify key entry points, build call graphs, and determine security-critical files/functions.

Use the provided tools to explore the workspace and understand the code structure.

Output a JSON block wrapped in ```json ... ```. Two possible types:

[analysis_result] - Output after completing structural analysis:

```json
{
  "type": "analysis_result",
  "entry_points": [
    {"function": "cache_create", "file": "src/cache_core.c", "reason": "公共API，外部可直接调用"}
  ],
  "critical_functions": [
    {"function": "cache_put", "file": "src/cache_core.c", "risk": "涉及内存分配和指针操作"}
  ],
  "call_graph_summary": "cache_create -> hash_init -> malloc; cache_put -> hash_insert -> realloc",
  "recommended_audit_order": ["cache_create", "cache_put", "cache_get", "cache_delete"],
  "notes": "缓存模块核心函数均涉及动态内存管理，建议重点审计"
}
```

[schema_refinement] - Output when refining the snapshot schema for a specific task:

```json
{
  "type": "schema_refinement",
  "refined_schema": {
    "type": "object",
    "properties": {
      "func_name": {"type": "string"},
      "summary": {"type": "string"},
      "inputs": {"type": "array", "items": {"type": "object", "properties": {"name": {"type": "string"}, "type": {"type": "string"}, "role": {"type": "string"}}}},
      "outputs": {"type": "array", "items": {"type": "object", "properties": {"kind": {"type": "string"}, "type": {"type": "string"}, "meaning": {"type": "string"}}}},
      "resources": {"type": "object", "properties": {"allocates_memory": {"type": "boolean"}, "frees_memory": {"type": "boolean"}}},
      "error_handling": {"type": "object", "properties": {"checks_parameters": {"type": "boolean"}, "rollback_on_error": {"type": "string"}}},
      "concurrency": {"type": "object", "properties": {"thread_safe": {"type": "string"}, "uses_global_state": {"type": "boolean"}}},
      "task_specific_notes": {"type": "string", "description": "针对本次审计任务的特定检查点"}
    }
  }
}
```

All descriptive fields (reason, risk, notes, etc.): 用中文描述。
"""

class AnalystAgent(BaseAgent):
    """Agent for structural and dependency analysis."""
    
    def __init__(self, llm_client: LLMClient, tools: List[Any]):
        super().__init__(
            name="analyst_agent",
            description="Analyzes project structure and identifies audit targets."
        )
        self.llm_client = llm_client
        self.tools = tools
        self.tools_schema = [t.get_schema() for t in tools]

    def _tool_executor(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        for tool in self.tools:
            if tool.name == name:
                return tool.execute(args)
        return {"error": f"Unknown tool: {name}"}

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        mode = input_data.get("mode", "analysis")
        project_root = input_data.get("project_root", ".")
        task_description = input_data.get("task", "Explore the project and identify security-critical entry points.")
        base_schema = input_data.get("base_schema", {})

        if mode == "schema_refining":
            prompt = f"Task Context: {task_description}\nBase Schema: {json.dumps(base_schema, indent=2)}\n\nPlease refine the schema to include fields necessary for this specific audit task."
        else:
            prompt = f"Project Root: {project_root}\nTask: {task_description}"
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            result = self.llm_client.run_conversation_with_tools(
                messages=messages,
                tools_schema=self.tools_schema,
                tool_executor=self._tool_executor
            )
            
            content = result["content"]
            from ...common.utils import extract_json_blocks

            candidates = extract_json_blocks(content)
            for data in candidates:
                if isinstance(data, dict) and (data.get("type") in ["analysis_result", "schema_refinement"] or "entry_points" in data):
                    return AgentResponse(success=True, data=data)
            
            return AgentResponse(success=False, data={}, error="Failed to parse analysis JSON")
            
        except Exception as e:
            return AgentResponse(success=False, data={}, error=str(e))
