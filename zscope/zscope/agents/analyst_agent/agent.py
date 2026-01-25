from typing import Dict, Any, List
import json
import re
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient

SYSTEM_PROMPT = """
You are the Analyst Agent for Z-SCOPE. 
Your goal is to perform structural analysis of a C/C++ project.
You identify key entry points, build call graphs, and determine which files/functions are critical for security auditing.

You MUST output a JSON block with type 'analysis_result' or 'schema_refinement'.

If type is 'analysis_result':
{
  "type": "analysis_result",
  ... (same as before)
}

If type is 'schema_refinement':
{
  "type": "schema_refinement",
  "refined_schema": {
     "type": "object",
     "properties": {
        "func_name": {"type": "string"},
        "summary": {"type": "string"},
        "inputs": {"type": "array"},
        "outputs": {"type": "array"},
        "resources": {"type": "object", "properties": { ... }},
        "error_handling": {"type": "object", "properties": { ... }},
        "concurrency": {"type": "object", "properties": { ... }},
        "task_specific_notes": {"type": "string", "description": "Specific check based on user task"}
     }
  }
}

Use the provided tools to explore the workspace and understand the code structure.
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
