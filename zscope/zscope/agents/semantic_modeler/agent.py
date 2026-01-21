from typing import Dict, Any, List
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient
from ...tools.code_retrieval import GetFunctionImplTool
from ...tools.snapshot_tool import GetFunctionSnapshotTool
from ...tools.utils import ListFunctionsTool, GetFileSnippetTool

SYSTEM_PROMPT = """
You are the Semantic Modeler for Z-SCOPE. 
Your goal is to create a detailed semantic snapshot of the provided C function.
A snapshot should summarize the function's behavior, resources (memory, locks, IO), error handling, and concurrency attributes.

You MUST output a JSON block with type 'function_snapshot'.

Schema:
{
  "type": "function_snapshot",
  "func_name": "...",
  "location": "path:line-line",
  "summary": "Brief semantic summary...",
  "inputs": [{"name":"...","type":"...","role":"..."}],
  "outputs": [{"kind":"return","type":"...","meaning":"..."}],
  "resources": {
    "allocates_memory": true/false,
    "frees_memory": true/false,
    "locks": [{"lock":"...","mode":"...","balanced":true/false}],
    "file_io": true/false,
    "network_io": true/false
  },
  "error_handling": {
    "checks_parameters": true/false,
    "checks_alloc_failure": true/false,
    "rollback_on_error": "none|partial|full"
  },
  "concurrency": {
    "thread_safe": "unknown|likely_yes|likely_no",
    "uses_global_state": true/false
  },
  "semantic_fingerprint": {
    "normalized_hash_hint": "string summary of logic",
    "key_semantics": ["invariant1", "invariant2"]
  },
  "callees": ["func1", "func2"]
}

Focus ONLY on documenting the function accurately. Do not look for bugs unless they are part of the semantic behavior.
"""

class SemanticModeler(BaseAgent):
    """Agent for generating function snapshots."""
    
    def __init__(self, llm_client: LLMClient, tools: List[Any]):
        super().__init__(
            name="semantic_modeler",
            description="Generates semantic snapshots of C functions."
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
        func_name = input_data.get("func_name")
        func_code = input_data.get("code")
        location = input_data.get("location")

        prompt = f"Please model the following function: {func_name}\nLocation: {location}\nCode:\n```c\n{func_code}\n```"
        
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
            
            # Find JSON block
            import re
            import json
            content = result["content"]
            match = re.search(r"({.*})", content, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(1))
                    return AgentResponse(success=True, data=data)
                except:
                    pass
            
            return AgentResponse(success=False, data={}, error="Failed to parse snapshot JSON")
            
        except Exception as e:
            return AgentResponse(success=False, data={}, error=str(e))
