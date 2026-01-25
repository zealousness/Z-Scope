from typing import Dict, Any, List
import json
import re
import logging
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient
from ...tools.code_retrieval import GetFunctionImplTool
from ...tools.snapshot_tool import GetFunctionSnapshotTool
from ...tools.utils import ListFunctionsTool, GetFileSnippetTool

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are the Semantic Modeler for Z-SCOPE. 
Your goal is to create a detailed semantic snapshot of the provided C function based on a specific JSON schema.
A snapshot should summarize the function's behavior, resources, error handling, and other task-specific attributes.

You MUST output a JSON block that strictly follows the provided schema.

Target Schema:
{schema}

You MUST provide all descriptive fields (summary, meaning, key_semantics, etc.) in Chinese.

Special Attention:
1. **Resource Lifecycle**: For every resource (memory, fd, lock), explicitly state if it is allocated, deallocated, or transferred. 
2. **Error Paths**: Analyze what happens to acquired resources in every early return or error-handling branch.
3. **Contracts**: Document assumptions about input pointers (e.g., "must not be null", "may be null but handled").
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
        schema = input_data.get("schema", "{}")

        system_prompt = SYSTEM_PROMPT.format(schema=json.dumps(schema, indent=2, ensure_ascii=False))
        prompt = f"Please model the following function: {func_name}\nLocation: {location}\nCode:\n```c\n{func_code}\n```"
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]

        try:
            result = self.llm_client.run_conversation_with_tools(
                messages=messages,
                tools_schema=self.tools_schema,
                tool_executor=self._tool_executor
            )
            
            content = result["content"]
            conversation = result.get("conversation", [])

            from ...common.utils import extract_json_blocks, is_valid_snapshot
            
            # Search in result content and history
            all_text_sources = [content] + [msg.get("content", "") for msg in reversed(conversation) if msg.get("role") == "assistant"]
            
            for text in all_text_sources:
                if not text: continue
                candidates = extract_json_blocks(text)
                for data in candidates:
                    if is_valid_snapshot(data):
                        return AgentResponse(success=True, data=data)
                    if "function_snapshot" in data and is_valid_snapshot(data["function_snapshot"]):
                        return AgentResponse(success=True, data=data["function_snapshot"])
            
            logger.error(f"Failed to parse snapshot JSON for {func_name}. Content: {content}")
            return AgentResponse(success=False, data={}, error="Failed to parse snapshot JSON. See logs for full content.")
            
        except Exception as e:
            return AgentResponse(success=False, data={}, error=str(e))
