from typing import Any, Dict, List, cast
import json
import re
import logging
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient
from ...tools.code_retrieval import GetFunctionImplTool
from ...tools.snapshot_tool import GetFunctionSnapshotTool
from ...tools.utils import ListFunctionsTool, GetFileSnippetTool

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are the Semantic Modeler for Z-SCOPE.
Create a detailed semantic snapshot of the provided C function based on the JSON schema below.

Target Schema:
{schema}

Output a JSON block wrapped in ```json ... ``` that strictly follows the schema above.
All descriptive fields (summary, meaning, key_semantics, role, etc.) MUST be in Chinese.

Special Attention:
1. Resource Lifecycle: for every resource (memory, fd, lock), state whether it is allocated, freed, or transferred to caller.
2. Error Paths: describe what happens to acquired resources in every early return or error branch.
3. Contracts: document assumptions about input pointers, e.g. "不可为NULL" or "可为NULL，内部已处理".
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
                return cast(Dict[str, Any], tool.execute(args))
        return {"error": f"Unknown tool: {name}"}

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        func_name = input_data.get("func_name")
        func_code = input_data.get("code")
        location = input_data.get("location")
        schema = input_data.get("schema", "{}")
        user_context = input_data.get("user_config_context")
        agent_contract = input_data.get("agent_contract")
        skill_contracts = input_data.get("skill_contracts")
        workflow_context = input_data.get("workflow_context")

        system_prompt = SYSTEM_PROMPT.format(schema=json.dumps(schema, indent=2, ensure_ascii=False))
        if workflow_context:
            system_prompt += f"\n\n[Workflow Contract]\n{workflow_context}"
        if agent_contract:
            system_prompt += f"\n\n[Agent Contract]\n{agent_contract}"
        if skill_contracts:
            system_prompt += f"\n\n[Loaded Skill Contracts]\n{skill_contracts}"
        prompt = f"Please model the following function: {func_name}\nLocation: {location}\nCode:\n```c\n{func_code}\n```"
        if user_context:
            prompt += f"\n\nUser-provided project context:\n{user_context}"
        
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
            ctx_tokens = result.get("context_tokens", 0)

            parsed = self._try_extract_snapshot(content, result, conversation)
            if parsed:
                return AgentResponse(success=True, data=parsed, metadata={"context_tokens": ctx_tokens})

            # ── JSON Parse Retry Loop ──
            MAX_JSON_RETRIES = 2
            for retry in range(1, MAX_JSON_RETRIES + 1):
                logger.warning(
                    f"[Retry {retry}/{MAX_JSON_RETRIES}] Failed to parse snapshot JSON for {func_name}. "
                    f"Asking LLM to re-output valid JSON..."
                )
                conversation.append({
                    "role": "user",
                    "content": (
                        "你上一轮的输出不包含合法的JSON语义快照。请严格按照之前给出的Schema格式，"
                        "用 ```json ... ``` 包裹重新输出完整的函数语义快照，不要输出任何其他内容。"
                    )
                })

                retry_response = self.llm_client.chat_completion(conversation, tools=None)
                retry_choice = retry_response.get("choices", [{}])[0]
                retry_message = retry_choice.get("message", {})
                retry_content = retry_message.get("content", "")
                conversation.append(retry_message)
                
                # Estimate tokens for retry if we don't have it tracked
                from ...framework.llm_client import LLMClient
                retry_ctx_tokens = LLMClient.estimate_tokens(conversation)

                parsed = self._try_extract_snapshot(retry_content, {}, conversation)
                if parsed:
                    logger.info(f"[Retry {retry}] Successfully parsed snapshot JSON for {func_name}")
                    return AgentResponse(success=True, data=parsed, metadata={"context_tokens": ctx_tokens + retry_ctx_tokens})
            
            last_msg_debug = json.dumps(conversation[-1] if conversation else {}, ensure_ascii=False)
            logger.error(f"Failed to parse snapshot JSON for {func_name} after {MAX_JSON_RETRIES} retries. Last API Msg: {last_msg_debug}")
            return AgentResponse(success=False, data={}, error="Failed to parse snapshot JSON. See logs for full content.")
            
        except Exception as e:
            return AgentResponse(success=False, data={}, error=str(e))

    def _try_extract_snapshot(self, content: str, result: Dict[str, Any], conversation: list) -> Any:
        """Try to extract a valid snapshot JSON from LLM output. Returns parsed data or None."""
        from ...common.utils import extract_json_blocks, is_valid_snapshot

        all_text_sources = [content]
        if result.get("reasoning_content"):
            all_text_sources.append(result["reasoning_content"])

        for msg in reversed(conversation):
            if msg.get("role") == "assistant":
                all_text_sources.append(msg.get("content", ""))
                if "reasoning_content" in msg:
                    all_text_sources.append(msg.get("reasoning_content", ""))

        for text in all_text_sources:
            if not text:
                continue
            candidates = extract_json_blocks(text)
            for data in candidates:
                if is_valid_snapshot(data):
                    return data
                if "function_snapshot" in data and is_valid_snapshot(data["function_snapshot"]):
                    return data["function_snapshot"]
        return None

