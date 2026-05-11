from typing import Any, Dict, List
import json
import logging

from ..base import JsonToolAgent
from ...common.utils import is_valid_snapshot
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient

logger = logging.getLogger(__name__)


class SemanticModeler(JsonToolAgent):
    """Agent for generating function snapshots."""

    def __init__(self, llm_client: LLMClient, tools: List[Any]):
        super().__init__(
            name="semantic_modeler",
            description="Generates semantic snapshots of C functions.",
            llm_client=llm_client,
            tools=tools,
        )

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        func_name = input_data.get("func_name")
        func_code = input_data.get("code")
        location = input_data.get("location")
        schema = input_data.get("schema", "{}")
        user_context = input_data.get("user_config_context")

        schema_json = (
            schema
            if isinstance(schema, str)
            else json.dumps(schema, indent=2, ensure_ascii=False)
        )
        prompt = (
            f"Please model the following function: {func_name}\n"
            f"Location: {location}\n"
            f"Code:\n```c\n{func_code}\n```"
        )
        if user_context:
            prompt += f"\n\nUser-provided project context:\n{user_context}"

        messages = self._messages(
            input_data,
            prompt,
            substitutions={"schema": schema_json},
        )
        return self._run_json_conversation(
            messages,
            extractor=lambda content, result, conversation: self._extract_valid_payload(
                content,
                result,
                conversation,
                validator=is_valid_snapshot,
                nested_keys=("function_snapshot",),
            ),
            trace_label=f"function={func_name}",
            parse_label="snapshot JSON",
            retry_prompt=(
                "The previous response did not contain a valid function_snapshot JSON. "
                "Re-output only one complete ```json ... ``` block that follows the schema."
            ),
        )
