from typing import Any, Dict, List, Optional
import json
import logging

from ..base import JsonOutputSpec, JsonToolAgent
from ...tools.policy import ToolPolicy
from ...common.utils import is_valid_snapshot
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient
from .schema import DEFAULT_FUNCTION_SNAPSHOT_SCHEMA

logger = logging.getLogger(__name__)


def _schema_json(schema: Any) -> str:
    if schema in (None, "", "{}") or schema == {}:
        schema = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
    return schema if isinstance(schema, str) else json.dumps(schema, indent=2, ensure_ascii=False)


class SemanticModeler(JsonToolAgent):
    """Agent for generating function snapshots."""

    def __init__(
        self,
        llm_client: LLMClient,
        tools: List[Any],
        tool_policy: Optional[ToolPolicy] = None,
    ):
        super().__init__(
            name="semantic_modeler",
            description="Generates semantic snapshots of C functions.",
            llm_client=llm_client,
            tools=tools,
            tool_policy=tool_policy,
        )

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        func_name = input_data.get("func_name")
        func_code = input_data.get("code")
        location = input_data.get("location")
        schema = input_data.get("schema")
        user_context = input_data.get("user_config_context")

        schema_json = _schema_json(schema)
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
            json_output_spec=JsonOutputSpec(
                type_name="function_snapshot",
                schema=DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
                final_tool_name="emit_function_snapshot",
                final_tool_description="Emit the final semantic function_snapshot object.",
                validator=is_valid_snapshot,
                nested_keys=("function_snapshot",),
                metadata_prefix="snapshot",
            ),
        )
