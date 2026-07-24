from copy import deepcopy
from typing import Any, Dict, List, Optional
import json
import logging

from ..base import JsonOutputSpec, JsonToolAgent
from ...tools.policy import ToolPolicy
from ...common.utils import is_valid_snapshot
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient
from .schema import (
    DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
    LLM_EXCLUDED_SNAPSHOT_FIELDS,
    PROGRAM_GENERATED_SNAPSHOT_FIELDS,
    PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS,
    PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
    llm_function_snapshot_schema,
)

logger = logging.getLogger(__name__)


def _effective_schema(schema: Any) -> Dict[str, Any]:
    if schema in (None, "", "{}") or schema == {}:
        return DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
    if isinstance(schema, dict):
        return schema
    if isinstance(schema, str):
        parsed = json.loads(schema)
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("semantic_modeler schema must be a JSON object")


def _program_snapshot_fields(input_data: Dict[str, Any]) -> Dict[str, Any]:
    missing = [
        field
        for field in (
            *PROGRAM_GENERATED_SNAPSHOT_FIELDS,
            *PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
        )
        if field != "snapshot_kind" and field not in input_data
    ]
    if missing:
        raise ValueError(
            "semantic_modeler input is missing program fields: " + ", ".join(missing)
        )
    invalid_arrays = [
        field
        for field in PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS
        if not isinstance(input_data.get(field), list)
    ]
    invalid_optional = [
        field
        for field in PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS
        if field in input_data
        and (
            (
                field == "unresolved_referenced_types"
                and (
                    not isinstance(input_data.get(field), list)
                    or not input_data.get(field)
                )
            )
            or (
                field != "unresolved_referenced_types"
                and not isinstance(input_data.get(field), dict)
            )
        )
    ]
    if invalid_arrays or invalid_optional:
        raise ValueError(
            "semantic_modeler input has invalid program fields: "
            + ", ".join((*invalid_arrays, *invalid_optional))
        )
    required_type_fields = {
        "type_index_name",
        "kind",
        "full_definition",
        "reference_kinds",
        "reference_lines",
    }
    invalid_type_items = [
        item
        for item in input_data.get("referenced_types", [])
        if (
            not isinstance(item, dict)
            or set(item) != required_type_fields
        )
    ]
    if invalid_type_items:
        raise ValueError("semantic_modeler input has invalid referenced_types items")
    invalid_project_callees = [
        item
        for item in input_data.get("project_callees", [])
        if not isinstance(item, dict) or "is_macro" in item
    ]
    if invalid_project_callees:
        raise ValueError("semantic_modeler input has invalid project_callees items")
    macro_fields = {
        "macro_index_name",
        "definition",
        "is_function_like",
        "reference_lines",
    }
    invalid_macro_items = [
        item
        for item in input_data.get("referenced_macros", [])
        if not isinstance(item, dict) or set(item) != macro_fields
    ]
    if invalid_macro_items:
        raise ValueError("semantic_modeler input has invalid referenced_macros items")
    fields = {
        "func_name": str(input_data["func_name"]),
        "index_name": str(input_data["index_name"]),
        "file_path": str(input_data["file_path"]),
        "start_line": int(input_data["start_line"]),
        "end_line": int(input_data["end_line"]),
        "signature": str(input_data["signature"]),
        "snapshot_kind": "LLM-modeled",
        "is_static": bool(input_data["is_static"]),
        "is_macro": bool(input_data["is_macro"]),
        "project_callees": deepcopy(input_data["project_callees"]),
        "external_callees": deepcopy(input_data["external_callees"]),
        "referenced_globals": deepcopy(input_data["referenced_globals"]),
        "referenced_macros": deepcopy(input_data["referenced_macros"]),
        "referenced_types": deepcopy(input_data["referenced_types"]),
    }
    for field in PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS:
        if field in input_data:
            fields[field] = deepcopy(input_data[field])
    return fields


def _prompt_metadata(input_data: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "func_name",
        "index_name",
        "file_path",
        "start_line",
        "end_line",
        "signature",
        "is_static",
        "is_macro",
        "project_callees",
        "external_callees",
        "referenced_globals",
        "referenced_macros",
        "referenced_types",
        "project_callees_truncation",
        "external_callees_truncation",
        "referenced_globals_truncation",
        "referenced_macros_truncation",
        "unresolved_referenced_types",
        "referenced_types_truncation",
    )
    return {key: input_data[key] for key in keys if key in input_data}


def _merge_program_snapshot_fields(
    payload: Dict[str, Any],
    program_fields: Dict[str, Any],
) -> Dict[str, Any]:
    excluded = set(LLM_EXCLUDED_SNAPSHOT_FIELDS)
    semantic_payload = {
        key: value
        for key, value in payload.items()
        if key not in excluded
    }
    return {
        **semantic_payload,
        **program_fields,
    }


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
        self._active_target_queries: set[str] = set()

    def _tool_executor(self, name: str, args: Any) -> Dict[str, Any]:
        if name == "get_function_info" and isinstance(args, dict):
            query = str(args.get("func_name") or "").strip()
            if query and query in self._active_target_queries:
                return {
                    "success": False,
                    "error": (
                        "Target function metadata is already present in the initial prompt; "
                        "do not call get_function_info for the target function."
                    ),
                    "reason": "target_function_info_preloaded",
                }
        return super()._tool_executor(name, args)

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        try:
            program_fields = _program_snapshot_fields(input_data)
        except (TypeError, ValueError) as exc:
            return AgentResponse(
                success=False,
                data={},
                error=str(exc),
                metadata={"reason": "semantic_model_input_invalid", "llm_called": False},
            )

        func_name = program_fields["func_name"]
        func_code = str(input_data.get("code") or "")
        user_context = input_data.get("user_config_context")

        effective_schema = llm_function_snapshot_schema(
            _effective_schema(input_data.get("schema"))
        )
        metadata_json = json.dumps(
            _prompt_metadata(input_data),
            indent=2,
            ensure_ascii=False,
        )
        prompt = (
            f"Please model the following function: {func_name}\n"
            f"Target function metadata:\n```json\n{metadata_json}\n```\n"
            f"Code:\n```c\n{func_code}\n```\n\n"
            "Workflow: use the available retrieval tools only while additional evidence is "
            "needed. Do not write a complete snapshot in prose or a JSON code block during "
            "exploration. When the evidence is sufficient, submit exactly one final payload "
            "by calling emit_function_snapshot."
        )
        if user_context:
            prompt += f"\n\nUser-provided project context:\n{user_context}"

        messages = self._messages(input_data, prompt)
        self._active_target_queries = {
            str(program_fields["func_name"]),
            str(program_fields["index_name"]),
        }
        try:
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
                    schema=effective_schema,
                    final_tool_name="emit_function_snapshot",
                    final_tool_description="Emit the final semantic function_snapshot object.",
                    validator=is_valid_snapshot,
                    nested_keys=("function_snapshot",),
                    metadata_prefix="snapshot",
                ),
                post_process=lambda payload: _merge_program_snapshot_fields(
                    dict(payload),
                    program_fields,
                ),
                single_pass_final_tool=True,
            )
        finally:
            self._active_target_queries.clear()
