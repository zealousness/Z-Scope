import json

from zscope.agents.deep_worker.agent import DeepWorkerAgent
from zscope.agents.semantic_modeler.agent import SemanticModeler
from zscope.agents.semantic_modeler.schema import (
    DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
    EFFECT_CATEGORY_ENUM,
    EXIT_STATE_ENUM,
    PROGRAM_GENERATED_SNAPSHOT_FIELDS,
    PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS,
    PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
    SUSPICIOUS_POINT_CATEGORY_ENUM,
    llm_function_snapshot_schema,
)
from zscope.agents.vulnerability_analyzer.agent import VulnerabilityAnalyzer
from zscope.common.utils import is_valid_report
from zscope.orchestration.entry_discovery import COMM_PROMPT


class RepairLLM:
    models = ["unit-model"]
    supports_structured_output = False

    def __init__(self, tool_name: str, payload: dict):
        self.tool_name = tool_name
        self.payload = payload
        self.calls = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        assert kwargs["tools"][0]["function"]["name"] == self.tool_name
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_emit",
                                "type": "function",
                                "function": {
                                    "name": self.tool_name,
                                    "arguments": json.dumps(self.payload),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 4},
        }


class StructuredOutputLLM:
    models = ["unit-model"]
    supports_structured_output = True

    def __init__(self, payload: dict):
        self.payload = payload
        self.calls = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        assert kwargs["tools"] is None
        assert kwargs["response_format"]["type"] == "json_schema"
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(self.payload, ensure_ascii=False),
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 4},
        }


class SinglePassLLM:
    """Minimal LLM loop fake for the Semantic Modeler terminal-tool protocol."""

    models = ["unit-model"]

    def __init__(self, payload: dict, *, supports_structured_output: bool = False):
        self.payload = payload
        self.supports_structured_output = supports_structured_output
        self.calls = []

    def run_conversation_with_tools(self, **kwargs):
        self.calls.append(kwargs)
        tool_call = {
            "id": "call_emit",
            "type": "function",
            "function": {
                "name": "emit_function_snapshot",
                "arguments": json.dumps(self.payload),
            },
        }
        message = {"role": "assistant", "content": "", "tool_calls": [tool_call]}
        return {
            "content": "",
            "conversation": [*kwargs["messages"], message],
            "message": message,
            "terminal_tool_payload": self.payload,
            "terminal_tool_name": "emit_function_snapshot",
            "terminal_tool_valid": True,
            "terminal_tool_call_count": 1,
            "final_tool_call_count": 1,
            "iterations": 1,
            "tool_call_count": 0,
            "context_tokens": 10,
            "cumulative_prompt_tokens": 8,
            "cumulative_completion_tokens": 4,
            "cumulative_total_tokens": 12,
            "finish_reason": "tool_calls",
            "provider_model": "unit-model",
        }


class GetCallersTool:
    name = "get_callers"

    def get_schema(self):
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": "Get callers.",
                "parameters": {"type": "object", "properties": {}},
            },
        }


class GetFunctionInfoTool:
    name = "get_function_info"

    def get_schema(self):
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": "Get function info.",
                "parameters": {
                    "type": "object",
                    "properties": {"func_name": {"type": "string"}},
                    "required": ["func_name"],
                },
            },
        }

    def validate_arguments(self, arguments):
        del arguments
        return None

    def execute(self, arguments):
        return {"success": True, "data": arguments}


def _prose_result(text: str = "I can provide the JSON now."):
    return {
        "content": text,
        "conversation": [{"role": "assistant", "content": text}],
        "finish_reason": "stop",
        "provider_model": "unit-model",
        "iterations": 1,
        "tool_call_count": 0,
    }


def _snapshot_payload() -> dict:
    return {
        "type": "function_snapshot",
        "func_name": "api_entry",
        "index_name": "api_entry@demo.c:1",
        "file_path": "demo.c",
        "start_line": 1,
        "end_line": 1,
        "signature": "void api_entry(void)",
        "snapshot_kind": "LLM-modeled",
        "is_static": False,
        "is_macro": False,
        "summary": "demo",
        "parameters": [],
        "return_values": {
            "return_type": "void",
            "meaning": "无返回值",
            "nullable": "not_applicable",
            "success_cases": [],
            "failure_cases": [],
            "caller_obligation": "",
        },
        "effects": [],
        "error_handling": {"error_paths": []},
        "callers": [],
        "project_callees": [],
        "suspicious_points": [],
    }


def _semantic_model_input(**overrides) -> dict:
    payload = {
        "func_name": "api_entry",
        "index_name": "api_entry@demo.c:1-1",
        "file_path": "demo.c",
        "start_line": 1,
        "end_line": 1,
        "signature": "void api_entry(void)",
        "is_static": False,
        "is_macro": False,
        "code": "void api_entry(void) {}",
        "project_callees": [],
        "external_callees": [],
        "referenced_globals": [
            {
                "name": "global_state",
                "type": "int",
                "file_path": "demo.c",
                "line": 1,
                "is_extern": False,
                "storage_class": "static",
                "qualifiers": [],
                "initializer": "0",
                "definition_kind": "definition",
                "access": "read",
                "reference_lines": [1],
            }
        ],
        "referenced_macros": [
            {
                "macro_index_name": "LIMIT@demo.h:2-2",
                "definition": "2 | #define LIMIT 8\n",
                "is_function_like": False,
                "reference_lines": [1],
            }
        ],
        "referenced_types": [
            {
                "type_index_name": "ApiContext@demo.h:4-6",
                "kind": "struct",
                "full_definition": "4 | typedef struct { int value; } ApiContext;\n",
                "reference_kinds": ["parameter"],
                "reference_lines": [1],
            }
        ],
        "referenced_macros_truncation": {
            "truncated": True,
            "returned": 1,
            "total": 2,
        },
    }
    payload.update(overrides)
    return payload


def test_semantic_modeler_finalizes_function_snapshot_in_one_tool_conversation() -> None:
    llm = SinglePassLLM(_snapshot_payload())
    agent = SemanticModeler(llm, [])

    response = agent.run(_semantic_model_input())

    assert response.success is True
    assert response.data["type"] == "function_snapshot"
    assert response.data["referenced_globals"] == _semantic_model_input()[
        "referenced_globals"
    ]
    assert response.data["referenced_macros"] == _semantic_model_input()[
        "referenced_macros"
    ]
    assert response.data["referenced_types"] == _semantic_model_input()[
        "referenced_types"
    ]
    assert response.data["referenced_macros_truncation"] == {
        "truncated": True,
        "returned": 1,
        "total": 2,
    }
    assert response.metadata["single_pass"] is True
    assert response.metadata["finalization_mode"] == "single_pass_tool"
    assert response.metadata["terminal_tool_call_count"] == 1
    final_kwargs = llm.calls[0]
    assert final_kwargs["terminal_tool_required"] is True
    assert final_kwargs["terminal_tool_name"] == "emit_function_snapshot"
    assert (
        final_kwargs["tools_schema"][-1]["function"]["parameters"]
        == llm_function_snapshot_schema(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    )
    prompt_text = "\n".join(str(message.get("content") or "") for message in final_kwargs["messages"])
    assert "Target function metadata" in prompt_text
    assert "referenced_globals" in prompt_text
    assert "referenced_types" in prompt_text
    assert "Do not write a complete snapshot" in prompt_text


def test_semantic_modeler_project_callees_are_program_owned() -> None:
    payload = _snapshot_payload()
    payload["project_callees"] = [
        {
            "callee_index_name": "unknown@unknown.c:3-4",
            "callee_summary": "模型补充的未知摘要",
        },
        {
            "callee_index_name": "known@known.c:1-2",
            "callee_summary": "模型改写的已知摘要",
        },
    ]
    input_data = _semantic_model_input(
        project_callees=[
            {
                "callee_index_name": "known@known.c:1-2",
                "callsite_lines": [10],
                "call_type": ["direct"],
                "is_static": True,
                "callee_summary": "程序复用的 canonical summary",
            },
            {
                "callee_index_name": "unknown@unknown.c:3-4",
                "callsite_lines": [11],
                "call_type": ["direct"],
                "is_static": False,
                "callee_summary": "unknown",
            },
        ],
        external_callees=[
            {
                "callee_index_name": "printf",
                "callsite_lines": [12],
                "call_type": ["direct"],
            }
        ],
    )
    llm = SinglePassLLM(payload)

    response = SemanticModeler(llm, []).run(input_data)

    assert response.success is True
    assert response.data["project_callees"] == input_data["project_callees"]
    prompt_text = "\n".join(
        str(message.get("content") or "")
        for message in llm.calls[0]["messages"]
    )
    assert '"external_callees"' in prompt_text
    assert '"printf"' in prompt_text
    assert "Location:" not in prompt_text
    llm_schema = llm.calls[0]["tools_schema"][-1]["function"]["parameters"]
    assert "project_callees" not in llm_schema["properties"]
    assert "project_callees" not in llm_schema["required"]


def test_semantic_modeler_ignores_all_llm_project_callee_items() -> None:
    payload = _snapshot_payload()
    payload["project_callees"] = [
        {"callee_index_name": "", "callee_summary": "empty identity"},
        {"callee_index_name": "rogue@rogue.c:1-1", "callee_summary": "rogue"},
        {"callee_index_name": "target@target.c:1-2", "callee_summary": ""},
        {"callee_index_name": "target@target.c:1-2", "callee_summary": "first valid"},
        {"callee_index_name": "target@target.c:1-2", "callee_summary": "second valid"},
    ]
    input_record = {
        "callee_index_name": "target@target.c:1-2",
        "callsite_lines": [7],
        "call_type": ["direct"],
        "is_static": False,
        "callee_summary": "unknown",
    }

    response = SemanticModeler(llm := SinglePassLLM(payload), []).run(
        _semantic_model_input(project_callees=[input_record])
    )

    assert response.success is True
    assert response.data["project_callees"] == [input_record]
    assert len(response.data["project_callees"]) == 1
    assert llm.calls


def test_semantic_modeler_sparse_llm_callee_output_cannot_change_program_records() -> None:
    payload = _snapshot_payload()
    payload["project_callees"] = [
        {
            "callee_index_name": "second@second.c:3-4",
            "callee_summary": "second summary",
        }
    ]
    records = [
        {
            "callee_index_name": "first@first.c:1-2",
            "callsite_lines": [5],
            "call_type": ["direct"],
            "is_static": False,
            "callee_summary": "unknown",
        },
        {
            "callee_index_name": "second@second.c:3-4",
            "callsite_lines": [6],
            "call_type": ["direct"],
            "is_static": False,
            "callee_summary": "unknown",
        },
    ]

    response = SemanticModeler(SinglePassLLM(payload), []).run(
        _semantic_model_input(project_callees=records)
    )

    assert response.data["project_callees"] == records


def test_semantic_modeler_repairs_invalid_terminal_payload_in_same_conversation(monkeypatch) -> None:
    from zscope.framework.llm_client import LLMClient

    llm = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append((list(messages), kwargs))
        payload = {"summary": "incomplete"} if len(calls) == 1 else _snapshot_payload()
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_emit_{len(calls)}",
                                "type": "function",
                                "function": {
                                    "name": "emit_function_snapshot",
                                    "arguments": json.dumps(payload),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 4},
        }

    monkeypatch.setattr(llm, "chat_completion", fake_chat_completion)
    response = SemanticModeler(llm, []).run(_semantic_model_input())

    assert response.success is True
    assert len(calls) == 2
    assert any(
        message.get("role") == "tool"
        and message.get("terminal_tool_result")
        and "Invalid function_snapshot payload" in message.get("content", "")
        for message in calls[1][0]
    )
    assert response.metadata["terminal_tool_call_count"] == 2
    assert response.metadata["tool_call_count"] == 0
    assert response.metadata["api_call_count"] == 2
    assert response.data["index_name"] == "api_entry@demo.c:1-1"
    assert response.data["referenced_globals"] == _semantic_model_input()["referenced_globals"]


def test_semantic_modeler_uses_effective_schema_for_initial_terminal_tool() -> None:
    custom_schema = dict(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    custom_schema["description"] = "custom-schema-marker"
    llm = SinglePassLLM(_snapshot_payload())
    agent = SemanticModeler(llm, [])

    response = agent.run(
        _semantic_model_input(schema=custom_schema)
    )

    assert response.success is True
    final_kwargs = llm.calls[0]
    assert final_kwargs["tools_schema"][-1]["function"]["parameters"] == llm_function_snapshot_schema(
        custom_schema
    )


def test_semantic_modeler_uses_terminal_tool_even_for_structured_output_models() -> None:
    llm = SinglePassLLM(_snapshot_payload(), supports_structured_output=True)
    agent = SemanticModeler(llm, [])

    response = agent.run(_semantic_model_input())

    assert response.success is True
    final_kwargs = llm.calls[0]
    assert final_kwargs["terminal_tool_name"] == "emit_function_snapshot"
    assert final_kwargs["tools_schema"][-1]["function"]["parameters"] == llm_function_snapshot_schema(
        DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
    )


def test_semantic_modeler_program_fields_override_llm_identity() -> None:
    payload = _snapshot_payload()
    payload.update(
        {
            "func_name": "wrong",
            "index_name": "wrong@wrong.c:9-9",
            "file_path": "wrong.c",
            "start_line": 9,
            "end_line": 9,
            "signature": "int wrong(void)",
            "snapshot_kind": "wrong",
            "is_static": True,
            "is_macro": True,
            "referenced_globals": [{"name": "wrong_global"}],
            "referenced_macros": [{"name": "WRONG_MACRO"}],
            "referenced_types": [{"name": "WrongType"}],
            "unresolved_referenced_types": [
                {"name": "WrongMissing", "reason": "wrong"}
            ],
            "referenced_globals_truncation": {
                "truncated": True,
                "returned": 1,
                "total": 99,
            },
        }
    )
    llm = SinglePassLLM(payload)
    agent = SemanticModeler(llm, [])

    response = agent.run(_semantic_model_input())

    assert response.success is True
    assert {
        field: response.data[field]
        for field in PROGRAM_GENERATED_SNAPSHOT_FIELDS
    } == {
        "func_name": "api_entry",
        "index_name": "api_entry@demo.c:1-1",
        "file_path": "demo.c",
        "start_line": 1,
        "end_line": 1,
        "signature": "void api_entry(void)",
        "snapshot_kind": "LLM-modeled",
        "is_static": False,
        "is_macro": False,
    }
    assert response.data["referenced_globals"] == _semantic_model_input()[
        "referenced_globals"
    ]
    assert response.data["referenced_macros"] == _semantic_model_input()[
        "referenced_macros"
    ]
    assert response.data["referenced_types"] == _semantic_model_input()[
        "referenced_types"
    ]
    assert "unresolved_referenced_types" not in response.data
    assert "referenced_globals_truncation" not in response.data


def test_semantic_modeler_rejects_incomplete_program_input_without_calling_llm() -> None:
    llm = RepairLLM("emit_function_snapshot", _snapshot_payload())
    agent = SemanticModeler(llm, [])

    response = agent.run({"func_name": "api_entry", "code": "void api_entry(void) {}"})

    assert response.success is False
    assert response.metadata == {
        "reason": "semantic_model_input_invalid",
        "llm_called": False,
    }
    assert llm.calls == []


def test_semantic_modeler_rejects_invalid_symbol_context_without_calling_llm() -> None:
    llm = RepairLLM("emit_function_snapshot", _snapshot_payload())
    agent = SemanticModeler(llm, [])

    response = agent.run(_semantic_model_input(referenced_globals={}))

    assert response.success is False
    assert response.metadata == {
        "reason": "semantic_model_input_invalid",
        "llm_called": False,
    }
    assert "referenced_globals" in response.error
    assert llm.calls == []


def test_semantic_modeler_rejects_invalid_or_empty_optional_type_context() -> None:
    llm = RepairLLM("emit_function_snapshot", _snapshot_payload())
    agent = SemanticModeler(llm, [])

    invalid = agent.run(_semantic_model_input(referenced_types={}))
    legacy_resolved_item = _semantic_model_input()
    legacy_resolved_item["referenced_types"][0]["start_line"] = 4
    legacy = agent.run(legacy_resolved_item)
    empty_optional = agent.run(
        _semantic_model_input(unresolved_referenced_types=[])
    )

    assert invalid.success is False
    assert legacy.success is False
    assert empty_optional.success is False
    assert invalid.metadata["reason"] == "semantic_model_input_invalid"
    assert legacy.metadata["reason"] == "semantic_model_input_invalid"
    assert empty_optional.metadata["reason"] == "semantic_model_input_invalid"
    assert llm.calls == []


def test_semantic_modeler_blocks_redundant_target_function_info_call(monkeypatch) -> None:
    llm = SinglePassLLM(_snapshot_payload())
    agent = SemanticModeler(llm, [GetFunctionInfoTool()])
    tool_results = []

    def run_exploration(*args, **kwargs):
        del args, kwargs
        tool_results.append(
            agent._tool_executor("get_function_info", {"func_name": "api_entry"})
        )
        return llm.run_conversation_with_tools(messages=[])

    monkeypatch.setattr(agent, "_run_tool_conversation", run_exploration)

    response = agent.run(_semantic_model_input())

    assert response.success is True
    assert tool_results[0]["reason"] == "target_function_info_preloaded"


def test_semantic_modeler_schema_aligns_llm_snapshots_with_static_snapshots() -> None:
    required = set(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"])
    properties = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]

    for field in (
        "index_name",
        "file_path",
        "start_line",
        "end_line",
        "signature",
        "snapshot_kind",
    ):
        assert field in required
        assert field in properties
    for field in (
        "is_static",
        "is_macro",
    ):
        assert field in required
        assert field in properties
    assert properties["snapshot_kind"] == {"const": "LLM-modeled"}
    assert properties["is_static"] == {"type": "boolean"}
    assert properties["is_macro"] == {"type": "boolean"}
    assert "definition_hash" not in properties["referenced_types"]["items"]["properties"]
    assert "dependency_depth" not in properties["referenced_types"]["items"]["properties"]
    for field in ("name", "file_path", "start_line", "end_line"):
        assert field not in properties["referenced_types"]["items"]["properties"]
    for field in PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS:
        assert field in properties
        if field == "project_callees":
            assert field not in required
        else:
            assert field in required
    for field in PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS:
        assert field not in required
        assert field in properties
    llm_schema = llm_function_snapshot_schema(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    for field in (
        *PROGRAM_GENERATED_SNAPSHOT_FIELDS,
        *PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS,
        *PROGRAM_OPTIONAL_PASSTHROUGH_SNAPSHOT_FIELDS,
    ):
        assert field not in llm_schema["required"]
        assert field not in llm_schema["properties"]
    assert "is_inline" not in required
    assert "is_inline" not in properties

    global_properties = properties["referenced_globals"]["items"]["properties"]
    assert global_properties["storage_class"]["enum"] == [
        "static",
        "extern",
        "thread_local",
        "global",
        "unknown",
    ]
    assert global_properties["qualifiers"] == {
        "type": "array",
        "items": {"enum": ["const", "volatile", "atomic"]},
        "uniqueItems": True,
    }


def test_semantic_modeler_schema_omits_roles() -> None:
    required = set(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"])
    properties = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]

    assert "roles" not in required
    assert "roles" not in properties
    assert "role" not in required
    assert "role" not in properties


def test_semantic_modeler_schema_uses_parameters_and_return_values() -> None:
    required = set(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"])
    properties = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]

    assert "inputs" not in required
    assert "outputs" not in required
    assert "inputs" not in properties
    assert "outputs" not in properties
    assert "parameters" in required
    assert "return_values" in required
    assert properties["parameters"]["type"] == "array"
    assert properties["return_values"]["type"] == "object"
    assert "For void functions" in properties["return_values"]["description"]

    parameter_required = set(properties["parameters"]["items"]["required"])
    assert parameter_required == {
        "parameter_name",
        "parameter_type",
        "meaning",
        "input_origin",
    }
    parameter_properties = properties["parameters"]["items"]["properties"]
    assert "trust" not in parameter_properties
    assert parameter_properties["input_origin"]["enum"] == [
        "external",
        "internal",
        "mixed",
        "unknown",
    ]
    assert "ownership" not in parameter_properties
    assert "ownership_effect" not in parameter_required
    assert parameter_properties["ownership_effect"]["enum"] == [
        "borrow",
        "consume",
        "retain",
        "share",
        "release",
        "produce",
        "initialize",
        "mutate_borrowed",
        "unknown",
    ]
    assert "caller_obligation" not in properties["parameters"]["items"]["properties"]
    assert "risk" not in properties["parameters"]["items"]["properties"]
    assert "constraints" in properties["parameters"]["items"]["properties"]
    assert "Constraints, invariants" in properties["parameters"]["items"]["properties"]["constraints"]["description"]

    return_required = set(properties["return_values"]["required"])
    assert return_required == {"return_type"}
    assert "ownership" not in return_required
    assert "risk" not in properties["return_values"]["properties"]
    assert properties["return_values"]["properties"]["ownership"]["enum"] == [
        "caller_owned",
        "borrowed",
        "shared",
        "static_storage",
        "unknown",
    ]
    caller_obligations = properties["return_values"]["properties"]["caller_obligations"]
    assert "Additional caller actions" in caller_obligations["description"]
    assert "Omit when no additional obligation exists" in caller_obligations["description"]


def test_semantic_modeler_schema_replaces_legacy_effect_sections() -> None:
    required = set(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"])
    properties = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]

    legacy_sections = {
        "memory",
        "resources",
        "concurrency",
        "error_paths",
    }
    assert required.isdisjoint(legacy_sections)
    assert legacy_sections.isdisjoint(properties)
    assert "effects" in required
    assert "effects" in properties

    effects = properties["effects"]
    assert effects["type"] == "array"
    effect_item = effects["items"]
    assert set(effect_item["required"]) == {
        "category",
        "description",
        "line",
        "object",
    }
    effect_properties = effect_item["properties"]
    assert effect_properties["category"]["enum"] == EFFECT_CATEGORY_ENUM
    assert "action" not in effect_properties
    assert "confidence" not in effect_properties
    for field in ("description", "condition", "state_before", "state_after", "guard"):
        assert field in effect_properties
    assert "risk" not in effect_properties
    guard_description = effect_properties["guard"]["description"]
    assert "Protections of this effect" in guard_description
    assert "held lock" in guard_description
    assert "Omit when no guard applies" in guard_description
    details_description = effect_properties["details"]["description"]
    assert "Suggested keys by category" in details_description
    assert "memory: size_expression" in details_description
    assert "lock: lock_kind" in details_description
    assert "The object may be empty" in details_description
    assert "Do not duplicate object" in details_description


def test_semantic_modeler_schema_uses_error_handling() -> None:
    required = set(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"])
    properties = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]

    assert "error_paths" not in required
    assert "error_paths" not in properties
    assert "error_handling" in required
    assert "error_handling" in properties

    error_handling = properties["error_handling"]
    assert error_handling["type"] == "object"
    assert "Error path summary" in error_handling["description"]
    assert error_handling["required"] == ["error_paths"]

    error_paths = error_handling["properties"]["error_paths"]
    assert error_paths["type"] == "array"
    path_item = error_paths["items"]
    assert set(path_item["required"]) == {
        "trigger",
        "exit_line",
        "exit_action",
    }
    assert "return_value" in path_item["properties"]
    assert "risk" not in path_item["properties"]

    exit_states = path_item["properties"]["exit_states"]
    assert exit_states["type"] == "array"
    assert "Final states of memory objects" in exit_states["description"]
    assert "Omit when no relevant object" in exit_states["description"]
    resource_item = exit_states["items"]
    assert set(resource_item["required"]) == {"kind", "object", "state"}
    assert "owner" in resource_item["properties"]
    assert "risk" not in resource_item["properties"]
    assert resource_item["properties"]["state"]["enum"] == EXIT_STATE_ENUM
    assert "still_held" in EXIT_STATE_ENUM
    assert "held" in EXIT_STATE_ENUM
    assert "inconsistent" in EXIT_STATE_ENUM
    assert "unknown" in EXIT_STATE_ENUM


def test_semantic_modeler_schema_uses_suspicious_point_category_enum() -> None:
    required = set(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"])
    properties = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]

    assert "suspicious_points" in required
    suspicious_points = properties["suspicious_points"]
    assert suspicious_points["type"] == "array"
    assert "empty array" in suspicious_points["description"]

    item = suspicious_points["items"]
    assert "category" in item["required"]
    category = item["properties"]["category"]
    assert category["enum"] == SUSPICIOUS_POINT_CATEGORY_ENUM
    assert "memory_safety" in SUSPICIOUS_POINT_CATEGORY_ENUM
    assert "resource_lifecycle" in SUSPICIOUS_POINT_CATEGORY_ENUM
    assert "bounds" in SUSPICIOUS_POINT_CATEGORY_ENUM
    assert "invalid_free" not in SUSPICIOUS_POINT_CATEGORY_ENUM
    assert "fd_encoding_mismatch" not in SUSPICIOUS_POINT_CATEGORY_ENUM
    assert "other" in SUSPICIOUS_POINT_CATEGORY_ENUM


def test_semantic_modeler_schema_uses_lightweight_callers() -> None:
    required = set(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"])
    properties = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]

    assert "callers" not in required
    assert "callers" in properties

    callers = properties["callers"]
    assert callers["type"] == "array"
    caller_item = callers["items"]
    assert set(caller_item["required"]) == {
        "caller_index_name",
        "callsite_lines",
    }
    caller_properties = caller_item["properties"]
    assert set(caller_properties) == {
        "caller_index_name",
        "callsite_lines",
        "call_type",
    }
    assert caller_properties["callsite_lines"]["type"] == "array"
    assert caller_properties["callsite_lines"]["items"]["type"] == "integer"
    assert caller_properties["call_type"] == {
        "type": "array",
        "items": {"enum": ["direct", "indirect"]},
        "minItems": 1,
        "uniqueItems": True,
    }


def test_complete_schema_owns_full_project_callee_shape_but_llm_excludes_it() -> None:
    callee = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]["project_callees"]["items"]
    assert callee == {
        "type": "object",
        "required": [
            "callee_index_name",
            "callsite_lines",
            "call_type",
            "is_static",
            "callee_summary",
        ],
        "properties": {
            "callee_index_name": {"type": "string"},
            "callsite_lines": {
                "type": "array",
                "items": {"type": "integer"},
            },
            "call_type": {
                "type": "array",
                "items": {"enum": ["direct", "indirect"]},
                "minItems": 1,
                "uniqueItems": True,
            },
            "is_static": {"type": "boolean"},
            "callee_summary": {"type": "string"},
        },
        "additionalProperties": False,
    }
    macro_item = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]["referenced_macros"]["items"]
    assert macro_item["required"] == [
        "macro_index_name",
        "definition",
        "is_function_like",
        "reference_lines",
    ]
    assert set(macro_item["properties"]) == set(macro_item["required"])
    assert "project_callees" not in DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["required"]
    llm_schema = llm_function_snapshot_schema(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    assert "project_callees" not in llm_schema["required"]
    assert "project_callees" not in llm_schema["properties"]


def test_vulnerability_analyzer_repairs_final_report(monkeypatch) -> None:
    agent = VulnerabilityAnalyzer(
        RepairLLM(
            "emit_final_report",
            {"type": "final_report", "issues": [], "candidate_coverage": []},
        ),
        [],
    )
    monkeypatch.setattr(agent, "_run_tool_conversation", lambda *args, **kwargs: _prose_result(""))

    response = agent.run({"func_name": "api_entry", "code": "void api_entry(void) {}"}, max_iterations=1)

    assert response.success is True
    assert response.data["type"] == "final_report"
    assert response.data["issues"] == []
    assert response.metadata["report_repair_attempted"] == 1


def test_entry_focus_rewrites_hidden_get_callers_requirement() -> None:
    agent = VulnerabilityAnalyzer(RepairLLM("emit_final_report", {"type": "final_report", "issues": []}), [])

    focus = agent._entry_focus_for_available_tools(COMM_PROMPT)

    assert "get_callers" not in focus
    assert "caller-side parsing and validation" in focus
    assert "candidate evidence" in focus


def test_entry_focus_keeps_get_callers_when_tool_is_visible() -> None:
    agent = VulnerabilityAnalyzer(
        RepairLLM("emit_final_report", {"type": "final_report", "issues": []}),
        [GetCallersTool()],
    )

    assert "get_callers" in agent._entry_focus_for_available_tools(COMM_PROMPT)


def test_final_report_validator_requires_type_and_issues() -> None:
    assert is_valid_report({"type": "final_report", "issues": []}) is True
    assert is_valid_report({"overall_verdict": "clean"}) is False
    assert is_valid_report({"type": "final_report"}) is False


def test_deep_worker_preserves_partial_failure_metadata(monkeypatch) -> None:
    class BadRepairLLM:
        models = ["unit-model"]
        supports_structured_output = False

        def chat_completion(self, messages, **kwargs):
            return {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "still no JSON"},
                    }
                ],
                "model": "unit-model",
                "usage": {"prompt_tokens": 10, "completion_tokens": 4},
            }

    agent = DeepWorkerAgent(BadRepairLLM(), [])  # type: ignore[arg-type]
    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        lambda *args, **kwargs: {
            "content": "partial analysis text",
            "conversation": [{"role": "assistant", "content": "partial analysis text"}],
            "finish_reason": "stop",
            "truncated": True,
            "iterations": 2,
            "tool_call_count": 1,
        },
    )

    response = agent.run({"ticket": {"id": "T1"}, "context_slice": "", "max_iterations": 2})

    assert response.success is False
    assert response.data["partial_result"] == "partial analysis text"
    assert response.metadata["failure_kind"] == "partial"
    assert response.metadata["needs_human_review"] is True
