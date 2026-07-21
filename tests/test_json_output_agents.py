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
        "callees": [],
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
        "callees": [],
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
                "name": "LIMIT",
                "file_path": "demo.h",
                "line": 2,
                "definition": "#define LIMIT 8",
                "is_function_like": False,
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


def test_semantic_modeler_finalizes_function_snapshot_with_forced_tool(monkeypatch) -> None:
    llm = RepairLLM("emit_function_snapshot", _snapshot_payload())
    agent = SemanticModeler(llm, [])
    exploration_result = _prose_result()
    exploration_result["conversation"] = [
        {"role": "user", "content": "model api_entry"},
        {"role": "assistant", "content": "collected-evidence-marker"},
    ]
    exploration_messages = []

    def run_exploration(messages, *args, **kwargs):
        del args, kwargs
        exploration_messages.extend(messages)
        return exploration_result

    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        run_exploration,
    )

    response = agent.run(_semantic_model_input())

    assert response.success is True
    assert response.data["type"] == "function_snapshot"
    assert response.data["referenced_globals"] == _semantic_model_input()[
        "referenced_globals"
    ]
    assert response.data["referenced_macros"] == _semantic_model_input()[
        "referenced_macros"
    ]
    assert response.data["referenced_macros_truncation"] == {
        "truncated": True,
        "returned": 1,
        "total": 2,
    }
    assert response.metadata["snapshot_finalization_attempted"] == 1
    assert response.metadata["snapshot_finalization_accepted"] == 1
    final_messages, final_kwargs = llm.calls[0]
    assert any(message.get("content") == "collected-evidence-marker" for message in final_messages)
    assert final_kwargs["tool_choice"] == {
        "type": "function",
        "function": {"name": "emit_function_snapshot"},
    }
    assert (
        final_kwargs["tools"][0]["function"]["parameters"]
        == llm_function_snapshot_schema(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    )
    prompt_text = "\n".join(
        str(message.get("content") or "") for message in exploration_messages
    )
    assert "Target function metadata" in prompt_text
    assert "referenced_globals" in prompt_text
    assert "Location:" not in prompt_text


def test_semantic_modeler_uses_effective_schema_for_final_tool(monkeypatch) -> None:
    custom_schema = dict(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    custom_schema["description"] = "custom-schema-marker"
    llm = RepairLLM("emit_function_snapshot", _snapshot_payload())
    agent = SemanticModeler(llm, [])
    monkeypatch.setattr(agent, "_run_tool_conversation", lambda *args, **kwargs: _prose_result())

    response = agent.run(
        _semantic_model_input(schema=custom_schema)
    )

    assert response.success is True
    _, final_kwargs = llm.calls[0]
    assert final_kwargs["tools"][0]["function"]["parameters"] == llm_function_snapshot_schema(
        custom_schema
    )


def test_semantic_modeler_uses_response_format_for_structured_output(monkeypatch) -> None:
    llm = StructuredOutputLLM(_snapshot_payload())
    agent = SemanticModeler(llm, [])
    monkeypatch.setattr(agent, "_run_tool_conversation", lambda *args, **kwargs: _prose_result())

    response = agent.run(_semantic_model_input())

    assert response.success is True
    _, final_kwargs = llm.calls[0]
    assert (
        final_kwargs["response_format"]["json_schema"]["schema"]
        == llm_function_snapshot_schema(DEFAULT_FUNCTION_SNAPSHOT_SCHEMA)
    )


def test_semantic_modeler_program_fields_override_llm_identity(monkeypatch) -> None:
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
            "referenced_globals_truncation": {
                "truncated": True,
                "returned": 1,
                "total": 99,
            },
        }
    )
    llm = RepairLLM("emit_function_snapshot", payload)
    agent = SemanticModeler(llm, [])
    monkeypatch.setattr(agent, "_run_tool_conversation", lambda *args, **kwargs: _prose_result())

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


def test_semantic_modeler_blocks_redundant_target_function_info_call(monkeypatch) -> None:
    llm = RepairLLM("emit_function_snapshot", _snapshot_payload())
    agent = SemanticModeler(llm, [GetFunctionInfoTool()])
    tool_results = []

    def run_exploration(*args, **kwargs):
        del args, kwargs
        tool_results.append(
            agent._tool_executor("get_function_info", {"func_name": "api_entry"})
        )
        return _prose_result()

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
    for field in PROGRAM_PASSTHROUGH_SNAPSHOT_FIELDS:
        assert field in required
        assert field in properties
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
        "nullable",
        "constraints",
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
    assert return_required == {
        "return_type",
        "meaning",
        "nullable",
        "success_cases",
        "failure_cases",
    }
    assert "ownership" not in return_required
    assert "risk" not in properties["return_values"]["properties"]
    assert properties["return_values"]["properties"]["ownership"]["enum"] == [
        "caller_owned",
        "borrowed",
        "shared",
        "static_storage",
        "unknown",
    ]
    caller_obligation = properties["return_values"]["properties"]["caller_obligation"]
    assert "Additional caller action" in caller_obligation["description"]
    assert "Omit when no additional obligation exists" in caller_obligation["description"]


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
        "exit_states",
    }
    assert "return_value" in path_item["properties"]
    assert "risk" not in path_item["properties"]

    exit_states = path_item["properties"]["exit_states"]
    assert exit_states["type"] == "array"
    assert "Final states of memory objects" in exit_states["description"]
    assert "empty array" in exit_states["description"]
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


def test_semantic_modeler_schema_preserves_aggregated_callee_call_types() -> None:
    callee = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA["properties"]["callees"]["items"]
    call_type = callee["properties"]["call_type"]

    assert call_type == {
        "type": "array",
        "items": {"enum": ["direct", "indirect"]},
        "minItems": 1,
        "uniqueItems": True,
    }


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
