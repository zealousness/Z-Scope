import json

from zscope.agents.base import JsonOutputSpec, JsonToolAgent
from zscope.agents.review_memory.agent import ReviewMemoryAgent, _valid_payload


def _spec():
    return JsonOutputSpec(
        type_name="decision",
        schema={
            "type": "object",
            "properties": {"accepted": {"type": "boolean"}},
            "required": ["accepted"],
            "additionalProperties": False,
        },
        final_tool_name="emit_decision",
        final_tool_description="Emit decision",
        validator=lambda value: isinstance(value, dict),
        nested_keys=("result",),
    )


def test_weak_validator_cannot_bypass_published_schema():
    assert JsonToolAgent._coerce_payload_for_spec({}, _spec()) is None
    assert JsonToolAgent._coerce_payload_for_spec({"accepted": "yes"}, _spec()) is None
    assert JsonToolAgent._coerce_payload_for_spec({"result": {"accepted": True}}, _spec()) == {
        "accepted": True
    }


def test_extractor_fallback_still_checks_schema():
    class Agent(JsonToolAgent):
        def run(self, input_data):
            raise NotImplementedError

    assert (
        JsonToolAgent._extract_json_output(
            object.__new__(Agent),
            "",
            {},
            [],
            extractor=lambda *_: {},
            json_output_spec=_spec(),
        )
        is None
    )


def test_repair_has_field_diagnostic_without_inventing_type_field():
    prompt = JsonToolAgent._json_repair_prompt(
        "decision",
        error_type="schema_mismatch",
        result={"content": '{"accepted":"yes"}'},
        json_output_spec=_spec(),
    )
    assert "accepted: must be boolean" in prompt
    assert "type=decision" not in prompt


def test_review_pattern_validates_nested_fields():
    assert not _valid_payload(
        {
            "false_positive_reason": "原因",
            "required_checks": [3],
            "counter_conditions": [],
            "trigger_features": [],
        }
    )


def test_review_compatibility_rejects_wrong_terminal_tool():
    class Client:
        def chat_completion(self, *_args, **_kwargs):
            payload = {
                "false_positive_reason": "原因",
                "required_checks": [],
                "counter_conditions": [],
                "trigger_features": [],
            }
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "other_tool",
                                        "arguments": json.dumps(payload),
                                    }
                                }
                            ]
                        }
                    }
                ]
            }

    assert not ReviewMemoryAgent(Client()).run({}).success
