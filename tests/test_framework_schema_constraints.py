"""Local tool validation must enforce sibling JSON Schema constraints."""

import pytest

from zscope.framework.base import validate_function_arguments


@pytest.mark.parametrize("keyword", ["anyOf", "oneOf"])
def test_combinator_does_not_bypass_sibling_object_constraints(keyword):
    schema = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
        "additionalProperties": False,
        keyword: [{"type": "object"}],
    }
    assert validate_function_arguments(schema, {"query": "hello"}) is None
    assert "query: is required" == validate_function_arguments(schema, {})
    assert "extra: unknown field" == validate_function_arguments(
        schema, {"query": "hello", "extra": True}
    )


def test_combinator_siblings_apply_to_nested_tool_arguments():
    schema = {
        "type": "object",
        "properties": {
            "limit": {
                "anyOf": [{"type": "integer"}, {"type": "null"}],
                "minimum": 1,
            }
        },
    }
    assert validate_function_arguments(schema, {"limit": 1}) is None
    assert validate_function_arguments(schema, {"limit": None}) is None
    assert validate_function_arguments(schema, {"limit": 0}) == "limit: must be at least 1"


def test_nullable_type_does_not_bypass_enum():
    schema = {
        "type": "object",
        "properties": {"mode": {"type": ["string", "null"], "enum": ["exact"]}},
    }
    assert validate_function_arguments(schema, {"mode": "exact"}) is None
    assert validate_function_arguments(schema, {"mode": None}) is not None
    schema["properties"]["mode"]["enum"].append(None)
    assert validate_function_arguments(schema, {"mode": None}) is None


def test_const_and_enum_distinguish_booleans_from_numbers():
    schema = {
        "type": "object",
        "properties": {"language": {"const": "java"}, "complete": {"const": True}},
    }
    assert validate_function_arguments(schema, {"language": "java", "complete": True}) is None
    assert validate_function_arguments(schema, {"language": "c_cpp"}) is not None
    assert validate_function_arguments(schema, {"complete": 1}) is not None
    schema["properties"]["complete"] = {"enum": [True]}
    assert validate_function_arguments(schema, {"complete": 1}) is not None


@pytest.mark.parametrize("confidence", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_confidence_cannot_pass_numeric_bounds(confidence):
    schema = {
        "type": "object",
        "properties": {"confidence": {"type": "number", "minimum": 0, "maximum": 1}},
    }
    assert validate_function_arguments(schema, {"confidence": confidence}) is not None


def test_nonfinite_values_are_rejected_in_free_form_json_fields():
    schema = {"type": "object", "properties": {"extra": {"type": "object"}}}
    assert validate_function_arguments(schema, {"extra": {"values": [float("nan")]}}) == (
        "extra.values[0]: must be a finite number"
    )
