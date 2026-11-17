"""
Z-Scope Framework Base Classes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import math
from typing import Dict, Any, List, Optional, Sequence

_JSON_SCHEMA_TYPES: Dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


def _schema_types(schema_type: Any) -> Sequence[str]:
    if isinstance(schema_type, str):
        return (schema_type,)
    if isinstance(schema_type, list):
        return tuple(item for item in schema_type if isinstance(item, str))
    return ()


def _json_values_equal(left: Any, right: Any) -> bool:
    """JSON booleans are distinct from numbers, including inside containers."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_values_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_values_equal(a, b) for a, b in zip(left, right)
        )
    return bool(left == right)


def _json_identity(value: Any) -> Any:
    """Hash JSON equality: object order is irrelevant, booleans are not numbers."""
    if isinstance(value, dict):
        return ("object", frozenset((key, _json_identity(item)) for key, item in value.items()))
    if isinstance(value, list):
        return ("array", tuple(_json_identity(item) for item in value))
    kind = (
        "number" if isinstance(value, (int, float)) and not isinstance(value, bool) else type(value)
    )
    return (kind, value)


def _nonfinite_number_error(value: Any, path: str = "") -> Optional[str]:
    if isinstance(value, float) and not math.isfinite(value):
        return f"{path or '$'}: must be a finite number"
    if isinstance(value, dict):
        children = ((f"{path}.{key}" if path else str(key), item) for key, item in value.items())
    elif isinstance(value, list):
        children = ((f"{path}[{index}]", item) for index, item in enumerate(value))
    else:
        return None
    for child_path, child in children:
        error = _nonfinite_number_error(child, child_path)
        if error:
            return error
    return None


def _validate_json_value(schema: Dict[str, Any], value: Any, path: str) -> Optional[str]:
    """Validate the JSON-Schema subset used by tool contracts, recursively."""
    if not isinstance(schema, dict):
        return f"{path or '$'}: schema must be an object"

    for keyword in ("oneOf", "anyOf"):
        variants = schema.get(keyword)
        if isinstance(variants, list):
            matches = [
                variant
                for variant in variants
                if isinstance(variant, dict) and _validate_json_value(variant, value, path) is None
            ]
            if (keyword == "oneOf" and len(matches) != 1) or (keyword == "anyOf" and not matches):
                return f"{path or '$'}: value does not match {keyword}"

    schema_types = _schema_types(schema.get("type"))
    if schema_types:
        valid = False
        for schema_type in schema_types:
            expected = _JSON_SCHEMA_TYPES.get(schema_type)
            if schema_type == "null":
                candidate = value is None
            elif expected is None:
                candidate = True
            else:
                candidate = isinstance(value, expected)
                if schema_type in {"integer", "number"} and isinstance(value, bool):
                    candidate = False
            valid = valid or candidate
        if not valid:
            expected_text = " or ".join(schema_types)
            return f"{path or '$'}: must be {expected_text}"

    enum = schema.get("enum")
    if enum is not None and not any(_json_values_equal(value, item) for item in enum):
        return f"{path or '$'}: must be one of {list(enum)}"
    if "const" in schema and not _json_values_equal(value, schema["const"]):
        return f"{path or '$'}: must equal {schema['const']!r}"

    if isinstance(value, str):
        min_length = schema.get("minLength")
        max_length = schema.get("maxLength")
        if isinstance(min_length, int) and len(value) < min_length:
            return f"{path or '$'}: length must be at least {min_length}"
        if isinstance(max_length, int) and len(value) > max_length:
            return f"{path or '$'}: length must be at most {max_length}"
        pattern = schema.get("pattern")
        if isinstance(pattern, str):
            import re

            try:
                if re.search(pattern, value) is None:
                    return f"{path or '$'}: must match pattern {pattern!r}"
            except re.error:
                return f"{path or '$'}: schema contains an invalid pattern"

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if isinstance(value, float) and not math.isfinite(value):
            return f"{path or '$'}: must be a finite number"
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if isinstance(minimum, (int, float)) and value < minimum:
            return f"{path or '$'}: must be at least {minimum}"
        if isinstance(maximum, (int, float)) and value > maximum:
            return f"{path or '$'}: must be at most {maximum}"

    if isinstance(value, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(value) < min_items:
            return f"{path or '$'}: must contain at least {min_items} item(s)"
        if isinstance(max_items, int) and len(value) > max_items:
            return f"{path or '$'}: must contain at most {max_items} item(s)"
        if schema.get("uniqueItems") is True:
            normalized = [_json_identity(item) for item in value]
            if len(set(normalized)) != len(normalized):
                return f"{path or '$'}: items must be unique"
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                error = _validate_json_value(item_schema, item, f"{path}[{index}]")
                if error:
                    return error

    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        if not isinstance(properties, dict):
            return f"{path or '$'}: schema properties must be an object"
        for name in schema.get("required", []) or []:
            if name not in value:
                child = f"{path}.{name}" if path else str(name)
                return f"{child}: is required"
        additional = schema.get("additionalProperties", True)
        if additional is False:
            extras = sorted(name for name in value if name not in properties)
            if extras:
                child = f"{path}.{extras[0]}" if path else extras[0]
                return f"{child}: unknown field"
        for name, item in value.items():
            property_schema = properties.get(name)
            if not isinstance(property_schema, dict):
                continue
            child = f"{path}.{name}" if path else name
            error = _validate_json_value(property_schema, item, child)
            if error:
                return error
    return None


def validate_function_arguments(
    schema: Optional[Dict[str, Any]],
    arguments: Any,
    *,
    reject_unknown: bool = False,
) -> Optional[str]:
    """Validate arguments against a function tool schema, including nested values."""
    if schema is None:
        return "tool schema is missing"
    if not isinstance(arguments, dict):
        return "Tool arguments must be a JSON object"
    number_error = _nonfinite_number_error(arguments)
    if number_error:
        return number_error

    if isinstance(schema.get("function"), dict):
        parameters = schema["function"].get("parameters", {})
    elif isinstance(schema.get("inputSchema"), dict):
        parameters = schema["inputSchema"]
    else:
        # Also accept a bare JSON schema for validating structured tool output.
        parameters = schema
    if not isinstance(parameters, dict):
        return "tool schema parameters must be an object schema"
    effective = dict(parameters)
    if reject_unknown:
        effective["additionalProperties"] = False
    return _validate_json_value(effective, arguments, "")


@dataclass
class AgentResponse:
    """Standard response from an agent."""

    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAgent(ABC):
    """Abstract base class for all agents."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    def _agent_system_prompt(
        self,
        input_data: Optional[Dict[str, Any]] = None,
        *,
        substitutions: Optional[Dict[str, Any]] = None,
        active_skill_names: Optional[List[str]] = None,
    ) -> str:
        """Return the AGENT.md-backed system prompt for this agent."""
        prompt = ""
        if input_data:
            prompt = str(input_data.get("agent_contract") or "")

        if not prompt:
            prompt = self._default_agent_contract(active_skill_names)

        for key, value in (substitutions or {}).items():
            prompt = prompt.replace("{" + key + "}", str(value))
        return prompt

    def _default_agent_contract(
        self,
        active_skill_names: Optional[List[str]] = None,
    ) -> str:
        from ..orchestration.specs import SpecRegistry

        registry = SpecRegistry()
        spec = registry.get_agent(self.name)
        if not spec:
            return self.description
        return spec.to_prompt_block(active_skills=active_skill_names)

    @abstractmethod
    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        """Run the agent's logic."""
        pass


class BaseTool(ABC):
    """Abstract base class for all tools."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the tool."""
        pass

    @abstractmethod
    def get_schema(self) -> Dict[str, Any]:
        """Get the OpenAI function schema for the tool."""
        pass

    def validate_arguments(self, arguments: Any) -> Optional[Dict[str, Any]]:
        """Validate tool arguments recursively against this tool's function schema."""
        error = validate_function_arguments(self.get_schema(), arguments)
        if not error:
            return None
        if error == "Tool arguments must be a JSON object":
            return {
                "success": False,
                "error": "Tool arguments must be a JSON object; please correct the payload and retry.",
            }
        return {
            "success": False,
            "error": f"{error}; please correct and retry.",
        }
