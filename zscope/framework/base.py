"""
Z-Scope Framework Base Classes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

_JSON_SCHEMA_TYPES: Dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}


def validate_function_arguments(
    schema: Optional[Dict[str, Any]],
    arguments: Any,
    *,
    reject_unknown: bool = False,
) -> Optional[str]:
    """Validate arguments against the flat object schema used by function tools."""
    if schema is None:
        return "tool schema is missing"
    if not isinstance(arguments, dict):
        return "Tool arguments must be a JSON object"

    parameters = schema.get("function", {}).get("parameters", {})
    if not isinstance(parameters, dict):
        return "tool schema parameters must be an object schema"
    properties = parameters.get("properties") or {}
    if not isinstance(properties, dict):
        return "tool schema properties must be an object"

    for name in parameters.get("required", []) or []:
        if name not in arguments or arguments.get(name) is None:
            return f"'{name}' is required"

    if reject_unknown:
        extra = sorted(name for name in arguments if name not in properties)
        if extra:
            return f"unknown argument(s): {', '.join(extra)}"

    for name, value in arguments.items():
        if name not in properties or value is None:
            continue
        property_schema = properties.get(name) or {}
        schema_type = property_schema.get("type")
        expected = _JSON_SCHEMA_TYPES.get(schema_type) if isinstance(schema_type, str) else None
        if expected is not None:
            valid = isinstance(value, expected)
            if schema_type in {"integer", "number"} and isinstance(value, bool):
                valid = False
            if not valid:
                return f"'{name}' must be {schema_type}"
        enum = property_schema.get("enum")
        if enum is not None and value not in enum:
            return f"'{name}' must be one of {list(enum)}"
    return None


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
        """Validate flat tool arguments against this tool's function schema."""
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
