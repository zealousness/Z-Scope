"""
Z-Scope Framework Base Classes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


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
