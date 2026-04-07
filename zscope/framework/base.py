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
