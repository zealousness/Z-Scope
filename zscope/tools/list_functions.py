from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class ListFunctionsTool(BaseTool):
    """Tool to list functions in the project (supports regex pattern)."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="list_known_functions",
            description="List functions in the project index, optionally filtered by regex pattern.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        pattern = arguments.get("pattern")
        limit = arguments.get("limit", 50)
        functions = self.code_index.list_functions(pattern=pattern, limit=limit)
        return {"success": True, "data": {"functions": functions, "count": len(functions)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Regex pattern to filter function names"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
        }
