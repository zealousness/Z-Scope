from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class GetCallersTool(BaseTool):
    """Tool to find callers of a function via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_callers",
            description="Find functions that call the given function. Useful for assessing vulnerability reachability.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name

        func_name = sanitize_func_name(arguments.get("func_name", ""))
        limit = arguments.get("limit", 20)
        callers = self.code_index.get_callers(func_name, limit=limit)
        return {"success": True, "data": {"callers": callers, "count": len(callers)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string", "description": "Name of the function to find callers for"},
                        "limit": {"type": "integer", "default": 20},
                    },
                    "required": ["func_name"],
                },
            },
        }
