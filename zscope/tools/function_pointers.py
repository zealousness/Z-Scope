from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class FindFunctionPointersTool(BaseTool):
    """Tool to find function pointer assignments and callback registrations."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="find_function_pointers",
            description="Find where a function is assigned as a pointer or registered as a callback.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name

        func_name = sanitize_func_name(arguments.get("func_name", ""))
        results = self.code_index.find_function_pointers(func_name)
        return {"success": True, "data": {"references": results, "count": len(results)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string", "description": "Function name to search for pointer usage"},
                    },
                    "required": ["func_name"],
                },
            },
        }
