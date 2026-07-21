from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex

GET_CALLERS_LIMIT = 20


class GetCallersTool(BaseTool):
    """Tool to find callers of a function via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_callers",
            description=(
                "Find canonical caller identities, callsite lines, and direct/indirect "
                "call types for one uniquely matched function. Use file_path or index_name "
                "to disambiguate same-name functions."
            ),
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = str(arguments.get("func_name") or "").strip()
        if not func_name:
            return {"success": False, "error": "Function name is empty"}

        file_path = arguments.get("file_path") or ""
        if not isinstance(file_path, str):
            return {"success": False, "error": "file_path must be a string"}

        result = self.code_index.find_function_callers(
            func_name,
            file_path=file_path,
            limit=GET_CALLERS_LIMIT,
        )
        match_count = int(result.get("match_count") or 0)
        if match_count == 0:
            return {
                "success": False,
                "error": f"Function '{func_name}' not found",
                "reason": "function_not_found",
            }
        if match_count > 1:
            return {
                "success": False,
                "error": (
                    f"Function '{func_name}' is ambiguous; provide file_path or index_name"
                ),
                "reason": "ambiguous_function",
                "match_count": match_count,
            }
        return {
            "success": True,
            "data": {"callers": list(result.get("callers") or [])},
        }

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {
                            "type": "string",
                            "description": "Function name, qualified name, or index_name for exact match.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Optional source file path used to disambiguate same-name functions.",
                        },
                    },
                    "required": ["func_name"],
                },
            },
        }
