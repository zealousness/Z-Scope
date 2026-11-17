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
        try:
            limit = int(arguments.get("limit", 50))
            offset = int(arguments.get("offset", 0))
        except (TypeError, ValueError, OverflowError):
            return {"success": False, "error": "limit and offset must be integers"}
        if limit < 1 or offset < 0:
            return {"success": False, "error": "limit must be positive and offset non-negative"}
        # A single bounded query probes for the next row without repeating a scan.
        fetched = self.code_index.list_functions(
            pattern=pattern,
            limit=limit + 1,
            offset=offset,
        )
        functions = fetched[:limit]
        truncated = len(fetched) > limit
        data = {
            "functions": functions,
            "count": len(functions),
            "pattern": pattern,
            "truncated": truncated,
        }
        if truncated:
            data["note"] = (
                "More functions match this pattern; re-run with a larger limit "
                "or a non-zero offset to page through the remaining entries."
            )
        return {"success": True, "data": data}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": (
                    "List functions in the project index, optionally filtered by "
                    "regex pattern. Returns up to `limit` functions from `offset`; "
                    "truncated=true means more matching functions exist beyond the "
                    "returned page."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {
                            "type": "string",
                            "description": "Regex pattern to filter function names",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 50,
                            "description": "Max functions to return for this page",
                        },
                        "offset": {
                            "type": "integer",
                            "minimum": 0,
                            "default": 0,
                            "description": "Number of matching functions to skip before this page",
                        },
                    },
                },
            },
        }
