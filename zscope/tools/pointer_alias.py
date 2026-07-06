from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class QueryPointerAliasTool(BaseTool):
    """Tool to retrieve SVF-resolved indirect callees."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="query_pointer_alias",
            description="Query SVF Andersen-resolved indirect call targets for a function.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name", "")
        limit = arguments.get("limit", 30)
        backend = getattr(self.code_index, "backend", None)
        if backend and hasattr(backend, "get_indirect_callees"):
            targets = backend.get_indirect_callees(func_name, limit=limit)
        else:
            targets = []
        return {"success": True, "data": {"function": func_name, "indirect_callees": targets, "count": len(targets)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string"},
                        "limit": {"type": "integer", "default": 30},
                    },
                    "required": ["func_name"],
                },
            },
        }
