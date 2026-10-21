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
        try:
            parsed_limit = max(1, int(limit))
        except (TypeError, ValueError):
            parsed_limit = 30
        backend = getattr(self.code_index, "backend", None)
        if backend and hasattr(backend, "get_indirect_callees"):
            fetched = backend.get_indirect_callees(func_name, limit=parsed_limit + 1)
        else:
            fetched = []
        truncated = len(fetched) > parsed_limit
        targets = fetched[:parsed_limit]
        data = {
            "function": func_name,
            "indirect_callees": targets,
            "count": len(targets),
            "truncated": truncated,
        }
        if truncated:
            data["note"] = (
                f"More than {parsed_limit} indirect call targets exist; re-run "
                "with a larger limit for the complete target set."
            )
        return {"success": True, "data": data}

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
                        "limit": {
                            "type": "integer",
                            "default": 30,
                            "description": "Max targets to return; truncated=true means more exist",
                        },
                    },
                    "required": ["func_name"],
                },
            },
        }
