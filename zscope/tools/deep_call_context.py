from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class GetDeepCallContextTool(BaseTool):
    """Tool returning a compact aggregate of calls, indirect calls, and taint hints."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_deep_call_context",
            description="Get callers, callees, indirect callees, taint hints, and method info in one call.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name", "")
        backend = getattr(self.code_index, "backend", None)
        callers = self.code_index.get_callers(func_name, limit=20)
        callees = self.code_index.get_callees(func_name, limit=30)
        indirect = backend.get_indirect_callees(func_name, limit=20) if backend and hasattr(backend, "get_indirect_callees") else []
        taint = backend.get_taint_bugs(func_name, limit=20) if backend and hasattr(backend, "get_taint_bugs") else []
        method = backend.get_method(func_name) if backend and hasattr(backend, "get_method") else None
        return {
            "success": True,
            "data": {
                "function": func_name,
                "method_info": method,
                "callers": callers,
                "callees": callees,
                "indirect_callees": indirect,
                "taint_bugs": taint,
            },
        }

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {"func_name": {"type": "string"}},
                    "required": ["func_name"],
                },
            },
        }
