from typing import Any, Dict, Set, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class GetCallGraphTool(BaseTool):
    """Tool to get call graph around a function via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_call_graph",
            description="Get the call graph (callers and callees) around a function.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name

        func_name = sanitize_func_name(arguments.get("func_name", ""))
        depth = arguments.get("depth", 1)
        limit = arguments.get("limit", 30)
        result = {"function": func_name, "callers": [], "callees": []}
        # Build graph up to requested depth
        visited_up: Set[str] = set()
        visited_down: Set[str] = set()
        self._collect_callers(func_name, result["callers"], visited_up, depth, limit)
        self._collect_callees(func_name, result["callees"], visited_down, depth, limit)
        return {"success": True, "data": result}

    def _collect_callers(self, name, out, visited, depth, limit):
        if depth <= 0 or name in visited or len(out) >= limit:
            return
        visited.add(name)
        callers = self.code_index.get_callers(name, limit=limit - len(out))
        for c in callers:
            if len(out) >= limit:
                break
            entry = {"name": c.get("name"), "filename": c.get("filename"), "depth": depth}
            out.append(entry)
            self._collect_callers(c.get("name", ""), out, visited, depth - 1, limit)

    def _collect_callees(self, name, out, visited, depth, limit):
        if depth <= 0 or name in visited or len(out) >= limit:
            return
        visited.add(name)
        callees = self.code_index.get_callees(name, limit=limit - len(out))
        for c in callees:
            if len(out) >= limit:
                break
            entry = {"name": c.get("name"), "filename": c.get("filename"), "depth": depth}
            out.append(entry)
            self._collect_callees(c.get("name", ""), out, visited, depth - 1, limit)

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string", "description": "Center function of the call graph"},
                        "depth": {"type": "integer", "default": 1, "description": "Traversal depth (default 1)"},
                        "limit": {"type": "integer", "default": 30, "description": "Max nodes to return"},
                    },
                    "required": ["func_name"],
                },
            },
        }
