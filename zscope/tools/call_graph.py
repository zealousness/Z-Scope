from typing import Any, Dict, TYPE_CHECKING

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
        func_name = str(arguments.get("func_name") or "").strip()
        if not func_name:
            return {"success": False, "error": "Function name is empty"}
        try:
            depth = int(arguments.get("depth", 1))
            limit = int(arguments.get("limit", 30))
        except (TypeError, ValueError, OverflowError):
            return {"success": False, "error": "depth and limit must be integers"}
        if not 0 <= depth <= 64 or limit < 1:
            return {
                "success": False,
                "error": "depth must be between 0 and 64; limit must be positive",
            }
        # An explicit value type keeps mypy from joining the heterogeneous
        # initial literal into Sequence[str] and rejecting the truncated flag.
        result: Dict[str, Any] = {
            "function": func_name,
            "callers": [],
            "callees": [],
        }
        # Build graph up to requested depth
        visited_up: Dict[str, int] = {}
        visited_down: Dict[str, int] = {}
        self._collect_callers(func_name, result["callers"], visited_up, depth, limit + 1)
        self._collect_callees(func_name, result["callees"], visited_down, depth, limit + 1)
        # One extra row distinguishes an incomplete neighborhood from an exact fit.
        if len(result["callers"]) > limit or len(result["callees"]) > limit:
            result["truncated"] = True
            result["note"] = (
                f"The caller or callee list hit the {limit}-node limit; re-run "
                "with a larger limit for the complete neighborhood."
            )
        result["callers"] = result["callers"][:limit]
        result["callees"] = result["callees"][:limit]
        return {"success": True, "data": result}

    def _collect_callers(self, name, out, visited, depth, limit):
        if depth <= 0 or visited.get(name, 0) >= depth or len(out) >= limit:
            return
        # A shorter route may leave more depth to inspect an already seen node.
        visited[name] = depth
        callers = self.code_index.get_callers(name, limit=limit - len(out))
        for c in callers:
            if len(out) >= limit:
                break
            entry = {"name": c.get("name"), "filename": c.get("filename"), "depth": depth}
            out.append(entry)
            self._collect_callers(c.get("name", ""), out, visited, depth - 1, limit)

    def _collect_callees(self, name, out, visited, depth, limit):
        if depth <= 0 or visited.get(name, 0) >= depth or len(out) >= limit:
            return
        visited[name] = depth
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
                        "func_name": {
                            "type": "string",
                            "description": "Center function of the call graph",
                        },
                        "depth": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 64,
                            "default": 1,
                            "description": "Traversal depth (default 1)",
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 30,
                            "description": "Max nodes to return",
                        },
                    },
                    "required": ["func_name"],
                },
            },
        }
