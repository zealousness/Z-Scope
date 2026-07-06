from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class VerifyTaintReachabilityTool(BaseTool):
    """Tool to retrieve SVF/Saber memory findings already imported into KnowledgeDB."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="verify_taint_reachability",
            description="Query SVF/Saber memory bug signatures such as leaks, UAF, and double free.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        bug_type = arguments.get("bug_type", "")
        limit = arguments.get("limit", 50)
        backend = getattr(self.code_index, "backend", None)
        if backend and hasattr(backend, "get_taint_bugs"):
            bugs = backend.get_taint_bugs(bug_type, limit=limit)
        else:
            bugs = []
        return {"success": True, "data": {"bugs": bugs, "count": len(bugs)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "bug_type": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
        }
