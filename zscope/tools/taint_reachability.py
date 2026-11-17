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
        try:
            parsed_limit = max(1, int(limit))
        except (TypeError, ValueError):
            parsed_limit = 50
        backend = getattr(self.code_index, "backend", None)
        if backend and hasattr(backend, "get_taint_bugs"):
            fetched = backend.get_taint_bugs(bug_type, limit=parsed_limit + 1)
        else:
            return {
                "success": False,
                "status": "unavailable",
                "error": "The current backend cannot query imported taint findings.",
            }
        truncated = len(fetched) > parsed_limit
        bugs = fetched[:parsed_limit]
        data = {"bugs": bugs, "count": len(bugs), "truncated": truncated}
        if truncated:
            data["note"] = (
                f"More than {parsed_limit} signatures match; re-run with a "
                "larger limit to see the remaining taint findings."
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
                        "bug_type": {"type": "string"},
                        "limit": {
                            "type": "integer",
                            "default": 50,
                            "description": "Max signatures to return; truncated=true means more exist",
                        },
                    },
                },
            },
        }
