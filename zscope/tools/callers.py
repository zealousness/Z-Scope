from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex

GET_CALLERS_LIMIT = 20
GET_CALLERS_MAX_LIMIT = 200


class GetCallersTool(BaseTool):
    """Tool to find callers of a function or function-like macro via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_callers",
            description=(
                "Find canonical caller identities, callsite lines, and direct/indirect "
                "call types for one uniquely matched function or function-like macro. "
                "Use file_path or index_name to disambiguate same-name targets. "
                f"Returns up to `limit` callers (default {GET_CALLERS_LIMIT}, max "
                f"{GET_CALLERS_MAX_LIMIT}); when more callers exist the result sets "
                "truncated=true and lists caller_count, so narrow with file_path or "
                "re-run with a larger limit instead of assuming the list is complete."
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

        raw_limit = arguments.get("limit")
        try:
            limit = int(raw_limit) if raw_limit is not None else GET_CALLERS_LIMIT
        except (TypeError, ValueError):
            limit = GET_CALLERS_LIMIT
        limit = max(1, min(GET_CALLERS_MAX_LIMIT, limit))

        # Fetch one extra caller to detect overflow so truncation is reported
        # instead of silently dropping callers beyond the limit.
        result = self.code_index.find_function_callers(
            func_name,
            file_path=file_path,
            limit=limit + 1,
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
                "error": (f"Function '{func_name}' is ambiguous; provide file_path or index_name"),
                "reason": "ambiguous_function",
                "match_count": match_count,
            }
        callers = list(result.get("callers") or [])
        truncated = len(callers) > limit
        if truncated:
            callers = callers[:limit]
        data: Dict[str, Any] = {
            "callers": callers,
            "caller_count": len(callers),
            "truncated": truncated,
        }
        if truncated:
            data["note"] = (
                f"More than {limit} callers exist; re-run with a larger limit "
                f"(max {GET_CALLERS_MAX_LIMIT}) or narrow the target with file_path."
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
                        "func_name": {
                            "type": "string",
                            "description": (
                                "Function or function-like macro name, qualified name, "
                                "or index_name for exact match."
                            ),
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Optional source file path used to disambiguate same-name targets.",
                        },
                        "limit": {
                            "type": "integer",
                            "description": (
                                f"Optional maximum number of callers to return "
                                f"(default {GET_CALLERS_LIMIT}, max {GET_CALLERS_MAX_LIMIT})."
                            ),
                        },
                    },
                    "required": ["func_name"],
                },
            },
        }
