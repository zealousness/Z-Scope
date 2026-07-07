from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..config.user_config_store import UserConfigStore
    from ..retrieval.code_index import CodeIndex


class GetFunctionInfoTool(BaseTool):
    """Tool to retrieve structured function metadata and call relationships."""

    def __init__(
        self,
        code_index: "CodeIndex",
        user_config: "UserConfigStore | None" = None,
    ):
        super().__init__(
            name="get_function_info",
            description=(
                "Retrieve structured metadata and caller/callee relationships for "
                "a function by name, optionally scoped by file path."
            ),
        )
        self.code_index = code_index
        self.user_config = user_config

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = str(arguments.get("func_name") or "").strip()
        if not func_name:
            return {"success": False, "error": "Function name is empty"}

        file_path = arguments.get("file_path") or ""
        if not isinstance(file_path, str):
            return {"success": False, "error": "file_path must be a string"}

        callers_limit = arguments.get("callers_limit", 30)
        callees_limit = arguments.get("callees_limit", 30)
        if not isinstance(callers_limit, int):
            return {"success": False, "error": "callers_limit must be an integer"}
        if not isinstance(callees_limit, int):
            return {"success": False, "error": "callees_limit must be an integer"}

        matches = self.code_index.find_function_infos(
            func_name,
            file_path=file_path,
            callers_limit=callers_limit,
            callees_limit=callees_limit,
        )
        if not matches and self.user_config:
            ext = self.user_config.get_external_function(func_name)
            if ext:
                matches = [
                    {
                        "function_name": func_name,
                        "file_path": "[external]",
                        "index_name": func_name,
                        "start_line": 0,
                        "end_line": 0,
                        "signature": f"{func_name}(...)",
                        "callers": [],
                        "callees": [],
                        "is_external": True,
                    }
                ]

        return {
            "success": True,
            "data": {
                "match_count": len(matches),
                "matches": matches,
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
                    "properties": {
                        "func_name": {
                            "type": "string",
                            "description": "Function name, qualified name, or index_name",
                        },
                        "file_path": {
                            "type": "string",
                            "description": (
                                "Optional source file path used to disambiguate "
                                "same-name functions"
                            ),
                        },
                        "callers_limit": {
                            "type": "integer",
                            "default": 30,
                            "description": "Maximum callers returned per matched function",
                        },
                        "callees_limit": {
                            "type": "integer",
                            "default": 30,
                            "description": "Maximum callees returned per matched function",
                        },
                    },
                    "required": ["func_name"],
                },
            },
        }
