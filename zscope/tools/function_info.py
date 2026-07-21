from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..config.user_config_store import UserConfigStore
    from ..retrieval.code_index import CodeIndex


class GetFunctionInfoTool(BaseTool):
    """Tool to retrieve structured function metadata and symbol context."""

    def __init__(
        self,
        code_index: "CodeIndex",
        user_config: "UserConfigStore | None" = None,
    ):
        super().__init__(
            name="get_function_info",
            description=(
                "Retrieve function identity, callees, referenced globals, and referenced "
                "macros by name, optionally scoped by file path. Function-like macro matches "
                "additionally return complete definition code. Any truncation field means "
                "the corresponding array was truncated and is not exhaustive."
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

        matches = self.code_index.find_function_infos(
            func_name,
            file_path=file_path,
        )
        if not matches:
            external_name = self.code_index.fallback_function_name(func_name) or func_name
            if self.user_config:
                ext = self.user_config.get_external_function(external_name)
                if ext:
                    matches = [
                        {
                            "function_name": external_name,
                            "file_path": "[external]",
                            "start_line": 0,
                            "end_line": 0,
                            "signature": f"{external_name}(...)",
                            "code": (
                                f"/* 外部函数 (来自 {ext.get('library', '未知库')})\n"
                                f" * 描述: {ext['description']}\n"
                                f" * 内存行为: {ext.get('memory_behavior', '{}')}\n"
                                f" * 并发行为: {ext.get('concurrency_behavior', '{}')}\n"
                                f" * 返回语义: {ext.get('return_semantics', '')}\n"
                                " */"
                            ),
                            "callees": [],
                            "referenced_globals": [],
                            "referenced_macros": [],
                            "is_external": True,
                        }
                    ]
                else:
                    self.user_config.add_config_warning(
                        "missing_external_func",
                        external_name,
                        f"函数 '{external_name}' 的实现未找到，且无用户提供的外部函数描述。",
                    )
            if not matches:
                return {
                    "success": False,
                    "error": f"Function '{external_name}' not found",
                }

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
                            "description": "Function name, qualified name, or index_name for exact match.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Optional source file path used to disambiguate same-name functions.",
                        },
                    },
                    "required": ["func_name"],
                },
            },
        }
