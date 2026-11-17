from typing import Dict, Any, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class GetFunctionImplTool(BaseTool):
    """Tool to retrieve function implementation."""

    def __init__(self, code_index: "CodeIndex", user_config=None):
        super().__init__(
            name="get_function_impl",
            description=(
                "Retrieve a C function or macro implementation by name, signature, or "
                "index_name. Exact queries are preserved; CodeIndex uses a controlled "
                "simple-name fallback only after an exact lookup misses. Project function "
                "results include boolean is_static; macro and external results omit it."
            ),
        )
        self.code_index = code_index
        self.user_config = user_config

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = str(arguments.get("func_name") or "").strip()
        if not func_name:
            return {"success": False, "error": "Function name is empty"}

        max_lines = arguments.get("max_lines", 200)

        result = self.code_index.get_function_impl(
            func_name, max_lines=max_lines, warn_missing=False
        )
        if result is None:
            external_name = self.code_index.fallback_function_name(func_name) or func_name
            if self.user_config:
                ext = self.user_config.get_external_function(external_name)
                if ext:
                    return {
                        "success": True,
                        "data": {
                            "func_name": external_name,
                            "code": (
                                f"/* 外部函数 (来自 {ext.get('library', '未知库')})\n"
                                f" * 描述: {ext['description']}\n"
                                f" * 内存行为: {ext.get('memory_behavior', '{}')}\n"
                                f" * 并发行为: {ext.get('concurrency_behavior', '{}')}\n"
                                f" * 返回语义: {ext.get('return_semantics', '')}\n"
                                " */"
                            ),
                            "file": "[external]",
                            "start_line": 0,
                            "end_line": 0,
                            "callees": [],
                            "signature": f"{external_name}(...)",
                            "truncated": False,
                            "is_external": True,
                        },
                    }
                self.user_config.add_config_warning(
                    "missing_external_func",
                    external_name,
                    f"函数 '{external_name}' 的实现未找到，且无用户提供的外部函数描述。",
                )
            return {
                "success": False,
                "error": f"Function '{external_name}' not found",
            }
        return {"success": True, "data": result}

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
                            "description": "Function name, signature, or index_name",
                        },
                        "max_lines": {"type": "integer", "default": 200},
                    },
                    "required": ["func_name"],
                },
            },
        }
