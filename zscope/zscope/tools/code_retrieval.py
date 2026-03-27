from typing import Dict, Any
from ..framework.base import BaseTool
from ..retrieval.code_index import CodeIndex

class GetFunctionImplTool(BaseTool):
    """Tool to retrieve function implementation."""
    
    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_function_impl",
            description="Retrieve the source code implementation of a specific C function by name."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name
        func_name = sanitize_func_name(arguments.get("func_name", ""))
        if not func_name:
            return {"success": False, "error": "Function name is empty"}
            
        max_lines = arguments.get("max_lines", 200)
        
        result = self.code_index.get_function_impl(func_name, max_lines=max_lines)
        if result is None:
            return {
                "success": False,
                "error": f"Function '{func_name}' not found",
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
                        "func_name": {"type": "string", "description": "The name of the function"},
                        "max_lines": {"type": "integer", "default": 200}
                    },
                    "required": ["func_name"],
                },
            },
        }
