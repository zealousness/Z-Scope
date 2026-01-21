from typing import Dict, Any, Optional
from ..framework.base import BaseTool
from ..retrieval.code_index import CodeIndex

class ListFunctionsTool(BaseTool):
    """Tool to list functions in the project."""
    
    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="list_known_functions",
            description="List all functions known in the project index."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        prefix = arguments.get("prefix")
        limit = arguments.get("limit", 50)
        functions = self.code_index.list_functions(prefix=prefix, limit=limit)
        return {"success": True, "data": {"functions": functions, "count": len(functions)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "prefix": {"type": "string"},
                        "limit": {"type": "integer", "default": 50}
                    }
                },
            },
        }

class GetFileSnippetTool(BaseTool):
    """Tool to retrieve file snippets."""
    
    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_file_snippet",
            description="Retrieve a specific line range from a source file."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path")
        start = arguments.get("start_line")
        end = arguments.get("end_line")
        result = self.code_index.get_file_snippet(file_path, start, end)
        if result is None:
            return {"success": False, "error": "Failed to read file"}
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
                        "file_path": {"type": "string"},
                        "start_line": {"type": "integer"},
                        "end_line": {"type": "integer"}
                    },
                    "required": ["file_path", "start_line", "end_line"],
                },
            },
        }
