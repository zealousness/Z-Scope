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

class GetSymbolDefinitionTool(BaseTool):
    """Tool to retrieve symbol definitions via LSP."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_symbol_definition",
            description="Retrieve symbol definition locations using LSP."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path")
        line = arguments.get("line")
        character = arguments.get("character")
        results = self.code_index.get_definition(file_path, line, character)
        return {"success": True, "data": {"definitions": results, "count": len(results)}}

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
                        "line": {"type": "integer"},
                        "character": {"type": "integer"}
                    },
                    "required": ["file_path", "line", "character"],
                },
            },
        }

class GetTypeDefinitionTool(BaseTool):
    """Tool to retrieve type definitions via LSP."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_type_definition",
            description="Retrieve type definition locations using LSP."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path")
        line = arguments.get("line")
        character = arguments.get("character")
        results = self.code_index.get_type_definition(file_path, line, character)
        return {"success": True, "data": {"definitions": results, "count": len(results)}}

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
                        "line": {"type": "integer"},
                        "character": {"type": "integer"}
                    },
                    "required": ["file_path", "line", "character"],
                },
            },
        }

class GetHoverInfoTool(BaseTool):
    """Tool to retrieve hover/type info via LSP."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_hover_info",
            description="Retrieve hover/type info for a symbol using LSP."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path")
        line = arguments.get("line")
        character = arguments.get("character")
        hover = self.code_index.get_hover_info(file_path, line, character)
        return {"success": True, "data": {"hover": hover}}

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
                        "line": {"type": "integer"},
                        "character": {"type": "integer"}
                    },
                    "required": ["file_path", "line", "character"],
                },
            },
        }
