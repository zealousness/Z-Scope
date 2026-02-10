from typing import Dict, Any, Optional
from ..framework.base import BaseTool
from ..retrieval.code_index import CodeIndex


def _validate_file_position(
    code_index: CodeIndex,
    tool_name: str,
    file_path: Any,
    line: Any,
    character: Any,
) -> Optional[Dict[str, Any]]:
    if not isinstance(file_path, str):
        return {"success": False, "error": "'file_path' must be string; please correct and retry."}
    if not isinstance(line, int) or not isinstance(character, int):
        return {
            "success": False,
            "error": "'line' and 'character' must be integers; please correct and retry.",
        }

    resolved = code_index.resolve_existing_file(file_path)
    if not resolved:
        return {
            "success": False,
            "error": (
                f"{tool_name} requires an existing file path. "
                f"'{file_path}' was not found; please correct the path and retry."
            ),
        }

    try:
        with open(resolved, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.readlines()
    except OSError as exc:
        return {"success": False, "error": f"Failed to read '{file_path}': {exc}"}

    if line < 1 or line > len(lines):
        return {
            "success": False,
            "error": (
                f"'{tool_name}' line {line} is out of range for '{file_path}'. "
                "Please correct the line number and retry."
            ),
        }

    line_text = lines[line - 1].rstrip("\n")
    if character < 0 or character > len(line_text):
        return {
            "success": False,
            "error": (
                f"'{tool_name}' character {character} is out of range for line {line} in '{file_path}'. "
                "Please correct the character offset and retry."
            ),
        }
    return None


class ListFunctionsTool(BaseTool):
    """Tool to list functions in the project."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="list_known_functions",
            description="List all functions known in the project index.",
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
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
        }


class GetFileSnippetTool(BaseTool):
    """Tool to retrieve file snippets."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_file_snippet",
            description="Retrieve a specific line range from a source file.",
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
                        "end_line": {"type": "integer"},
                    },
                    "required": [],
                },
            },
        }


class GetSymbolDefinitionTool(BaseTool):
    """Tool to retrieve symbol definitions via LSP."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_symbol_definition",
            description="Retrieve symbol definition locations using LSP.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path")
        line = arguments.get("line")
        character = arguments.get("character")
        validation_error = _validate_file_position(
            self.code_index, self.name, file_path, line, character
        )
        if validation_error:
            return validation_error
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
                        "character": {"type": "integer"},
                    },
                    "required": [],
                },
            },
        }


class GetTypeDefinitionTool(BaseTool):
    """Tool to retrieve type definitions via LSP."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_type_definition", description="Retrieve type definition locations using LSP."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path")
        line = arguments.get("line")
        character = arguments.get("character")
        validation_error = _validate_file_position(
            self.code_index, self.name, file_path, line, character
        )
        if validation_error:
            return validation_error
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
                        "character": {"type": "integer"},
                    },
                    "required": [],
                },
            },
        }


class GetHoverInfoTool(BaseTool):
    """Tool to retrieve hover/type info via LSP."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_hover_info", description="Retrieve hover/type info for a symbol using LSP."
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = arguments.get("file_path")
        line = arguments.get("line")
        character = arguments.get("character")
        validation_error = _validate_file_position(
            self.code_index, self.name, file_path, line, character
        )
        if validation_error:
            return validation_error
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
                        "character": {"type": "integer"},
                    },
                    "required": [],
                },
            },
        }
