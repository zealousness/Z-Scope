"""
Tools runtime - implements functions callable by LLM via tool/function calling.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..retrieval.code_index import CodeIndex
from .snapshot_store import SnapshotStore

logger = logging.getLogger(__name__)


class ToolsRuntime:
    """
    Provides tools that LLM can call during analysis.
    """

    def __init__(self, code_index: CodeIndex, snapshot_store: SnapshotStore):
        """Initialize tools runtime."""
        self.code_index = code_index
        self.snapshot_store = snapshot_store

    def _validate_tool_args(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(arguments, dict):
            return {
                "success": False,
                "error": "Tool arguments must be a JSON object; please correct the payload and retry.",
            }

        def ensure_type(value: Any, expected: type, name: str) -> Optional[Dict[str, Any]]:
            if not isinstance(value, expected):
                return {
                    "success": False,
                    "error": f"'{name}' must be {expected.__name__}; please correct and retry.",
                }
            return None

        def validate_existing_file(file_path: str) -> Optional[Path]:
            return self.code_index.resolve_existing_file(file_path)

        def ensure_existing_file(file_path: str) -> Optional[Dict[str, Any]]:
            resolved = validate_existing_file(file_path)
            if resolved:
                return None
            return {
                "success": False,
                "error": (
                    f"{tool_name} requires an existing file path. "
                    f"'{file_path}' was not found; please correct the path and retry."
                ),
            }

        def validate_position(file_path: str, line: int, character: int) -> Optional[Dict[str, Any]]:
            resolved = validate_existing_file(file_path)
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

        if tool_name == "get_function_impl":
            func_name = arguments.get("func_name")
            error = ensure_type(func_name, str, "func_name") if func_name is not None else {
                "success": False,
                "error": "'func_name' is required; please correct and retry.",
            }
            if error:
                return error
            max_lines = arguments.get("max_lines")
            if max_lines is not None:
                return ensure_type(max_lines, int, "max_lines")
        elif tool_name == "get_function_snapshot":
            func_name = arguments.get("func_name")
            error = ensure_type(func_name, str, "func_name") if func_name is not None else {
                "success": False,
                "error": "'func_name' is required; please correct and retry.",
            }
            if error:
                return error
            file_path = arguments.get("file_path")
            if file_path is not None:
                return ensure_type(file_path, str, "file_path")
        elif tool_name == "list_known_functions":
            prefix = arguments.get("prefix")
            if prefix is not None:
                error = ensure_type(prefix, str, "prefix")
                if error:
                    return error
            limit = arguments.get("limit")
            if limit is not None:
                return ensure_type(limit, int, "limit")
        elif tool_name == "get_file_snippet":
            file_path = arguments.get("file_path")
            if file_path is None:
                return {"success": False, "error": "'file_path' is required; please correct and retry."}
            error = ensure_type(file_path, str, "file_path")
            if error:
                return error
            error = ensure_existing_file(file_path)
            if error:
                return error
            start_line = arguments.get("start_line")
            end_line = arguments.get("end_line")
            if start_line is None or end_line is None:
                return {
                    "success": False,
                    "error": "'start_line' and 'end_line' are required; please correct and retry.",
                }
            error = ensure_type(start_line, int, "start_line")
            if error:
                return error
            error = ensure_type(end_line, int, "end_line")
            if error:
                return error
            resolved = validate_existing_file(file_path)
            if not resolved:
                return ensure_existing_file(file_path)
            with open(resolved, "r", encoding="utf-8", errors="ignore") as handle:
                total_lines = len(handle.readlines())
            if start_line < 1 or start_line > total_lines:
                return {
                    "success": False,
                    "error": (
                        f"'start_line' {start_line} is out of range for '{file_path}'. "
                        "Please correct the line range and retry."
                    ),
                }
            if end_line < start_line or end_line > total_lines:
                return {
                    "success": False,
                    "error": (
                        f"'end_line' {end_line} is out of range for '{file_path}'. "
                        "Please correct the line range and retry."
                    ),
                }
        elif tool_name in {"get_symbol_definition", "get_type_definition", "get_hover_info"}:
            file_path = arguments.get("file_path")
            if file_path is None:
                return {"success": False, "error": "'file_path' is required; please correct and retry."}
            error = ensure_type(file_path, str, "file_path")
            if error:
                return error
            line = arguments.get("line")
            character = arguments.get("character")
            if line is None or character is None:
                return {
                    "success": False,
                    "error": "'line' and 'character' are required; please correct and retry.",
                }
            error = ensure_type(line, int, "line")
            if error:
                return error
            error = ensure_type(character, int, "character")
            if error:
                return error
            return validate_position(file_path, line, character)
        return None

    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """
        Get OpenAI function calling schema for available tools.

        Returns:
            List of tool definitions compatible with OpenAI API
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_function_impl",
                    "description": "Retrieve the source code implementation of a specific C function by name. Returns the function's code, location, signature, and list of functions it calls.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {
                                "type": "string",
                                "description": "The name of the C function to retrieve",
                            },
                            "max_lines": {
                                "type": "integer",
                                "description": "Maximum number of lines to return (default: 200, max: 500)",
                                "default": 200,
                            },
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_snapshot",
                    "description": "Retrieve a previously saved semantic snapshot of a function. Snapshots contain pre-analyzed information about the function's behavior, resources, error handling, etc. Returns null if no snapshot exists.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {
                                "type": "string",
                                "description": "The name of the function whose snapshot to retrieve",
                            },
                            "file_path": {
                                "type": "string",
                                "description": "Optional file path to disambiguate snapshots for same-named functions",
                            },
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_known_functions",
                    "description": "List all functions known in the project index. Useful for discovering available functions or searching by prefix.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "prefix": {
                                "type": "string",
                                "description": "Optional prefix to filter function names",
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return (default: 50)",
                                "default": 50,
                            },
                        },
                        "required": [],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_file_snippet",
                    "description": "Retrieve a specific line range from a source file. Useful for examining context around a specific location.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file (relative to project root or absolute)",
                            },
                            "start_line": {
                                "type": "integer",
                                "description": "Starting line number (1-indexed, inclusive)",
                            },
                            "end_line": {
                                "type": "integer",
                                "description": "Ending line number (1-indexed, inclusive)",
                            },
                        },
                        "required": ["file_path", "start_line", "end_line"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_symbol_definition",
                    "description": "Retrieve symbol definition locations using LSP.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file (relative to project root or absolute)",
                            },
                            "line": {
                                "type": "integer",
                                "description": "Line number (1-indexed)",
                            },
                            "character": {
                                "type": "integer",
                                "description": "Character offset (0-indexed)",
                            },
                        },
                        "required": ["file_path", "line", "character"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_type_definition",
                    "description": "Retrieve type definition locations using LSP.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file (relative to project root or absolute)",
                            },
                            "line": {
                                "type": "integer",
                                "description": "Line number (1-indexed)",
                            },
                            "character": {
                                "type": "integer",
                                "description": "Character offset (0-indexed)",
                            },
                        },
                        "required": ["file_path", "line", "character"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_hover_info",
                    "description": "Retrieve hover/type info for a symbol using LSP.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file (relative to project root or absolute)",
                            },
                            "line": {
                                "type": "integer",
                                "description": "Line number (1-indexed)",
                            },
                            "character": {
                                "type": "integer",
                                "description": "Character offset (0-indexed)",
                            },
                        },
                        "required": ["file_path", "line", "character"],
                    },
                },
            },
        ]

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool by name with given arguments.

        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments

        Returns:
            Tool result as JSON-serializable dict
        """
        logger.debug(f"Executing tool '{tool_name}' with args: {arguments}")

        try:
            validation_error = self._validate_tool_args(tool_name, arguments)
            if validation_error:
                return validation_error
            if tool_name == "get_function_impl":
                return self._get_function_impl(**arguments)
            elif tool_name == "get_function_snapshot":
                return self._get_function_snapshot(**arguments)
            elif tool_name == "list_known_functions":
                return self._list_known_functions(**arguments)
            elif tool_name == "get_file_snippet":
                return self._get_file_snippet(**arguments)
            elif tool_name == "get_symbol_definition":
                return self._get_symbol_definition(**arguments)
            elif tool_name == "get_type_definition":
                return self._get_type_definition(**arguments)
            elif tool_name == "get_hover_info":
                return self._get_hover_info(**arguments)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            logger.error(f"Tool execution error: {e}", exc_info=True)
            return {"error": str(e)}

    def _get_function_impl(
        self, func_name: str, max_lines: int = 200
    ) -> Dict[str, Any]:
        """Get function implementation."""
        result = self.code_index.get_function_impl(func_name, max_lines=max_lines)
        if result is None:
            return {
                "success": False,
                "error": f"Function '{func_name}' not found in project index",
            }
        return {"success": True, "data": result}

    def _get_function_snapshot(self, func_name: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """Get function snapshot from cache."""
        snapshot = self.snapshot_store.load_snapshot(func_name, file_path=file_path)
        if snapshot is None:
            return {
                "success": True,
                "data": None,
                "message": f"No snapshot exists for '{func_name}'",
            }
        return {"success": True, "data": snapshot}

    def _list_known_functions(
        self, prefix: Optional[str] = None, limit: int = 50
    ) -> Dict[str, Any]:
        """List known functions."""
        functions = self.code_index.list_functions(prefix=prefix, limit=limit)
        return {
            "success": True,
            "data": {"functions": functions, "count": len(functions), "prefix": prefix},
        }

    def _get_file_snippet(
        self, file_path: str, start_line: Optional[int], end_line: Optional[int]
    ) -> Dict[str, Any]:
        """Get file snippet."""
        result = self.code_index.get_file_snippet(file_path, start_line, end_line)
        if result is None:
            return {"success": False, "error": f"Failed to read file snippet"}
        return {"success": True, "data": result}

    def _get_symbol_definition(
        self, file_path: str, line: int, character: int
    ) -> Dict[str, Any]:
        """Get symbol definitions via LSP."""
        results = self.code_index.get_definition(file_path, line, character)
        return {"success": True, "data": {"definitions": results, "count": len(results)}}

    def _get_type_definition(
        self, file_path: str, line: int, character: int
    ) -> Dict[str, Any]:
        """Get type definitions via LSP."""
        results = self.code_index.get_type_definition(file_path, line, character)
        return {"success": True, "data": {"definitions": results, "count": len(results)}}

    def _get_hover_info(
        self, file_path: str, line: int, character: int
    ) -> Dict[str, Any]:
        """Get hover/type info via LSP."""
        hover = self.code_index.get_hover_info(file_path, line, character)
        return {"success": True, "data": {"hover": hover}}
