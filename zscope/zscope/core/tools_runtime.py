"""
Tools runtime - implements functions callable by LLM via tool/function calling.
"""

import logging
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
            if tool_name == "get_function_impl":
                return self._get_function_impl(**arguments)
            elif tool_name == "get_function_snapshot":
                return self._get_function_snapshot(**arguments)
            elif tool_name == "list_known_functions":
                return self._list_known_functions(**arguments)
            elif tool_name == "get_file_snippet":
                return self._get_file_snippet(**arguments)
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
