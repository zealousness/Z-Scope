"""
Tools runtime - implements functions callable by LLM via tool/function calling.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

from ..retrieval.code_index import CodeIndex
from .snapshot_store import SnapshotStore
from ..config.user_config_store import UserConfigStore

logger = logging.getLogger(__name__)


class ToolsRuntime:
    """
    Provides tools that LLM can call during analysis.
    """

    def __init__(self, code_index: CodeIndex, snapshot_store: SnapshotStore,
                 user_config: Optional['UserConfigStore'] = None):
        """Initialize tools runtime."""
        self.code_index = code_index
        self.snapshot_store = snapshot_store
        self.user_config = user_config
        self._location_context: Dict[str, Any] = {
            "file_path": None,
            "line": None,
            "start_line": None,
            "end_line": None,
        }

    def _update_location_context(
        self,
        file_path: Optional[str] = None,
        line: Optional[int] = None,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> None:
        """Persist the latest successful location context for later tool auto-fill."""
        if file_path:
            self._location_context["file_path"] = file_path
        if line is not None:
            self._location_context["line"] = line
        if start_line is not None:
            self._location_context["start_line"] = start_line
            self._location_context["line"] = start_line
        if end_line is not None:
            self._location_context["end_line"] = end_line

    def _autofill_tool_args(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Fill missing file/line arguments from recent tool context when possible."""
        filled = dict(arguments)

        if tool_name == "get_file_snippet":
            if not filled.get("file_path") and self._location_context.get("file_path"):
                filled["file_path"] = self._location_context["file_path"]
            if filled.get("start_line") is None:
                context_start = self._location_context.get("start_line")
                if context_start is not None:
                    filled["start_line"] = context_start
            if filled.get("end_line") is None and filled.get("start_line") is not None:
                filled["end_line"] = filled["start_line"] + 40

        return filled

    def _validate_tool_args(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
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

        if tool_name == "get_function_impl":
            func_name = arguments.get("func_name")
            error = (
                ensure_type(func_name, str, "func_name")
                if func_name is not None
                else {
                    "success": False,
                    "error": "'func_name' is required; please correct and retry.",
                }
            )
            if error:
                return error
            max_lines = arguments.get("max_lines")
            if max_lines is not None:
                return ensure_type(max_lines, int, "max_lines")
        elif tool_name == "get_function_snapshot":
            func_name = arguments.get("func_name")
            error = (
                ensure_type(func_name, str, "func_name")
                if func_name is not None
                else {
                    "success": False,
                    "error": "'func_name' is required; please correct and retry.",
                }
            )
            if error:
                return error
            file_path = arguments.get("file_path")
            if file_path is not None:
                return ensure_type(file_path, str, "file_path")
        elif tool_name == "list_known_functions":
            pattern = arguments.get("pattern")
            if pattern is not None:
                error = ensure_type(pattern, str, "pattern")
                if error:
                    return error
            limit = arguments.get("limit")
            if limit is not None:
                return ensure_type(limit, int, "limit")
        elif tool_name == "get_file_snippet":
            file_path = arguments.get("file_path")
            if file_path is None:
                return {
                    "success": False,
                    "error": "'file_path' is required; please correct and retry.",
                }
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
        elif tool_name in {"get_callers", "get_call_graph", "find_function_pointers", "query_pointer_alias"}:
            func_name = arguments.get("func_name")
            if func_name is None:
                return {"success": False, "error": "'func_name' is required; please correct and retry."}
            return ensure_type(func_name, str, "func_name")
        elif tool_name == "get_type_info":
            type_name = arguments.get("type_name")
            if type_name is None:
                return {"success": False, "error": "'type_name' is required; please correct and retry."}
            return ensure_type(type_name, str, "type_name")
        elif tool_name == "get_data_flow":
            for param in ("source_func", "source_param", "sink_pattern"):
                val = arguments.get(param)
                if val is None:
                    return {"success": False, "error": f"'{param}' is required; please correct and retry."}
                error = ensure_type(val, str, param)
                if error:
                    return error
        return None

    def get_tools_schema(self) -> List[Dict[str, Any]]:
        """Get OpenAI function calling schema for available tools."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "get_function_impl",
                    "description": "Retrieve the source code of a C function by name.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {"type": "string", "description": "Function name"},
                            "max_lines": {"type": "integer", "default": 200},
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function_snapshot",
                    "description": "Retrieve a previously saved semantic snapshot of a function.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {"type": "string"},
                            "file_path": {"type": "string"},
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_known_functions",
                    "description": "List functions in the project index, filtered by regex pattern.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "pattern": {"type": "string", "description": "Regex pattern to filter"},
                            "limit": {"type": "integer", "default": 50},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_file_snippet",
                    "description": "Retrieve a specific line range from a source file.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {"type": "string"},
                            "start_line": {"type": "integer"},
                            "end_line": {"type": "integer"},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_callers",
                    "description": "Find functions that call the given function (vulnerability reachability).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {"type": "string"},
                            "limit": {"type": "integer", "default": 20},
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_type_info",
                    "description": "Retrieve struct/union/enum definition and members by type name.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "type_name": {"type": "string"},
                        },
                        "required": ["type_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_call_graph",
                    "description": "Get call graph (callers and callees) around a function.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {"type": "string"},
                            "depth": {"type": "integer", "default": 1},
                            "limit": {"type": "integer", "default": 30},
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_data_flow",
                    "description": "Trace data flow from source parameter to sink (taint analysis).",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "source_func": {"type": "string"},
                            "source_param": {"type": "string"},
                            "sink_pattern": {"type": "string"},
                        },
                        "required": ["source_func", "source_param", "sink_pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "find_function_pointers",
                    "description": "Find function pointer assignments and callback registrations.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {"type": "string"},
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "query_pointer_alias",
                    "description": "查询 SVF Andersen 指针分析解析出的间接调用目标。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {"type": "string"},
                            "limit": {"type": "integer", "default": 30},
                        },
                        "required": ["func_name"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "verify_taint_reachability",
                    "description": "查询 SVF Saber 检测到的内存缺陷（泄漏/UAF/双重释放）。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "bug_type": {"type": "string", "description": "缺陷类型过滤"},
                            "limit": {"type": "integer", "default": 50},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_deep_call_context",
                    "description": "获取函数的深度调用上下文：合并直接/间接调用关系 + 相关污点缺陷 + 函数签名。一次调用返回完整分析上下文。",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "func_name": {"type": "string", "description": "函数名"},
                        },
                        "required": ["func_name"],
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
            effective_args = self._autofill_tool_args(tool_name, arguments)
            validation_error = self._validate_tool_args(tool_name, effective_args)
            if validation_error:
                return validation_error
            if tool_name == "get_function_impl":
                return self._get_function_impl(**effective_args)
            elif tool_name == "get_function_snapshot":
                return self._get_function_snapshot(**effective_args)
            elif tool_name == "list_known_functions":
                return self._list_known_functions(**effective_args)
            elif tool_name == "get_file_snippet":
                return self._get_file_snippet(**effective_args)
            elif tool_name == "get_callers":
                return self._get_callers(**effective_args)
            elif tool_name == "get_type_info":
                return self._get_type_info(**effective_args)
            elif tool_name == "get_call_graph":
                return self._get_call_graph(**effective_args)
            elif tool_name == "get_data_flow":
                return self._get_data_flow(**effective_args)
            elif tool_name == "find_function_pointers":
                return self._find_function_pointers(**effective_args)
            elif tool_name == "query_pointer_alias":
                return self._query_pointer_alias(**effective_args)
            elif tool_name == "verify_taint_reachability":
                return self._verify_taint_reachability(**effective_args)
            elif tool_name == "get_deep_call_context":
                return self._get_deep_call_context(**effective_args)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            logger.error(f"Tool execution error: {e}", exc_info=True)
            return {"error": str(e)}

    def _get_function_impl(self, func_name: str, max_lines: int = 200) -> Dict[str, Any]:
        """Get function implementation. Falls back to user-provided external function description."""
        result = self.code_index.get_function_impl(func_name, max_lines=max_lines)
        if result is None:
            # Check user config for external function description
            if self.user_config:
                ext = self.user_config.get_external_function(func_name)
                if ext:
                    return {
                        "success": True,
                        "data": {
                            "code": f"/* 外部函数 (来自 {ext.get('library', '未知库')})\n"
                                    f" * 描述: {ext['description']}\n"
                                    f" * 内存行为: {ext.get('memory_behavior', '{}')}\n"
                                    f" * 并发行为: {ext.get('concurrency_behavior', '{}')}\n"
                                    f" * 返回语义: {ext.get('return_semantics', '')}\n */",
                            "file": "[external]",
                            "start_line": 0,
                            "end_line": 0,
                            "is_external": True,
                        },
                    }
                # No user description — record a config warning
                self.user_config.add_config_warning(
                    "missing_external_func", func_name,
                    f"函数 '{func_name}' 的实现未找到，且无用户提供的外部函数描述。"
                )
            return {
                "success": False,
                "error": f"Function '{func_name}' not found in project index",
            }
        self._update_location_context(
            file_path=result.get("file"),
            start_line=result.get("start_line"),
            end_line=result.get("end_line"),
        )
        return {"success": True, "data": result}

    def _get_function_snapshot(
        self, func_name: str, file_path: Optional[str] = None
    ) -> Dict[str, Any]:
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
        self, pattern: Optional[str] = None, limit: int = 50
    ) -> Dict[str, Any]:
        """List known functions."""
        functions = self.code_index.list_functions(pattern=pattern, limit=limit)
        return {
            "success": True,
            "data": {"functions": functions, "count": len(functions), "pattern": pattern},
        }

    def _get_file_snippet(
        self, file_path: str, start_line: Optional[int], end_line: Optional[int]
    ) -> Dict[str, Any]:
        """Get file snippet."""
        result = self.code_index.get_file_snippet(file_path, start_line, end_line)
        if result is None:
            return {"success": False, "error": f"Failed to read file snippet"}
        self._update_location_context(
            file_path=result.get("file"),
            start_line=result.get("start_line"),
            end_line=result.get("end_line"),
        )
        return {"success": True, "data": result}

    def _get_callers(self, func_name: str, limit: int = 20) -> Dict[str, Any]:
        """Get callers of a function."""
        callers = self.code_index.get_callers(func_name, limit=limit)
        return {"success": True, "data": {"callers": callers, "count": len(callers)}}

    def _get_type_info(self, type_name: str) -> Dict[str, Any]:
        """Get type definition and members."""
        info = self.code_index.get_type_info(type_name)
        if info is None:
            return {"success": False, "error": f"Type '{type_name}' not found"}
        return {"success": True, "data": info}

    def _get_call_graph(self, func_name: str, depth: int = 1, limit: int = 30) -> Dict[str, Any]:
        """Get call graph around a function."""
        callers = self.code_index.get_callers(func_name, limit=limit)
        callees = self.code_index.get_callees(func_name, limit=limit)
        return {
            "success": True,
            "data": {"function": func_name, "callers": callers, "callees": callees},
        }

    def _get_data_flow(
        self, source_func: str, source_param: str, sink_pattern: str
    ) -> Dict[str, Any]:
        """Trace data flow from source to sink."""
        flows = self.code_index.get_data_flow(source_func, source_param, sink_pattern)
        return {"success": True, "data": {"flows": flows, "count": len(flows)}}

    def _find_function_pointers(self, func_name: str) -> Dict[str, Any]:
        """Find function pointer assignments."""
        refs = self.code_index.find_function_pointers(func_name)
        return {"success": True, "data": {"references": refs, "count": len(refs)}}

    def _query_pointer_alias(self, func_name: str, limit: int = 30) -> Dict[str, Any]:
        """查询 SVF 解析出的间接调用目标。"""
        backend = self.code_index.backend
        if backend and hasattr(backend, "get_indirect_callees"):
            targets = backend.get_indirect_callees(func_name, limit=limit)
        else:
            targets = []
        return {"success": True, "data": {"function": func_name, "indirect_callees": targets, "count": len(targets)}}

    def _verify_taint_reachability(self, bug_type: str = "", limit: int = 50) -> Dict[str, Any]:
        """查询 SVF Saber 检测到的污点/内存缺陷。"""
        backend = self.code_index.backend
        if backend and hasattr(backend, "get_taint_bugs"):
            bugs = backend.get_taint_bugs(bug_type, limit=limit)
        else:
            bugs = []
        return {"success": True, "data": {"bugs": bugs, "count": len(bugs)}}

    def _get_deep_call_context(self, func_name: str) -> Dict[str, Any]:
        """高聚合查询：一次返回调用图 + 间接调用 + 污点缺陷 + 函数签名。"""
        backend = self.code_index.backend
        callers = self.code_index.get_callers(func_name, limit=20)
        callees = self.code_index.get_callees(func_name, limit=30)
        indirect = []
        if backend and hasattr(backend, "get_indirect_callees"):
            indirect = backend.get_indirect_callees(func_name, limit=20)
        taint = []
        if backend and hasattr(backend, "get_taint_bugs"):
            taint = backend.get_taint_bugs(func_name, limit=20)
        method = backend.get_method(func_name) if backend else None
        return {
            "success": True,
            "data": {
                "function": func_name,
                "method_info": method,
                "callers": callers,
                "callees": callees,
                "indirect_callees": indirect,
                "taint_bugs": taint,
            },
        }
