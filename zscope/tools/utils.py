from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING
from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class ListFunctionsTool(BaseTool):
    """Tool to list functions in the project (supports regex pattern)."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="list_known_functions",
            description="List functions in the project index, optionally filtered by regex pattern.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        pattern = arguments.get("pattern")
        limit = arguments.get("limit", 50)
        functions = self.code_index.list_functions(pattern=pattern, limit=limit)
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
                        "pattern": {"type": "string", "description": "Regex pattern to filter function names"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
        }


class GetFileSnippetTool(BaseTool):
    """Tool to retrieve file snippets."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_file_snippet",
            description=(
                "Read an inclusive 1-based line range from a source file for exact "
                "evidence. Use this only when the existing entry code, function "
                "snapshot, or an earlier snippet does not already contain the needed "
                "lines. Do not repeat the same or covered line range; use the prior "
                "tool result directly. If more context is needed, request one wider "
                "range instead of several overlapping ranges."
            ),
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = str(arguments.get("file_path") or "")
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
                        "file_path": {
                            "type": "string",
                            "description": "Project-relative source path, for example src/main.c.",
                        },
                        "start_line": {
                            "type": "integer",
                            "description": "Inclusive 1-based first line to read.",
                        },
                        "end_line": {
                            "type": "integer",
                            "description": (
                                "Inclusive 1-based last line to read. If omitted or "
                                "before start_line, the tool returns up to 200 lines."
                            ),
                        },
                    },
                    "required": [],
                },
            },
        }


class GetCallersTool(BaseTool):
    """Tool to find callers of a function via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_callers",
            description="Find functions that call the given function. Useful for assessing vulnerability reachability.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name
        func_name = sanitize_func_name(arguments.get("func_name", ""))
        limit = arguments.get("limit", 20)
        callers = self.code_index.get_callers(func_name, limit=limit)
        return {"success": True, "data": {"callers": callers, "count": len(callers)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string", "description": "Name of the function to find callers for"},
                        "limit": {"type": "integer", "default": 20},
                    },
                    "required": ["func_name"],
                },
            },
        }


class GetTypeInfoTool(BaseTool):
    """Tool to retrieve struct/union/enum definitions via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_type_info",
            description="Retrieve struct/union/enum definition and its members by type name.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        type_name = str(arguments.get("type_name") or "")
        info = self.code_index.get_type_info(type_name)
        if info is None:
            return {"success": False, "error": f"Type '{type_name}' not found"}
        return {"success": True, "data": info}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "type_name": {"type": "string", "description": "Name of the struct/union/enum type"},
                    },
                    "required": ["type_name"],
                },
            },
        }


class GetCallGraphTool(BaseTool):
    """Tool to get call graph around a function via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_call_graph",
            description="Get the call graph (callers and callees) around a function.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name
        func_name = sanitize_func_name(arguments.get("func_name", ""))
        depth = arguments.get("depth", 1)
        limit = arguments.get("limit", 30)
        result = {"function": func_name, "callers": [], "callees": []}
        # Build graph up to requested depth
        visited_up: Set[str] = set()
        visited_down: Set[str] = set()
        self._collect_callers(func_name, result["callers"], visited_up, depth, limit)
        self._collect_callees(func_name, result["callees"], visited_down, depth, limit)
        return {"success": True, "data": result}

    def _collect_callers(self, name, out, visited, depth, limit):
        if depth <= 0 or name in visited or len(out) >= limit:
            return
        visited.add(name)
        callers = self.code_index.get_callers(name, limit=limit - len(out))
        for c in callers:
            if len(out) >= limit:
                break
            entry = {"name": c.get("name"), "filename": c.get("filename"), "depth": depth}
            out.append(entry)
            self._collect_callers(c.get("name", ""), out, visited, depth - 1, limit)

    def _collect_callees(self, name, out, visited, depth, limit):
        if depth <= 0 or name in visited or len(out) >= limit:
            return
        visited.add(name)
        callees = self.code_index.get_callees(name, limit=limit - len(out))
        for c in callees:
            if len(out) >= limit:
                break
            entry = {"name": c.get("name"), "filename": c.get("filename"), "depth": depth}
            out.append(entry)
            self._collect_callees(c.get("name", ""), out, visited, depth - 1, limit)

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string", "description": "Center function of the call graph"},
                        "depth": {"type": "integer", "default": 1, "description": "Traversal depth (default 1)"},
                        "limit": {"type": "integer", "default": 30, "description": "Max nodes to return"},
                    },
                    "required": ["func_name"],
                },
            },
        }


class GetDataFlowTool(BaseTool):
    """Tool for taint tracking / data flow analysis via CPG."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_data_flow",
            description="Trace data flow from a source function parameter to a sink pattern (taint analysis).",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name
        source_func = sanitize_func_name(arguments.get("source_func", ""))
        source_param = str(arguments.get("source_param") or "")
        sink_pattern = str(arguments.get("sink_pattern") or "")
        flows = self.code_index.get_data_flow(source_func, source_param, sink_pattern)
        return {"success": True, "data": {"flows": flows, "count": len(flows)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "source_func": {"type": "string", "description": "Source function name"},
                        "source_param": {"type": "string", "description": "Source parameter name"},
                        "sink_pattern": {"type": "string", "description": "Sink function name pattern (regex)"},
                    },
                    "required": ["source_func", "source_param", "sink_pattern"],
                },
            },
        }


class FindFunctionPointersTool(BaseTool):
    """Tool to find function pointer assignments and callback registrations."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="find_function_pointers",
            description="Find where a function is assigned as a pointer or registered as a callback.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name
        func_name = sanitize_func_name(arguments.get("func_name", ""))
        results = self.code_index.find_function_pointers(func_name)
        return {"success": True, "data": {"references": results, "count": len(results)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string", "description": "Function name to search for pointer usage"},
                    },
                    "required": ["func_name"],
                },
            },
        }


class QueryPointerAliasTool(BaseTool):
    """Tool to retrieve SVF-resolved indirect callees."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="query_pointer_alias",
            description="Query SVF Andersen-resolved indirect call targets for a function.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name", "")
        limit = arguments.get("limit", 30)
        backend = getattr(self.code_index, "backend", None)
        if backend and hasattr(backend, "get_indirect_callees"):
            targets = backend.get_indirect_callees(func_name, limit=limit)
        else:
            targets = []
        return {"success": True, "data": {"function": func_name, "indirect_callees": targets, "count": len(targets)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string"},
                        "limit": {"type": "integer", "default": 30},
                    },
                    "required": ["func_name"],
                },
            },
        }


class VerifyTaintReachabilityTool(BaseTool):
    """Tool to retrieve SVF/Saber memory findings already imported into KnowledgeDB."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="verify_taint_reachability",
            description="Query SVF/Saber memory bug signatures such as leaks, UAF, and double free.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        bug_type = arguments.get("bug_type", "")
        limit = arguments.get("limit", 50)
        backend = getattr(self.code_index, "backend", None)
        if backend and hasattr(backend, "get_taint_bugs"):
            bugs = backend.get_taint_bugs(bug_type, limit=limit)
        else:
            bugs = []
        return {"success": True, "data": {"bugs": bugs, "count": len(bugs)}}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "bug_type": {"type": "string"},
                        "limit": {"type": "integer", "default": 50},
                    },
                },
            },
        }


class GetDeepCallContextTool(BaseTool):
    """Tool returning a compact aggregate of calls, indirect calls, and taint hints."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_deep_call_context",
            description="Get callers, callees, indirect callees, taint hints, and method info in one call.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name", "")
        backend = getattr(self.code_index, "backend", None)
        callers = self.code_index.get_callers(func_name, limit=20)
        callees = self.code_index.get_callees(func_name, limit=30)
        indirect = backend.get_indirect_callees(func_name, limit=20) if backend and hasattr(backend, "get_indirect_callees") else []
        taint = backend.get_taint_bugs(func_name, limit=20) if backend and hasattr(backend, "get_taint_bugs") else []
        method = backend.get_method(func_name) if backend and hasattr(backend, "get_method") else None
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

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {"func_name": {"type": "string"}},
                    "required": ["func_name"],
                },
            },
        }
