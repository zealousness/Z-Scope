from typing import Dict, Any, Optional, List
from ..framework.base import BaseTool
from ..retrieval.code_index import CodeIndex


class ListFunctionsTool(BaseTool):
    """Tool to list functions in the project (supports regex pattern)."""

    def __init__(self, code_index: CodeIndex):
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


class GetCallersTool(BaseTool):
    """Tool to find callers of a function via CPG."""

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_callers",
            description="Find functions that call the given function. Useful for assessing vulnerability reachability.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name")
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

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_type_info",
            description="Retrieve struct/union/enum definition and its members by type name.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        type_name = arguments.get("type_name")
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

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_call_graph",
            description="Get the call graph (callers and callees) around a function.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name")
        depth = arguments.get("depth", 1)
        limit = arguments.get("limit", 30)
        result = {"function": func_name, "callers": [], "callees": []}
        # Build graph up to requested depth
        visited_up = set()
        visited_down = set()
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

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="get_data_flow",
            description="Trace data flow from a source function parameter to a sink pattern (taint analysis).",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        source_func = arguments.get("source_func")
        source_param = arguments.get("source_param")
        sink_pattern = arguments.get("sink_pattern")
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

    def __init__(self, code_index: CodeIndex):
        super().__init__(
            name="find_function_pointers",
            description="Find where a function is assigned as a pointer or registered as a callback.",
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name")
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
