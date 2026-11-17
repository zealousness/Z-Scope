from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


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
                        "sink_pattern": {
                            "type": "string",
                            "description": "Sink function name pattern (regex)",
                        },
                    },
                    "required": ["source_func", "source_param", "sink_pattern"],
                },
            },
        }
