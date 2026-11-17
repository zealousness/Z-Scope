from typing import Dict, Any, TYPE_CHECKING
from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class FollowTaintTool(BaseTool):
    """
    Experimental tool to retrieve the Data Flow Graph (DFG) slice for a specific variable.
    Requires an underlying graph backend like SVF or Joern.
    """

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="follow_taint",
            description=(
                "Legacy DFG-slicing entry point; implementation is unavailable. "
                "Use trace_data_flow for supported queries."
            ),
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        variable = arguments.get("variable")
        location = arguments.get("location")
        if not variable or not location:
            return {"success": False, "error": "Missing required arguments: variable, location"}

        # Keep the public compatibility entry without presenting a scaffold as evidence.
        return {
            "success": False,
            "status": "unavailable",
            "error": "DFG slicing is not implemented by this legacy tool.",
            "hint": "Use trace_data_flow for supported backend analysis.",
        }

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "variable": {
                            "type": "string",
                            "description": "The name of the variable to trace (e.g., 'req->buffer')",
                        },
                        "location": {
                            "type": "string",
                            "description": "The starting line locus where the variable is defined or used (e.g., '145' or 'main.c:145')",
                        },
                        "direction": {
                            "type": "string",
                            "enum": ["forward", "backward", "both"],
                            "description": "Direction of taint tracking",
                        },
                        "depth": {
                            "type": "integer",
                            "description": "Maximum call depth to trace. Default is 3.",
                        },
                    },
                    "required": ["variable", "location", "direction"],
                },
            },
        }
