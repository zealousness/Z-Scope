from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


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
