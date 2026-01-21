from typing import Dict, Any
from ..framework.base import BaseTool
from ..core.snapshot_store import SnapshotStore

class GetFunctionSnapshotTool(BaseTool):
    """Tool to retrieve function semantic snapshot."""
    
    def __init__(self, snapshot_store: SnapshotStore):
        super().__init__(
            name="get_function_snapshot",
            description="Retrieve a previously saved semantic snapshot of a function."
        )
        self.snapshot_store = snapshot_store

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name")
        snapshot = self.snapshot_store.load_snapshot(func_name)
        if snapshot is None:
            return {"success": True, "data": None, "message": "No snapshot exists"}
        return {"success": True, "data": snapshot}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {"type": "string"}
                    },
                    "required": ["func_name"],
                },
            },
        }
