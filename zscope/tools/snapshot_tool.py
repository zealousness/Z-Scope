from typing import Callable, Dict, Any, Optional
from ..framework.base import BaseTool
from ..snapshots.store import SnapshotStore

class GetFunctionSnapshotTool(BaseTool):
    """Tool to retrieve function semantic snapshot."""
    
    def __init__(
        self,
        snapshot_store: SnapshotStore,
        resolver: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None,
        on_missing: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None,
    ):
        super().__init__(
            name="get_function_snapshot",
            description="Retrieve a previously saved semantic snapshot of a function."
        )
        self.snapshot_store = snapshot_store
        self.resolver = resolver or on_missing

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        from ..common.utils import sanitize_func_name
        func_name = sanitize_func_name(arguments.get("func_name", ""))
        if not func_name:
            return {"success": False, "error": "Function name is empty"}

        file_path = arguments.get("file_path")
        if file_path is not None and not isinstance(file_path, str):
            return {"success": False, "error": "file_path must be a string"}

        if self.resolver:
            return self.resolver(func_name, file_path)

        snapshot = self.snapshot_store.load_snapshot(func_name, file_path=file_path)
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
                        "func_name": {"type": "string"},
                        "file_path": {"type": "string"}
                    },
                    "required": ["func_name"],
                },
            },
        }
