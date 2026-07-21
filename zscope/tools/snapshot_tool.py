from copy import deepcopy
from typing import Callable, Dict, Any, Optional
from ..framework.base import BaseTool
from ..snapshots.modeling_input import SemanticModelInputError, build_semantic_model_input
from ..snapshots.store import SnapshotStore

class GetFunctionSnapshotTool(BaseTool):
    """Tool to retrieve function semantic snapshot."""
    
    def __init__(
        self,
        snapshot_store: SnapshotStore,
        code_index: Any = None,
        resolver: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None,
        on_missing: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None,
    ):
        super().__init__(
            name="get_function_snapshot",
            description=(
                "Retrieve a current semantic snapshot of a function. When on-demand building "
                "is disabled and the snapshot is missing or stale, data is null and the result "
                "includes current function_info. "
            )
        )
        self.snapshot_store = snapshot_store
        self.code_index = code_index
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

        if self.code_index is None:
            return {
                "success": False,
                "error": "Snapshot lookup requires a code index or resolver",
            }
        try:
            context = build_semantic_model_input(
                self.code_index,
                func_name,
                file_path=file_path or "",
                include_context=False,
            )
        except SemanticModelInputError as exc:
            return {"success": False, "error": str(exc), "reason": exc.reason}
        index_name = str(context["index_name"])
        function_info = self._function_info_fallback(context)
        snapshot = self.snapshot_store.load_snapshot(index_name)
        if snapshot is None:
            return {
                "success": True,
                "data": None,
                "snapshot_status": "missing",
                "reason": "no_snapshot",
                "message": (
                    "No snapshot exists; canonical function info is provided as fallback"
                ),
                "function_info": function_info,
            }
        needs_refresh, reason = self.snapshot_store.needs_refresh(
            index_name,
            str(context["code"]),
            context,
        )
        if needs_refresh:
            return {
                "success": True,
                "data": None,
                "snapshot_status": "stale",
                "message": "Saved snapshot is stale and must be rebuilt",
                "reason": reason,
                "function_info": function_info,
            }
        return {"success": True, "data": snapshot}

    @staticmethod
    def _function_info_fallback(context: Dict[str, Any]) -> Dict[str, Any]:
        info = {
            "function_name": str(context.get("func_name") or ""),
            "index_name": str(context.get("index_name") or ""),
            "file_path": str(context.get("file_path") or ""),
            "start_line": int(context.get("start_line") or 0),
            "end_line": int(context.get("end_line") or 0),
            "signature": str(context.get("signature") or ""),
            "is_static": bool(context.get("is_static")),
            "is_macro": bool(context.get("is_macro")),
            "callees": deepcopy(list(context.get("callees") or [])),
            "referenced_globals": deepcopy(
                list(context.get("referenced_globals") or [])
            ),
            "referenced_macros": deepcopy(
                list(context.get("referenced_macros") or [])
            ),
        }
        for field in (
            "callees_truncation",
            "referenced_globals_truncation",
            "referenced_macros_truncation",
        ):
            if field in context:
                info[field] = deepcopy(context[field])
        return info

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
