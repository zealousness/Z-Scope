from typing import Callable, Dict, Any, Optional
from ..framework.base import BaseTool
from ..snapshots.modeling_input import (
    SemanticModelInputError,
    build_semantic_model_input,
    hydrate_project_callee_summaries,
)
from ..snapshots.store import SnapshotStore
from .function_info import GetFunctionInfoTool


class GetFunctionSnapshotTool(BaseTool):
    """Tool to retrieve function semantic snapshot."""

    def __init__(
        self,
        snapshot_store: SnapshotStore,
        code_index: Any = None,
        resolver: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None,
        on_missing: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None,
        user_config: Any = None,
    ):
        super().__init__(
            name="get_function_snapshot",
            description=(
                "Retrieve a current semantic snapshot of a function. When on-demand building "
                "is disabled and the snapshot is missing or stale, data is null and the result "
                "includes current function_info. "
            ),
        )
        self.snapshot_store = snapshot_store
        self.code_index = code_index
        self.resolver = resolver or on_missing
        self.function_info_tool = (
            GetFunctionInfoTool(code_index, user_config) if code_index is not None else None
        )

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        # Exact signatures and index names disambiguate overloads before lookup.
        func_name = str(arguments.get("func_name") or "").strip()
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
            context = hydrate_project_callee_summaries(
                context,
                self.code_index,
                self.snapshot_store,
            )
        except SemanticModelInputError as exc:
            return {"success": False, "error": str(exc), "reason": exc.reason}
        index_name = str(context["index_name"])
        snapshot = self.snapshot_store.load_snapshot(index_name)
        if snapshot is None:
            function_info = self._function_info_fallback(arguments)
            return {
                "success": True,
                "data": None,
                "snapshot_status": "missing",
                "message": ("No snapshot exists; canonical function info is provided as fallback."),
                "function_info": function_info,
            }
        needs_refresh, reason = self.snapshot_store.needs_refresh(
            index_name,
            str(context["code"]),
            context,
        )
        if needs_refresh:
            function_info = self._function_info_fallback(arguments)
            return {
                "success": True,
                "data": None,
                "snapshot_status": "stale",
                "message": "Saved snapshot is stale and must be rebuilt.",
                "function_info": function_info,
            }
        return {"success": True, "data": snapshot}

    def _function_info_fallback(
        self,
        snapshot_arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return the complete public function-info response for this query."""
        if self.function_info_tool is None:
            return {
                "success": False,
                "error": "Function-info fallback requires a code index",
            }

        arguments = {"func_name": snapshot_arguments.get("func_name", "")}
        if "file_path" in snapshot_arguments:
            arguments["file_path"] = snapshot_arguments["file_path"]
        return self.function_info_tool.execute(arguments)

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
                        "file_path": {"type": "string"},
                    },
                    "required": ["func_name"],
                },
            },
        }
