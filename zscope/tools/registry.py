"""Construction helpers for the built-in analysis tools."""

from pathlib import Path
from typing import Dict, Optional, TYPE_CHECKING

from ..framework.base import BaseTool
from .call_graph import GetCallGraphTool
from .callers import GetCallersTool
from .code_retrieval import GetFunctionImplTool
from .data_flow import GetDataFlowTool
from .deep_call_context import GetDeepCallContextTool
from .file_snippet import GetFileSnippetTool
from .function_info import GetFunctionInfoTool
from .function_pointers import FindFunctionPointersTool
from .list_functions import ListFunctionsTool
from .pointer_alias import QueryPointerAliasTool
from .snapshot_tool import GetFunctionSnapshotTool
from .security_semantics import GetSecuritySemanticsTool
from .taint_reachability import VerifyTaintReachabilityTool
from .type_info import GetTypeInfoTool

if TYPE_CHECKING:
    from ..config.user_config_store import UserConfigStore
    from ..retrieval.code_index import CodeIndex
    from ..snapshots.store import SnapshotStore


def build_tool_registry(
    code_index: "CodeIndex",
    snapshot_store: "SnapshotStore",
    user_config: Optional["UserConfigStore"] = None,
    *,
    include_advanced: bool = True,
) -> Dict[str, BaseTool]:
    """Build the ordered registry of built-in tools for one analysis context."""
    tools = [
        GetFunctionImplTool(code_index, user_config),
        GetFunctionInfoTool(code_index, user_config),
        GetFunctionSnapshotTool(
            snapshot_store,
            code_index=code_index,
            user_config=user_config,
        ),
        GetSecuritySemanticsTool(
            Path(getattr(snapshot_store, "snapshot_dir", ".zscope_snapshots")) / "security_map.db"
        ),
        ListFunctionsTool(code_index),
        GetFileSnippetTool(code_index),
        GetCallersTool(code_index),
        GetTypeInfoTool(code_index),
    ]
    if include_advanced:
        tools.extend(
            [
                GetCallGraphTool(code_index),
                GetDataFlowTool(code_index),
                FindFunctionPointersTool(code_index),
                QueryPointerAliasTool(code_index),
                VerifyTaintReachabilityTool(code_index),
                GetDeepCallContextTool(code_index),
            ]
        )

    registry: Dict[str, BaseTool] = {}
    for tool in tools:
        if tool.name in registry:
            raise ValueError(f"Duplicate tool name: {tool.name}")
        registry[tool.name] = tool
    return registry
