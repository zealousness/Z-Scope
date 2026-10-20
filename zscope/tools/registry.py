"""Construction helpers for the six evidence-oriented analysis tools."""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional, TYPE_CHECKING

from ..framework.base import BaseTool
from .code_graph_query import QueryCodeGraphTool
from .data_flow_trace import TraceDataFlowTool
from .read_code import ReadCodeTool
from .search_code import SearchCodeTool
from .semantic_context import SemanticContextTool
from .static_findings import QueryStaticFindingsTool
from .symbols import SymbolCatalog
from .source_access import ProjectSourceAccess

if TYPE_CHECKING:
    from ..config.user_config_store import UserConfigStore
    from ..retrieval.code_index import CodeIndex
    from ..snapshots.store import SnapshotStore


SnapshotResolver = Callable[[str, Optional[str]], Dict[str, Any]]


def build_tool_registry(
    code_index: "CodeIndex",
    snapshot_store: "SnapshotStore",
    user_config: Optional["UserConfigStore"] = None,
    *,
    snapshot_resolver: Optional[SnapshotResolver] = None,
    candidate_ledger: Any = None,
    include_advanced: bool = True,
    access_profile: str = "default",
) -> Dict[str, BaseTool]:
    """Build the atomic six-tool public registry for one analysis context.

    ``include_advanced`` remains accepted for Python caller compatibility. Backend
    differences are now expressed by result coverage, never by changing vocabulary.
    """
    del include_advanced
    if access_profile not in {"default", "read_only", "candidate_blind"}:
        raise ValueError("Unknown tool access profile")
    catalog = SymbolCatalog(code_index, user_config)
    source_access = ProjectSourceAccess.for_index(code_index)
    if access_profile != "default" and source_access is not None:
        catalog.permitted_source = source_access.allowed
    tools = [
        SearchCodeTool(catalog, source_access),
        ReadCodeTool(code_index, catalog, source_access),
        SemanticContextTool(
            snapshot_store,
            code_index,
            catalog,
            resolver=snapshot_resolver,
            cache_only=access_profile != "default",
            candidate_blind=access_profile == "candidate_blind",
        ),
        QueryCodeGraphTool(code_index, catalog),
        TraceDataFlowTool(code_index, catalog),
        QueryStaticFindingsTool(code_index, catalog, candidate_ledger),
    ]
    registry: Dict[str, BaseTool] = {}
    for tool in tools:
        if tool.name in registry:
            raise ValueError(f"Duplicate tool name: {tool.name}")
        registry[tool.name] = tool
    return registry
