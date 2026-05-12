"""MCP resource/prompt/tool provider backed by Z-SCOPE internals."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config.config import ZScopeConfig
from ..core.snapshot_store import SnapshotStore
from ..core.tools_runtime import ToolsRuntime
from ..orchestration.entry_discovery import EntryDiscovery
from ..retrieval.code_index import CodeIndex


class ZScopeMcpProvider:
    """Expose CodeIndex, knowledge.db, and snapshot.db through MCP primitives."""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: Optional[CodeIndex] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        tools_runtime: Optional[ToolsRuntime] = None,
    ):
        self.config = config
        self.code_index = code_index or CodeIndex(
            config.project.project_root,
            config.project.compile_commands_path,
            source_root=config.project.source_root,
            indexing_config=config.indexing,
            include_paths=config.project.include_paths,
            exclude_paths=config.project.exclude_paths,
            wait_for_cpg=True,
        )
        self.snapshot_store = snapshot_store or SnapshotStore(Path(config.analysis.snapshot_dir))
        self.tools_runtime = tools_runtime or ToolsRuntime(self.code_index, self.snapshot_store)

    def list_resources(self) -> List[Dict[str, Any]]:
        return [
            {
                "uri": "zscope://config",
                "name": "Z-SCOPE Config",
                "description": "Effective project, analysis, and indexing configuration.",
                "mimeType": "application/json",
            },
            {
                "uri": "zscope://knowledge/stats",
                "name": "Knowledge DB Stats",
                "description": "Counts of indexed functions, calls, types, and SVF findings.",
                "mimeType": "application/json",
            },
            {
                "uri": "zscope://knowledge/functions",
                "name": "Indexed Functions",
                "description": "Function names currently known to CodeIndex.",
                "mimeType": "application/json",
            },
            {
                "uri": "zscope://snapshots/list",
                "name": "Snapshot List",
                "description": "Function semantic snapshots and final reports known to snapshot.db.",
                "mimeType": "application/json",
            },
        ]

    def read_resource(self, uri: str) -> Dict[str, Any]:
        if uri == "zscope://config":
            return self._resource(uri, self._config_dict())
        if uri == "zscope://knowledge/stats":
            return self._resource(uri, self._knowledge_stats())
        if uri == "zscope://knowledge/functions":
            return self._resource(uri, {"functions": self.code_index.list_functions(limit=100000)})
        if uri == "zscope://snapshots/list":
            return self._resource(uri, {"snapshots": self.snapshot_store.list_snapshots()})
        raise KeyError(f"Unknown resource: {uri}")

    def list_prompts(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "zscope.entry_discovery",
                "description": "Classify public API, communication, thread, and other input entry functions.",
                "arguments": [],
            },
            {
                "name": "zscope.resource_lifecycle_audit",
                "description": "Prompt for narrow acquire/release lifetime analysis.",
                "arguments": [{"name": "function", "required": True}],
            },
            {
                "name": "zscope.concurrency_audit",
                "description": "Prompt for lock order, race, and thread lifetime analysis.",
                "arguments": [{"name": "function", "required": True}],
            },
        ]

    def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        arguments = arguments or {}
        if name == "zscope.entry_discovery":
            text = (
                "Discover scan entries by combining header-declared public APIs, communication "
                "interfaces (send/recv/read/write/shared memory), thread creation, and other "
                "user-input sources. Return candidates with exposure reasons and focused audit prompts."
            )
        elif name == "zscope.resource_lifecycle_audit":
            func = arguments.get("function", "<function>")
            text = (
                f"Audit {func} for resource lifecycle issues. For each acquire site, trace normal "
                "and error paths, ownership transfer, duplicate release, UAF, and missing release."
            )
        elif name == "zscope.concurrency_audit":
            func = arguments.get("function", "<function>")
            text = (
                f"Audit {func} for data races, lock imbalance, lock-order cycles, missing unlocks "
                "on error paths, stack argument escape, and thread join/detach cleanup."
            )
        else:
            raise KeyError(f"Unknown prompt: {name}")
        return {"messages": [{"role": "user", "content": {"type": "text", "text": text}}]}

    def list_tools(self) -> List[Dict[str, Any]]:
        tools = list(self.tools_runtime.get_tools_schema())
        tools.extend(
            [
                {
                    "type": "function",
                    "function": {
                        "name": "query_knowledge",
                        "description": "Run a safe read-only SELECT query against code_knowledge.db.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "sql": {"type": "string"},
                                "params": {"type": "array", "items": {"type": "string"}},
                                "limit": {"type": "integer", "default": 100},
                            },
                            "required": ["sql"],
                        },
                    },
                },
                {
                    "type": "function",
                    "function": {
                        "name": "discover_entries",
                        "description": "Classify project exposure and return scan entry candidates.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "max_candidates": {"type": "integer", "default": 200},
                            },
                        },
                    },
                },
            ]
        )
        return tools

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        arguments = arguments or {}
        if name == "query_knowledge":
            return self._query_knowledge(
                arguments.get("sql", ""),
                arguments.get("params") or [],
                int(arguments.get("limit") or 100),
            )
        if name == "discover_entries":
            discovery = EntryDiscovery(self.code_index)
            return {"success": True, "data": discovery.discover(int(arguments.get("max_candidates") or 200)).to_dict()}
        return self.tools_runtime.execute_tool(name, arguments)

    def close(self) -> None:
        self.code_index.close()

    def _resource(self, uri: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(payload, ensure_ascii=False, indent=2),
                }
            ]
        }

    def _config_dict(self) -> Dict[str, Any]:
        return {
            "project": {
                "root": str(self.config.project.project_root),
                "source_root": str(self.config.project.source_root),
                "entry_function": self.config.project.entry_function,
                "entry_functions_list": str(self.config.project.entry_functions_list or ""),
                "prompt_autofill": self.config.project.prompt_autofill.__dict__,
                "include_paths": [str(p) for p in self.config.project.include_paths],
                "exclude_paths": [str(p) for p in self.config.project.exclude_paths],
            },
            "analysis": self.config.analysis.__dict__,
            "indexing": self.config.indexing.__dict__,
        }

    def _knowledge_stats(self) -> Dict[str, Any]:
        db_path = self._knowledge_db_path()
        if not db_path.exists():
            return {"available": False, "path": str(db_path)}
        counts: Dict[str, int] = {}
        with sqlite3.connect(str(db_path)) as conn:
            for table in (
                "functions",
                "type_definitions",
                "call_edges",
                "macro_definitions",
                "translation_units",
                "indirect_calls",
                "taint_signatures",
            ):
                try:
                    row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                    counts[table] = int(row[0]) if row else 0
                except sqlite3.Error:
                    counts[table] = -1
        return {"available": True, "path": str(db_path), "counts": counts}

    def _query_knowledge(self, sql: str, params: List[Any], limit: int = 100) -> Dict[str, Any]:
        stripped = sql.strip().rstrip(";")
        lowered = stripped.lower()
        if not (lowered.startswith("select ") or lowered.startswith("with ")):
            return {"success": False, "error": "Only read-only SELECT/CTE queries are allowed."}
        if any(token in lowered for token in (" insert ", " update ", " delete ", " drop ", " alter ", " attach ")):
            return {"success": False, "error": "Mutation statements are not allowed."}

        db_path = self._knowledge_db_path()
        if not db_path.exists():
            return {"success": False, "error": f"Knowledge DB not found: {db_path}"}

        limited_sql = stripped
        if " limit " not in lowered:
            limited_sql = f"{stripped} LIMIT {max(1, min(limit, 1000))}"

        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(limited_sql, params).fetchall()
            return {"success": True, "data": {"rows": [dict(row) for row in rows], "count": len(rows)}}

    def _knowledge_db_path(self) -> Path:
        configured = Path(self.config.indexing.knowledge_db_path)
        if configured.is_absolute():
            return configured
        return self.config.project.project_root / configured
