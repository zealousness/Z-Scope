"""MCP resource/prompt/tool provider backed by Z-SCOPE internals."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from ..config.config import ZScopeConfig
from ..snapshots.store import SnapshotStore
from ..tools.policy import ToolPolicy, deny_sensitive_paths_hook
from ..tools.runtime import ToolsRuntime
from ..orchestration.entry_discovery import EntryDiscovery
from ..retrieval.code_index import CodeIndex


MCP_TOOL_ALIASES: Dict[str, str] = {
    "zscope.code.get_function_impl": "get_function_impl",
    "zscope.code.get_function_snapshot": "get_function_snapshot",
    "zscope.code.list_known_functions": "list_known_functions",
    "zscope.code.get_file_snippet": "get_file_snippet",
    "zscope.code.get_callers": "get_callers",
    "zscope.code.get_type_info": "get_type_info",
    "zscope.graph.get_call_graph": "get_call_graph",
    "zscope.graph.get_data_flow": "get_data_flow",
    "zscope.graph.find_function_pointers": "find_function_pointers",
    "zscope.graph.query_pointer_alias": "query_pointer_alias",
    "zscope.graph.verify_taint_reachability": "verify_taint_reachability",
    "zscope.graph.get_deep_call_context": "get_deep_call_context",
    "zscope.knowledge.query": "query_knowledge",
    "zscope.entries.discover": "discover_entries",
}

MCP_RAW_TOOL_ALIASES: Dict[str, str] = {
    raw_name: namespaced_name for namespaced_name, raw_name in MCP_TOOL_ALIASES.items()
}


class ZScopeMcpProvider:
    """Expose CodeIndex, knowledge.db, and snapshot.db through MCP primitives."""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: Optional[CodeIndex] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        tools_runtime: Optional[ToolsRuntime] = None,
        tool_policy: Optional[ToolPolicy] = None,
        max_result_chars: int = 100000,
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
            svf_parallel_workers=config.analysis.parallel_workers,
        )
        self.snapshot_store = snapshot_store or SnapshotStore(Path(config.analysis.snapshot_dir))
        resolved_policy = tool_policy or ToolPolicy.allow_all(
            pre_hooks=[deny_sensitive_paths_hook],
            audit_log_path=self._tool_audit_log_path(config),
        )
        self.tools_runtime = tools_runtime or ToolsRuntime(
            self.code_index,
            self.snapshot_store,
            tool_policy=resolved_policy,
        )
        self.tool_policy = resolved_policy if tool_policy else self.tools_runtime.tool_policy
        self.max_result_chars = max(1000, int(max_result_chars or 100000))

    def list_resources(self) -> List[Dict[str, Any]]:
        resources = [
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
        return self.tool_policy.filter_resources(resources)

    def read_resource(self, uri: str) -> Dict[str, Any]:
        base_uri, query = self._parse_resource_uri(uri)
        policy_error = self.tool_policy.enforce_resource(base_uri, actor="mcp")
        if policy_error:
            raise PermissionError(policy_error["error"])
        if base_uri == "zscope://config":
            return self._resource(uri, self._config_dict())
        if base_uri == "zscope://knowledge/stats":
            return self._resource(uri, self._knowledge_stats())
        if base_uri == "zscope://knowledge/functions":
            limit = self._query_int(query, "limit", default=1000, min_value=1, max_value=10000)
            offset = self._query_int(query, "offset", default=0, min_value=0, max_value=100000)
            functions = self.code_index.list_functions(limit=offset + limit + 1)
            page = functions[offset: offset + limit]
            return self._resource(
                uri,
                {
                    "functions": page,
                    "pagination": {
                        "offset": offset,
                        "limit": limit,
                        "returned": len(page),
                        "has_more": len(functions) > offset + limit,
                    },
                },
            )
        if base_uri == "zscope://snapshots/list":
            limit = self._query_int(query, "limit", default=1000, min_value=1, max_value=10000)
            offset = self._query_int(query, "offset", default=0, min_value=0, max_value=100000)
            snapshots = self.snapshot_store.list_snapshots()
            page = snapshots[offset: offset + limit]
            return self._resource(
                uri,
                {
                    "snapshots": page,
                    "pagination": {
                        "offset": offset,
                        "limit": limit,
                        "returned": len(page),
                        "has_more": len(snapshots) > offset + limit,
                    },
                },
            )
        raise KeyError(f"Unknown resource: {uri}")

    def list_prompts(self) -> List[Dict[str, Any]]:
        prompts = [
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
        return self.tool_policy.filter_prompts(prompts)

    def get_prompt(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        arguments = arguments or {}
        policy_error = self.tool_policy.enforce_prompt(name, arguments, actor="mcp")
        if policy_error:
            raise PermissionError(policy_error["error"])
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
        tools = list(self.tools_runtime.get_tools_schema(apply_policy=False))
        tools.extend(
            [
                {
                    "type": "function",
                    "function": {
                        "name": "query_knowledge",
                        "description": "Run a safe read-only SELECT query against code_knowledge.db.",
                        "_meta": {"anthropic/maxResultSizeChars": self.max_result_chars},
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
        return self.tool_policy.filter_tool_schemas(self._with_namespaced_aliases(tools))

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        arguments = arguments or {}
        requested_name = name
        runtime_name = MCP_TOOL_ALIASES.get(requested_name, requested_name)
        policy_error = self.tool_policy.enforce_tool(
            requested_name,
            arguments,
            schema=self._tool_schema_by_name().get(requested_name),
            actor="mcp",
        )
        if policy_error:
            return policy_error
        start = time.perf_counter()
        if runtime_name == "query_knowledge":
            result = self._bounded_tool_result(
                requested_name,
                self._query_knowledge(
                    arguments.get("sql", ""),
                    arguments.get("params") or [],
                    int(arguments.get("limit") or 100),
                ),
            )
            return self._post_tool_result(requested_name, arguments, result, start)
        if runtime_name == "discover_entries":
            discovery = EntryDiscovery(self.code_index)
            result = self._bounded_tool_result(
                requested_name,
                {"success": True, "data": discovery.discover(int(arguments.get("max_candidates") or 200)).to_dict()},
            )
            return self._post_tool_result(requested_name, arguments, result, start)
        result = self._bounded_tool_result(
            requested_name,
            self.tools_runtime.execute_tool(
                runtime_name,
                arguments,
                actor="mcp",
                enforce_policy=False,
            ),
        )
        return self._post_tool_result(requested_name, arguments, result, start)

    def close(self) -> None:
        self.code_index.close()

    def _resource(self, uri: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        text = self._bounded_json_text(payload)
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": text,
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
        safety_error = self._validate_readonly_sql(sql)
        if safety_error:
            return {"success": False, "error": safety_error}
        if not isinstance(params, list):
            return {"success": False, "error": "SQL params must be a list."}

        stripped = sql.strip().rstrip(";")
        lowered = stripped.lower()

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

    def _tool_schema_by_name(self) -> Dict[str, Dict[str, Any]]:
        return {
            self.tool_policy.schema_name(schema): schema
            for schema in self.list_tools()
        }

    @staticmethod
    def _with_namespaced_aliases(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        visible_tools: List[Dict[str, Any]] = []
        for schema in tools:
            visible_tools.append(schema)
            raw_name = ToolPolicy.schema_name(schema)
            alias_name = MCP_RAW_TOOL_ALIASES.get(raw_name)
            if alias_name:
                visible_tools.append(ZScopeMcpProvider._alias_tool_schema(schema, alias_name, raw_name))
        return visible_tools

    @staticmethod
    def _alias_tool_schema(
        schema: Dict[str, Any],
        alias_name: str,
        raw_name: str,
    ) -> Dict[str, Any]:
        alias_schema = dict(schema)
        function = dict(alias_schema.get("function") or {})
        function["name"] = alias_name
        meta = dict(function.get("_meta") or {})
        meta["zscope/rawToolName"] = raw_name
        function["_meta"] = meta
        alias_schema["function"] = function
        return alias_schema

    @staticmethod
    def _tool_audit_log_path(config: ZScopeConfig) -> Optional[Path]:
        configured = str(getattr(config.analysis, "tool_audit_log", "") or "").strip()
        if not configured:
            return None
        path = Path(configured)
        if path.is_absolute():
            return path
        return config.project.project_root / path

    @staticmethod
    def _validate_readonly_sql(sql: str) -> str:
        if not isinstance(sql, str) or not sql.strip():
            return "SQL must be a non-empty string."
        stripped = sql.strip()
        if ";" in stripped.rstrip(";"):
            return "Multiple SQL statements are not allowed."
        if "--" in stripped or "/*" in stripped or "*/" in stripped:
            return "SQL comments are not allowed."
        normalized = stripped.rstrip(";").strip().lower()
        if not (normalized.startswith("select ") or normalized.startswith("with ")):
            return "Only read-only SELECT/CTE queries are allowed."
        dangerous = (
            "alter",
            "analyze",
            "attach",
            "create",
            "delete",
            "detach",
            "drop",
            "insert",
            "load_extension",
            "pragma",
            "reindex",
            "replace",
            "truncate",
            "update",
            "vacuum",
        )
        for token in dangerous:
            if re.search(rf"\b{re.escape(token)}\b", normalized):
                return f"SQL token '{token}' is not allowed."
        return ""

    @staticmethod
    def _parse_resource_uri(uri: str) -> tuple[str, Dict[str, List[str]]]:
        parsed = urlsplit(uri)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return base, parse_qs(parsed.query)

    @staticmethod
    def _query_int(
        query: Dict[str, List[str]],
        key: str,
        *,
        default: int,
        min_value: int,
        max_value: int,
    ) -> int:
        raw = query.get(key, [str(default)])[0]
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = default
        return max(min_value, min(max_value, value))

    def _bounded_json_text(self, payload: Dict[str, Any]) -> str:
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if len(text) <= self.max_result_chars:
            return text
        preview_budget = max(0, self.max_result_chars - 800)
        bounded_payload = {
            "truncated": True,
            "max_result_chars": self.max_result_chars,
            "original_chars": len(text),
            "message": "MCP result exceeded the configured hard limit; request a smaller page.",
            "preview": text[:preview_budget],
        }
        return json.dumps(bounded_payload, ensure_ascii=False, indent=2)

    def _bounded_tool_result(self, name: str, result: Dict[str, Any]) -> Dict[str, Any]:
        text = json.dumps(result, ensure_ascii=False)
        if len(text) <= self.max_result_chars:
            return result
        return {
            "success": bool(result.get("success", True)),
            "data": {
                "truncated": True,
                "tool": name,
                "max_result_chars": self.max_result_chars,
                "original_chars": len(text),
                "message": "MCP tool result exceeded the configured hard limit; request a smaller page or limit.",
            },
        }

    def _post_tool_result(
        self,
        name: str,
        arguments: Dict[str, Any],
        result: Dict[str, Any],
        start: float,
    ) -> Dict[str, Any]:
        self.tool_policy.run_post_hooks(
            "tool",
            name,
            arguments,
            result=result,
            actor="mcp",
            duration_ms=(time.perf_counter() - start) * 1000,
        )
        return result
