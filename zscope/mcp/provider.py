"""MCP resource/prompt/tool provider backed by Z-SCOPE internals."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, cast
from urllib.parse import parse_qs, urlsplit

from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..framework.llm_usage import scan_token_usage_snapshot
from ..snapshots.store import SnapshotStore
from ..snapshots.readonly import ReadonlySnapshotStore
from ..retrieval.cached_index import CachedCodeIndex
from ..tools.policy import ToolPolicy, deny_sensitive_paths_hook
from ..tools.runtime import ToolsRuntime
from ..tools.contracts import tool_result
from ..orchestration.entry_discovery import EntryDiscovery
from ..orchestration.rollout import rollout_runtime_policy
from ..retrieval.code_index import CodeIndex
from ..rules.catalog import serialize_effective_rules
from ..rules.extensions import preflight_rules
from ..wiki.control import wiki_query, wiki_status
from .jobs_adapter import McpJobsAdapter

MCP_TOOL_NAMES: Dict[str, str] = {
    "zscope.config.prepare": "prepare_saved_config",
    "zscope.code.search": "search_code",
    "zscope.code.read": "read_code",
    "zscope.semantic.context": "get_semantic_context",
    "zscope.graph.query": "query_code_graph",
    "zscope.flow.trace": "trace_data_flow",
    "zscope.findings.query": "query_static_findings",
    "zscope.knowledge.query": "query_knowledge",
    "zscope.entries.discover": "discover_entries",
    "zscope.scan.run": "run_scan",
    "zscope.scan.status": "scan_status",
    "zscope.jobs.list": "jobs_list",
    "zscope.jobs.events": "jobs_events",
    "zscope.jobs.result": "jobs_result",
    "zscope.jobs.cancel": "jobs_cancel",
    "zscope.jobs.resume": "jobs_resume",
    "zscope.wiki.status": "wiki_status",
    "zscope.wiki.query": "wiki_query",
}

# MCP job tools dispatch onto the shared persistent service through the
# adapter; the runtime names exist only as dispatch keys (the tools runtime
# itself has no job tools).
JOBS_TOOL_METHODS: Dict[str, str] = {
    "run_scan": "start",
    "scan_status": "status",
    "jobs_list": "list",
    "jobs_events": "events",
    "jobs_result": "result",
    "jobs_cancel": "cancel",
    "jobs_resume": "resume",
}

MCP_PROFILES = ("default", "read_only", "candidate_blind")
_READ_TOOLS = frozenset(
    {
        "zscope.code.search",
        "zscope.code.read",
        "zscope.semantic.context",
        "zscope.graph.query",
        "zscope.flow.trace",
        "zscope.findings.query",
    }
)


class ZScopeMcpProvider:
    """Expose CodeIndex, knowledge.db, and snapshot.db through MCP primitives."""

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: Optional[CodeIndex] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        tools_runtime: Optional[ToolsRuntime] = None,
        tool_policy: Optional[ToolPolicy] = None,
        max_result_chars: int = 60000,
        config_path: Optional[Path] = None,
        jobs_adapter: Optional[McpJobsAdapter] = None,
        profile: str = "default",
    ):
        if profile not in MCP_PROFILES:
            raise ValueError("Unknown MCP profile")
        self.profile = profile
        self._owns_code_index = code_index is None
        if profile != "default":
            if any(
                item is not None
                for item in (code_index, snapshot_store, tools_runtime, jobs_adapter)
            ):
                raise ValueError(
                    "Read-only MCP profiles require their controlled cached-state factory"
                )
            code_index = cast(CodeIndex, CachedCodeIndex(config))
            snapshot_store = cast(
                SnapshotStore, ReadonlySnapshotStore(Path(config.analysis.snapshot_dir))
            )
        else:
            preflight_rules(config)
        self.config = config
        self.config_path = (
            Path(config_path).expanduser().resolve() if config_path is not None else None
        )
        self.code_index = code_index or CodeIndex(
            config.project.project_root,
            config.project.compile_commands_path,
            source_root=config.project.source_root,
            indexing_config=config.indexing,
            include_paths=config.project.include_paths,
            exclude_paths=config.project.exclude_paths,
            wait_for_cpg=True,
            svf_parallel_workers=(
                config.concurrency.svf_workers or config.concurrency.index_workers
            ),
        )
        self.snapshot_store = snapshot_store or SnapshotStore.from_config(config)
        resolved_policy = tool_policy or ToolPolicy.allow_all(
            pre_hooks=[deny_sensitive_paths_hook],
            audit_log_path=self._tool_audit_log_path(config),
        )
        if tools_runtime is None:
            user_config = None
            configured_user_file = getattr(config.project, "user_config_file", None)
            if (
                profile == "default"
                and configured_user_file
                and Path(configured_user_file).exists()
            ):
                user_config = UserConfigStore(Path(configured_user_file))
            self.tools_runtime = ToolsRuntime(
                self.code_index,
                self.snapshot_store,
                user_config=user_config,
                tool_policy=resolved_policy,
                access_profile=profile,
            )
        else:
            self.tools_runtime = tools_runtime
        self.tool_policy = resolved_policy if tool_policy else self.tools_runtime.tool_policy
        self.max_result_chars = max(1000, int(max_result_chars or 60000))
        self.protocol_version = "2025-06-18"
        # Job control goes through the same persistent ScanJobService the Web
        # jobs API uses; the adapter is lazy, so constructing a provider (any
        # profile) starts no backend, thread, or store.
        self.jobs_adapter = jobs_adapter
        if profile == "default" and self.jobs_adapter is None and config_path is not None:
            self.jobs_adapter = McpJobsAdapter(self.config_path)

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
            {
                "uri": "zscope://reports/latest",
                "name": "Latest Z-SCOPE Report",
                "description": "Latest completed report including effective scan and token telemetry.",
                "mimeType": "application/json",
            },
            {
                "uri": "zscope://rules/effective",
                "name": "Effective Rules",
                "description": "Effective rule activation, provenance, and qualification state.",
                "mimeType": "application/json",
            },
        ]
        if self.config_path is not None:
            resources.append(
                {
                    "uri": "zscope://config/preparation",
                    "name": "Saved Configuration Preparation",
                    "description": (
                        "Read-only saved-config readiness, declared field wiring, "
                        "and start capability; does not run a scan or select a target."
                    ),
                    "mimeType": "application/json",
                }
            )
        if self.profile == "candidate_blind":
            resources = []
        elif self.profile == "read_only":
            resources = [
                r
                for r in resources
                if r["uri"]
                in {
                    "zscope://config",
                    "zscope://config/preparation",
                    "zscope://reports/latest",
                }
            ]
        return self.tool_policy.filter_resources(resources)

    def read_resource(self, uri: str) -> Dict[str, Any]:
        base_uri, query = self._parse_resource_uri(uri)
        if self.profile != "default" and base_uri not in {r["uri"] for r in self.list_resources()}:
            raise PermissionError("Resource unavailable in this MCP profile")
        policy_error = self.tool_policy.enforce_resource(base_uri, actor="mcp")
        if policy_error:
            raise PermissionError(policy_error["error"])
        if base_uri == "zscope://config":
            return self._resource(uri, self._config_dict())
        if base_uri == "zscope://config/preparation":
            if uri != "zscope://config/preparation":
                raise ValueError("Saved configuration preparation accepts no URI parameters.")
            return self._resource(uri, self._saved_config_preparation())
        if base_uri == "zscope://knowledge/stats":
            return self._resource(uri, self._knowledge_stats())
        if base_uri == "zscope://knowledge/functions":
            limit = self._query_int(query, "limit", default=1000, min_value=1, max_value=10000)
            offset = self._query_int(query, "offset", default=0, min_value=0, max_value=100000)
            functions = self.code_index.list_functions(limit=offset + limit + 1)
            page = functions[offset : offset + limit]
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
            page = snapshots[offset : offset + limit]
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
        if base_uri == "zscope://reports/latest":
            return self._resource(uri, self._latest_report())
        if base_uri == "zscope://rules/effective":
            return self._resource(uri, serialize_effective_rules(self.config.effective_rules))
        raise KeyError(f"Unknown resource: {uri}")

    def list_prompts(self) -> List[Dict[str, Any]]:
        if self.profile != "default":
            return []
        prompts: List[Dict[str, Any]] = [
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
        if self.profile != "default":
            raise PermissionError("Prompt unavailable in this MCP profile")
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

    def list_tools(self, protocol_version: Optional[str] = None) -> List[Dict[str, Any]]:
        protocol = protocol_version or self.protocol_version
        include_output = protocol != "2024-11-05"
        tools: List[Dict[str, Any]] = []
        for public_name, runtime_name in MCP_TOOL_NAMES.items():
            tool = self.tools_runtime._tools_by_name.get(runtime_name)
            if tool is None:
                continue
            contract_getter = getattr(tool, "get_contract", None)
            if callable(contract_getter):
                schema = contract_getter().mcp_schema(public_name, include_output=include_output)
                schema["_meta"] = {"anthropic/maxResultSizeChars": self.max_result_chars}
                tools.append(schema)

        if self.profile == "default":
            tools.extend(self._management_tool_schemas(include_output=include_output))
        else:
            tools = [t for t in tools if self._profile_allows_tool(t["name"])]
        if self.config_path is not None and self._profile_allows_tool("zscope.config.prepare"):
            preparation_schema: Dict[str, Any] = {
                "name": "zscope.config.prepare",
                "description": (
                    "Inspect the server's saved configuration using the same read-only "
                    "preparation as CLI/Web; disclose field wiring and whether it can start. "
                    "Does not execute, index, run a model, or choose a build target."
                ),
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
                "annotations": {
                    "readOnlyHint": True,
                    "idempotentHint": True,
                    "destructiveHint": False,
                    "openWorldHint": False,
                },
                "_meta": {"anthropic/maxResultSizeChars": self.max_result_chars},
            }
            if include_output:
                preparation_schema["outputSchema"] = {"type": "object"}
            tools.append(preparation_schema)
        return self.tool_policy.filter_tool_schemas(tools)

    def _profile_allows_tool(self, name: str) -> bool:
        if name == "zscope.config.prepare":
            return self.profile in {"default", "read_only"}
        return self.profile == "default" or (
            name in _READ_TOOLS
            and not (self.profile == "candidate_blind" and name == "zscope.findings.query")
        )

    def _management_tool_schemas(self, *, include_output: bool) -> List[Dict[str, Any]]:
        readonly = {
            "readOnlyHint": True,
            "idempotentHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        }
        mutating = {
            "readOnlyHint": False,
            "idempotentHint": False,
            "destructiveHint": False,
            "openWorldHint": True,
        }
        specs = [
            (
                "zscope.knowledge.query",
                "Run a safe read-only SELECT query against code_knowledge.db with limit/offset pagination.",
                {
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "minLength": 1},
                        "params": {"type": "array", "items": {}},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
                        "offset": {"type": "integer", "minimum": 0},
                    },
                    "required": ["sql"],
                    "additionalProperties": False,
                },
                readonly,
            ),
            (
                "zscope.entries.discover",
                "Classify project exposure and return scan entry candidates.",
                {
                    "type": "object",
                    "properties": {
                        "max_candidates": {"type": "integer", "minimum": 1, "maximum": 1000}
                    },
                    "additionalProperties": False,
                },
                readonly,
            ),
            (
                "zscope.scan.run",
                "Start one persistent scan job on the saved config; returns the durable job, run, revision, and input binding. Duplicate request_id replays the same job.",
                {
                    "type": "object",
                    "properties": {
                        "request_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 128,
                            "description": "Caller-chosen idempotency key for this exact request",
                        },
                        "scan_depth": {
                            "type": "string",
                            "enum": ["fast", "balanced", "deep"],
                            "description": "Optional depth override; omit to use the saved config",
                        },
                        "stop_at": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "description": "ISO8601 absolute time with timezone; one window for this attempt only",
                        },
                    },
                    "required": ["request_id"],
                    "additionalProperties": False,
                },
                mutating,
            ),
            (
                "zscope.scan.status",
                "Read one persistent job's status, revision, input binding, owner state, and capabilities by job_id.",
                {
                    "type": "object",
                    "properties": {"job_id": {"type": "string", "minLength": 1, "maxLength": 128}},
                    "required": ["job_id"],
                    "additionalProperties": False,
                },
                readonly,
            ),
            (
                "zscope.jobs.list",
                "List this project's persistent scan jobs and whether a new one can start.",
                {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                readonly,
            ),
            (
                "zscope.jobs.events",
                "Page the persistent event log of one job after a cursor (after_seq).",
                {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "after_seq": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Cursor from a previous page; 0 starts at the beginning",
                        },
                    },
                    "required": ["job_id"],
                    "additionalProperties": False,
                },
                readonly,
            ),
            (
                "zscope.jobs.result",
                "Read the current attempt's verified report binding with the "
                "lightweight findings/acceptance projection; findings come only "
                "from the bound snapshot, whose review scope is shared with the "
                "current report only when the content still matches.",
                {
                    "type": "object",
                    "properties": {"job_id": {"type": "string", "minLength": 1, "maxLength": 128}},
                    "required": ["job_id"],
                    "additionalProperties": False,
                },
                readonly,
            ),
            (
                "zscope.jobs.cancel",
                "Request cancellation of one job; the detached owner stops its own process group.",
                {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "base_revision": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Revision of the job this request was made against",
                        },
                        "request_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    },
                    "required": ["job_id", "base_revision", "request_id"],
                    "additionalProperties": False,
                },
                mutating,
            ),
            (
                "zscope.jobs.resume",
                "Arm a new attempt of a resumable job with a fresh input verification; the old window is not carried over.",
                {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "base_revision": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Revision of the job this request was made against",
                        },
                        "request_id": {"type": "string", "minLength": 1, "maxLength": 128},
                    },
                    "required": ["job_id", "base_revision", "request_id"],
                    "additionalProperties": False,
                },
                mutating,
            ),
            (
                "zscope.wiki.status",
                "Read the active project Wiki revision status.",
                {"type": "object", "properties": {}, "additionalProperties": False},
                readonly,
            ),
            (
                "zscope.wiki.query",
                "Query bounded project Wiki or direct Markdown context for candidate subjects.",
                {
                    "type": "object",
                    "properties": {
                        "subjects": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 32,
                            "items": {"type": "string", "minLength": 1, "maxLength": 300},
                        },
                        "fact_kind": {"type": "string", "maxLength": 80},
                        "candidate_file": {"type": "string", "maxLength": 500},
                        "max_tokens": {"type": "integer", "minimum": 256},
                    },
                    "required": ["subjects"],
                    "additionalProperties": False,
                },
                readonly,
            ),
        ]
        result = []
        for name, description, input_schema, annotations in specs:
            item: Dict[str, Any] = {
                "name": name,
                "description": description,
                "inputSchema": input_schema,
                "annotations": dict(annotations),
                "_meta": {"anthropic/maxResultSizeChars": self.max_result_chars},
            }
            if include_output:
                item["outputSchema"] = {"type": "object"}
            result.append(item)
        return result

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self._profile_allows_tool(name):
            return tool_result(
                status="forbidden",
                data=None,
                error={
                    "code": "profile_denied",
                    "path": None,
                    "message": "Tool unavailable in this MCP profile.",
                    "retryable": False,
                },
            )
        requested_name = name
        runtime_name = MCP_TOOL_NAMES.get(requested_name)
        if arguments is None:
            arguments = {}
        elif not isinstance(arguments, dict):
            if runtime_name in self.tools_runtime._tools_by_name:
                return tool_result(
                    status="invalid_request",
                    data=None,
                    coverage_level="unsupported",
                    error={
                        "code": "invalid_arguments",
                        "path": "$",
                        "message": "Tool arguments must be a JSON object",
                        "retryable": True,
                    },
                )
            return {
                "success": False,
                "error": "Tool arguments must be a JSON object",
            }
        runtime_tool = self.tools_runtime._tools_by_name.get(runtime_name or "")
        if runtime_tool is not None:
            validation_error = runtime_tool.validate_arguments(arguments)
            if validation_error:
                self.tool_policy.enforce_tool(
                    requested_name,
                    arguments,
                    schema=self._tool_schema_by_name().get(requested_name),
                    actor="mcp",
                )
                return validation_error
        policy_error = self.tool_policy.enforce_tool(
            requested_name,
            arguments,
            schema=self._tool_schema_by_name().get(requested_name),
            actor="mcp",
        )
        if policy_error:
            if runtime_name in self.tools_runtime._tools_by_name:
                return tool_result(
                    status="forbidden",
                    data=None,
                    coverage_level="unsupported",
                    error={
                        "code": "policy_denied",
                        "path": None,
                        "message": str(policy_error.get("error") or "Tool use blocked by policy"),
                        "retryable": False,
                    },
                )
            return policy_error
        if runtime_name is None:
            return {"success": False, "error": f"Unknown MCP tool: {requested_name}"}
        start = time.perf_counter()
        if runtime_name == "prepare_saved_config":
            if arguments:
                result = {
                    "success": False,
                    "code": "invalid_arguments",
                    "error": "Saved configuration preparation accepts no arguments.",
                }
            else:
                try:
                    result = {"success": True, "data": self._saved_config_preparation()}
                except ValueError:
                    result = {
                        "success": False,
                        "code": "preparation_unavailable",
                        "error": "Saved configuration preparation is unavailable.",
                    }
            result = self._bounded_tool_result(requested_name, result)
            return self._post_tool_result(requested_name, arguments, result, start)
        if runtime_name == "query_knowledge":
            result = self._bounded_tool_result(
                requested_name,
                self._query_knowledge(
                    arguments.get("sql", ""),
                    arguments.get("params") or [],
                    int(arguments.get("limit") or 100),
                    int(arguments.get("offset") or 0),
                ),
            )
            return self._post_tool_result(requested_name, arguments, result, start)
        if runtime_name == "discover_entries":
            discovery = EntryDiscovery(self.code_index)
            result = self._bounded_tool_result(
                requested_name,
                {
                    "success": True,
                    "data": discovery.discover(
                        int(arguments.get("max_candidates") or 200)
                    ).to_dict(),
                },
            )
            return self._post_tool_result(requested_name, arguments, result, start)
        if runtime_name in JOBS_TOOL_METHODS:
            result = self._bounded_tool_result(
                requested_name, self._call_jobs_tool(runtime_name, arguments)
            )
            return self._post_tool_result(requested_name, arguments, result, start)
        if runtime_name in {"wiki_status", "wiki_query"}:
            wiki = self.config.project.wiki
            root = self.config.project.project_root
            try:
                if runtime_name == "wiki_status":
                    data = wiki_status(root, state_dir=wiki.state_dir)
                else:
                    subjects = arguments.get("subjects")
                    if not isinstance(subjects, list) or not subjects:
                        raise ValueError("subjects must be a non-empty array")
                    if len(subjects) > 32 or any(
                        not isinstance(item, str)
                        or not item.strip()
                        or len(item) > 300
                        or re.search(r"[\x00-\x1f\x7f]", item)
                        for item in subjects
                    ):
                        raise ValueError(
                            "subjects must contain 1-32 non-empty strings up to 300 characters"
                        )
                    fact_kind = str(arguments.get("fact_kind") or "unknown").strip()
                    if len(fact_kind) > 80 or re.search(r"[\x00-\x1f\x7f]", fact_kind):
                        raise ValueError("fact_kind must be at most 80 characters")
                    candidate_file = (
                        str(arguments.get("candidate_file") or "").replace("\\", "/").strip()
                    )
                    if (
                        len(candidate_file) > 500
                        or candidate_file.startswith("/")
                        or re.match(r"^[A-Za-z]:/", candidate_file)
                        or ".." in Path(candidate_file).parts
                        or re.search(r"[\x00-\x1f\x7f]", candidate_file)
                    ):
                        raise ValueError("candidate_file must be project-root relative")
                    raw_max_tokens = arguments.get("max_tokens")
                    max_tokens = None if raw_max_tokens is None else int(raw_max_tokens)
                    if max_tokens is not None and max_tokens < 256:
                        raise ValueError("max_tokens must be at least 256")
                    data = wiki_query(
                        root,
                        subjects=[item.strip() for item in subjects],
                        fact_kind=fact_kind,
                        candidate_file=candidate_file,
                        max_tokens=max_tokens,
                        project_id=str(self.config.project.project_id or root.name),
                        state_dir=wiki.state_dir,
                        overrides={
                            "exclude": list(wiki.document_exclude),
                            "explanatory": list(wiki.explanatory_overrides),
                            "generated": list(wiki.generated_overrides),
                        },
                        max_file_bytes=wiki.max_file_bytes,
                        max_files=wiki.max_files,
                        max_total_bytes=wiki.max_total_bytes,
                    )
                result = {"success": True, "data": data}
            except (TypeError, ValueError) as exc:
                message = str(exc)
                safe_prefixes = (
                    "subjects",
                    "fact_kind",
                    "candidate_file",
                    "max_tokens",
                )
                result = {
                    "success": False,
                    "error": (
                        message[:500]
                        if message.startswith(safe_prefixes)
                        else "Wiki control operation is unavailable."
                    ),
                }
            except OSError:
                result = {
                    "success": False,
                    "error": "Wiki control operation is unavailable.",
                }
            result = self._bounded_tool_result(requested_name, result)
            return self._post_tool_result(requested_name, arguments, result, start)
        result = self.tools_runtime.execute_tool(
            runtime_name,
            arguments,
            actor="mcp",
            enforce_policy=False,
        )
        result = self.tools_runtime._enforce_result_limit(result, self.max_result_chars)
        return self._post_tool_result(requested_name, arguments, result, start)

    def _saved_config_preparation(self) -> Dict[str, Any]:
        """Read the bound saved document afresh; never compose a second runtime.

        The public MCP startup still composes its effective single-target
        configuration. This projection does not relax that boundary: an
        already running provider may inspect a subsequently saved multi-target
        document, whose shared preparation reports execution as not startable.
        """
        if self.config_path is None:
            raise ValueError("Saved configuration preparation is unavailable.")
        from ..config.v3_preparation import prepare_saved_config

        try:
            return prepare_saved_config(str(self.config_path))
        except (OSError, ValueError, TypeError, RuntimeError) as exc:
            # Parser diagnostics may contain raw document values. The shared
            # projection is unchanged, but transport errors expose no secrets.
            raise ValueError("Saved configuration preparation is unavailable.") from exc

    def _call_jobs_tool(self, runtime_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one job tool onto the shared persistent job service.

        The adapter owns validation and envelope translation; an adapter bug
        surfaces as a generic internal error instead of leaking internals.
        """

        adapter = self.jobs_adapter
        if adapter is None:
            return {
                "success": False,
                "error": (
                    "persistent scan jobs are unavailable: this session has no " "saved config path"
                ),
                "code": "unavailable",
                "status_code": 503,
            }
        # Typed dispatch: the adapter method returns the MCP result mapping,
        # so the call site keeps its declared return type.
        method: Callable[[Any], Dict[str, Any]] = getattr(adapter, JOBS_TOOL_METHODS[runtime_name])
        try:
            return method(arguments)
        except Exception as exc:  # defensive: the service maps its own errors
            return {
                "success": False,
                "error": f"job tool failure ({type(exc).__name__})",
                "code": "internal_error",
                "status_code": 500,
            }

    def close(self) -> None:
        if self._owns_code_index:
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
        rollout = rollout_runtime_policy(self.config)
        effective_scan = {
            "depth": self.config.scan.depth,
            "depth_source": self.config.scan.depth_source,
            "rollout": rollout,
        }
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
            "scan": dict(effective_scan),
            "effective_scan": effective_scan,
            "llm_usage": scan_token_usage_snapshot(self.config),
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

    def _latest_report(self) -> Dict[str, Any]:
        if self.profile != "default":
            from ..common.readonly import ReadonlyStateError, read_bytes
            from ..reporting.shared_objects import decode_storage

            for name in ("zscope_batch_report.json", "report.json"):
                try:
                    value = decode_storage(
                        json.loads(read_bytes(self.config.project.project_root, name))
                    )
                    return {
                        "available": isinstance(value, dict),
                        "path": name,
                        "report": value if isinstance(value, dict) else {},
                    }
                except FileNotFoundError:
                    continue
                except (OSError, ValueError, ReadonlyStateError):
                    return {"available": False, "reason": "report_unavailable"}
            return {"available": False}
        for name in ("zscope_batch_report.json", "report.json"):
            path = self.config.project.project_root / name
            if not path.is_file():
                continue
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                return {"available": False, "path": str(path), "error": str(exc)}
            return {
                "available": isinstance(value, dict),
                "path": str(path),
                "report": value if isinstance(value, dict) else {},
            }
        return {"available": False, "path": ""}

    def _query_knowledge(
        self,
        sql: str,
        params: List[Any],
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
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

        page_limit = max(1, min(int(limit), 1000))
        page_offset = max(0, int(offset))
        has_user_limit = " limit " in lowered
        if has_user_limit:
            # The user's own LIMIT bounds the page; fetch one extra row via a
            # wrapper projection so overflow (has_more) is detectable without
            # rewriting their SQL.
            limited_sql = f"SELECT * FROM ({stripped}) LIMIT {page_limit + 1} OFFSET {page_offset}"
        else:
            limited_sql = f"{stripped} LIMIT {page_limit + 1} OFFSET {page_offset}"

        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(limited_sql, params).fetchall()
            has_more = len(rows) > page_limit
            page_rows = [dict(row) for row in rows[:page_limit]]
            data: Dict[str, Any] = {
                "rows": page_rows,
                "count": len(page_rows),
                "offset": page_offset,
                "has_more": has_more,
            }
            if has_more:
                data["note"] = (
                    "More rows match this query; re-run with offset="
                    f"{page_offset + page_limit} (or a larger limit) to page "
                    "through the remaining rows."
                )
            return {"success": True, "data": data}

    def _knowledge_db_path(self) -> Path:
        configured = Path(self.config.indexing.knowledge_db_path)
        if configured.is_absolute():
            return configured
        return self.config.project.project_root / configured

    def _tool_schema_by_name(self) -> Dict[str, Dict[str, Any]]:
        return {self.tool_policy.schema_name(schema): schema for schema in self.list_tools()}

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
        # Keep a head preview (mirroring _bounded_json_text) so an oversized
        # result still exposes its leading content instead of replacing the
        # whole payload with a metadata-only stub the caller cannot act on.
        preview_budget = max(0, self.max_result_chars - 800)
        return {
            "success": bool(result.get("success", True)),
            "data": {
                "truncated": True,
                "tool": name,
                "max_result_chars": self.max_result_chars,
                "original_chars": len(text),
                "message": (
                    "MCP tool result exceeded the configured hard limit; request a "
                    "smaller page or limit. The preview contains the leading "
                    f"{preview_budget} characters of the original result."
                ),
                "preview": text[:preview_budget],
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
