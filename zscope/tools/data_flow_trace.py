"""Unified source-to-sink static flow tool."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .contracts import (
    ContractTool,
    ToolContract,
    invalid_request,
    object_schema,
    output_schema,
    page_result,
    tool_result,
)
from .flow_query import FlowQueryService
from .search_code import _unsafe_regex_reason
from .symbols import (
    SYMBOL_SCHEMA,
    SymbolCatalog,
    project_relative_path_error,
    public_symbol,
    valid_symbol_id,
)

DESCRIPTION = """Trace source-to-sink propagation from an exact function/method symbol_id and
structured selectors. When IDs and endpoint names are known, call this directly:
put a sink call name in sink.query without searching or reading first. Returns
bounded def-use, call/return, alias, and dispatch paths with may/must evidence."""


SOURCE_SCHEMA = object_schema(
    {
        "kind": {"type": "string", "enum": ["parameter", "variable", "global", "location"]},
        "name": {"type": ["string", "null"], "maxLength": 256},
        "file_path": {"type": ["string", "null"], "maxLength": 1024},
        "line": {"type": ["integer", "null"], "minimum": 1},
        "column": {"type": ["integer", "null"], "minimum": 1},
    },
    required=["kind"],
)

SINK_SCHEMA = object_schema(
    {
        "kind": {"type": "string", "enum": ["call", "variable", "global", "return", "location"]},
        "query": {"type": ["string", "null"], "maxLength": 256},
        "match_mode": {"type": "string", "enum": ["exact", "regex"]},
        "name": {"type": ["string", "null"], "maxLength": 256},
        "file_path": {"type": ["string", "null"], "maxLength": 1024},
        "line": {"type": ["integer", "null"], "minimum": 1},
        "column": {"type": ["integer", "null"], "minimum": 1},
    },
    required=["kind"],
)


FLOW_CONTRACT = ToolContract(
    name="trace_data_flow",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "symbol_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "source": SOURCE_SCHEMA,
            "sink": SINK_SCHEMA,
            "max_call_depth": {"type": "integer", "minimum": 0, "maximum": 8},
            "include_may_alias": {"type": "boolean"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 20},
            "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
        },
        required=["symbol_id", "source", "sink"],
    ),
    output_schema=output_schema(
        object_schema(
            {
                "subject": SYMBOL_SCHEMA,
                "reason": {"type": "string"},
                "paths": {
                    "type": "array",
                    "items": object_schema(
                        {
                            "path_id": {"type": "string"},
                            "classification": {
                                "type": "string",
                                "enum": ["may", "must"],
                            },
                            "nodes": {
                                "type": "array",
                                "maxItems": 200,
                                "items": object_schema(
                                    {
                                        "node_id": {"type": "string"},
                                        "kind": {"type": "string"},
                                        "event_kind": {"type": "string"},
                                        "expression": {"type": "string"},
                                        "callee": {"type": "string"},
                                        "location": object_schema(
                                            {
                                                "file": {"type": ["string", "null"]},
                                                "line": {
                                                    "type": ["integer", "null"],
                                                    "minimum": 1,
                                                },
                                                "column": {
                                                    "type": ["integer", "null"],
                                                    "minimum": 1,
                                                },
                                            },
                                            required=["file", "line", "column"],
                                        ),
                                        "guards": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                    },
                                    required=["node_id", "kind", "expression", "location"],
                                ),
                            },
                            "edges": {
                                "type": "array",
                                "items": object_schema(
                                    {
                                        "kind": {"type": "string"},
                                        "from": {"type": "string"},
                                        "to": {"type": "string"},
                                        "guard": {"type": "string"},
                                        "evidence": {"type": "object"},
                                    },
                                    required=["kind", "from", "to", "guard", "evidence"],
                                ),
                            },
                            "guards": {"type": "array", "items": {"type": "string"}},
                            "truncated": {"type": "boolean"},
                        },
                        required=[
                            "path_id",
                            "classification",
                            "nodes",
                            "edges",
                            "guards",
                            "truncated",
                        ],
                    ),
                },
                "max_call_depth": {"type": "integer"},
            },
            required=["subject", "reason", "paths", "max_call_depth"],
        )
    ),
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
)


class TraceDataFlowTool(ContractTool):
    def __init__(self, code_index: Any, catalog: SymbolCatalog) -> None:
        super().__init__(FLOW_CONTRACT)
        self.code_index = code_index
        self.catalog = catalog
        self.service = FlowQueryService(code_index, catalog)

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not valid_symbol_id(arguments.get("symbol_id")):
            return invalid_request(
                code="invalid_symbol_id",
                path="symbol_id",
                message="symbol_id must be passed unchanged from search_code",
            )
        source = arguments.get("source") or {}
        sink = arguments.get("sink") or {}
        source_kind = source.get("kind")
        sink_kind = sink.get("kind")
        if source_kind in {"parameter", "variable", "global"} and not source.get("name"):
            return invalid_request(
                code="missing_kind_field",
                path="source.name",
                message=f"source.name is required when source.kind={source_kind}",
            )
        if source_kind == "location":
            for field in ("file_path", "line"):
                if not source.get(field):
                    return invalid_request(
                        code="missing_kind_field",
                        path=f"source.{field}",
                        message=f"source.{field} is required when source.kind=location",
                    )
            path_error = project_relative_path_error(source.get("file_path"))
            if path_error:
                return invalid_request(
                    code="invalid_project_path",
                    path="source.file_path",
                    message=path_error,
                )
        if sink_kind in {"variable", "global"} and not sink.get("name"):
            return invalid_request(
                code="missing_kind_field",
                path="sink.name",
                message=f"sink.name is required when sink.kind={sink_kind}",
            )
        if sink_kind == "location":
            for field in ("file_path", "line"):
                if not sink.get(field):
                    return invalid_request(
                        code="missing_kind_field",
                        path=f"sink.{field}",
                        message=f"sink.{field} is required when sink.kind=location",
                    )
            path_error = project_relative_path_error(sink.get("file_path"))
            if path_error:
                return invalid_request(
                    code="invalid_project_path",
                    path="sink.file_path",
                    message=path_error,
                )
        if sink_kind == "call":
            if not sink.get("query"):
                return invalid_request(
                    code="missing_kind_field",
                    path="sink.query",
                    message="sink.query is required when sink.kind=call",
                )
            if sink.get("match_mode", "exact") == "regex":
                query = str(sink["query"])
                reason = _unsafe_regex_reason(query)
                if reason:
                    return invalid_request(code="unsafe_regex", path="sink.query", message=reason)
                try:
                    re.compile(query)
                except re.error as exc:
                    return invalid_request(
                        code="invalid_regex", path="sink.query", message=str(exc)
                    )
        return None

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        record = self.catalog.resolve(str(arguments["symbol_id"]))
        if record is None:
            return tool_result(
                status="not_found",
                data=None,
                providers=list(self.catalog.snapshot().providers),
                next_actions=["Run search_code again and pass the returned symbol_id unchanged."],
            )
        if record["kind"] not in {"function", "method"}:
            return invalid_request(
                code="invalid_symbol_kind",
                path="symbol_id",
                message="trace_data_flow requires a function or method symbol_id",
            )
        source = dict(arguments["source"])
        sink = dict(arguments["sink"])
        sink.setdefault("match_mode", "exact")
        limit = int(arguments.get("limit", 10))
        offset = int(arguments.get("offset", 0))
        query_limit = offset + limit + 1
        backend_name = str(getattr(self.code_index, "backend_name", "") or "").lower()
        backend_type = type(getattr(self.code_index, "_backend", None)).__name__.lower()
        if backend_name == "joern" or "joern" in backend_type:
            result = self.service.trace_joern(
                str(record.get("qualified_name") or record["name"]),
                source,
                sink,
                max_paths=query_limit,
            )
        elif str(getattr(self.code_index, "language", "c_cpp")) == "java":
            result = {
                "status": "unsupported",
                "reason": "unsupported_selector",
                "paths": [],
                "providers": [backend_name] if backend_name else [],
                "missing": ["java_def_use_backend"],
                "details": {},
            }
        else:
            result = self.service.trace_clang(
                str(record.get("index_name") or record["qualified_name"]),
                str(record.get("file") or ""),
                source,
                sink,
                include_may_alias=bool(arguments.get("include_may_alias", True)),
                max_call_depth=int(arguments.get("max_call_depth", 3)),
                max_paths=query_limit,
            )
        all_paths = result["paths"]
        selected = all_paths[offset : offset + limit]
        return tool_result(
            status=str(result["status"]),
            data={
                "subject": public_symbol(record, include_macro=False),
                "reason": result["reason"],
                "paths": selected,
                "max_call_depth": int(arguments.get("max_call_depth", 3)),
            },
            providers=list(result["providers"]),
            missing=list(result["missing"]),
            coverage_details=dict(result["details"]),
            page=page_result(offset, limit, len(selected), len(all_paths)),
            warnings=(
                ["No observed path is not proof of non-reachability under incomplete coverage."]
                if not selected and result["status"] != "ok"
                else []
            ),
        )
