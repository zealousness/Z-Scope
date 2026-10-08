"""Bounded semantic snapshot and Security Semantic Map access."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..snapshots.modeling_input import SemanticModelInputError, build_semantic_model_input
from .contracts import (
    ContractTool,
    ToolContract,
    invalid_request,
    object_schema,
    output_schema,
    page_result,
    tool_result,
)
from .security_semantics import GetSecuritySemanticsTool
from .symbols import SYMBOL_SCHEMA, SymbolCatalog, public_symbol, valid_symbol_id

DESCRIPTION = """Get bounded function snapshots/contracts or Security Semantic Map claims,
audit units, and summary. Function requests may rebuild and persist stale
snapshots when a resolver exists. Prefer read_code when source conflicts."""


SEMANTIC_CONTRACT = ToolContract(
    name="get_semantic_context",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "kind": {
                "type": "string",
                "enum": ["function", "claim", "audit_unit", "summary"],
            },
            "symbol_id": {
                "type": ["string", "null"],
                "maxLength": 128,
            },
            "query": {"type": ["string", "null"], "maxLength": 256},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
        },
        required=["kind"],
    ),
    output_schema=output_schema(
        object_schema(
            {
                "kind": {
                    "type": "string",
                    "enum": ["function", "claim", "audit_unit", "summary"],
                },
                "subject": SYMBOL_SCHEMA,
                "snapshot": object_schema(
                    {
                        "status": {
                            "type": "string",
                            "enum": ["current", "missing", "stale"],
                        },
                        "rebuilt": {"type": "boolean"},
                        "persisted": {"type": "boolean"},
                        "rebuild_available": {"type": "boolean"},
                        "data": {"type": ["object", "null"]},
                    },
                    required=[
                        "status",
                        "rebuilt",
                        "persisted",
                        "rebuild_available",
                        "data",
                    ],
                ),
                "contract": {"type": "object"},
                "security_semantics": object_schema(
                    {
                        "status": {"type": "string", "enum": ["current", "unavailable"]},
                        "records": {"type": "array", "items": {"type": "object"}},
                    },
                    required=["status", "records"],
                ),
                "query": {"type": "string"},
                "records": {"type": "array", "items": {"type": "object"}},
                "summary": {"type": "object"},
                "provenance": object_schema(
                    {
                        "revision": {"type": ["string", "null"]},
                        "snapshot_hash": {"type": ["string", "null"]},
                        "map_fingerprint": {"type": ["string", "null"]},
                    }
                ),
            },
            required=["kind"],
        )
    ),
    annotations={
        "readOnlyHint": False,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": True,
    },
)


class SemanticContextTool(ContractTool):
    def __init__(
        self,
        snapshot_store: Any,
        code_index: Any,
        catalog: SymbolCatalog,
        resolver: Optional[Callable[[str, Optional[str]], Dict[str, Any]]] = None,
    ) -> None:
        super().__init__(SEMANTIC_CONTRACT)
        self.snapshot_store = snapshot_store
        self.code_index = code_index
        self.catalog = catalog
        self.resolver = resolver
        self.semantic_map = GetSecuritySemanticsTool(
            Path(getattr(snapshot_store, "snapshot_dir", ".zscope_snapshots")) / "security_map.db"
        )

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if arguments.get("symbol_id") and not valid_symbol_id(arguments["symbol_id"]):
            return invalid_request(
                code="invalid_symbol_id",
                path="symbol_id",
                message="symbol_id must be passed unchanged from search_code",
            )
        if arguments.get("kind") == "function" and not arguments.get("symbol_id"):
            return invalid_request(
                code="missing_kind_field",
                path="symbol_id",
                message="symbol_id is required when kind=function",
            )
        if arguments.get("kind") != "function" and arguments.get("symbol_id"):
            return invalid_request(
                code="unexpected_kind_field",
                path="symbol_id",
                message="symbol_id is only valid when kind=function",
            )
        return None

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        kind = str(arguments["kind"])
        if kind == "function":
            return self._function_context(str(arguments.get("symbol_id") or ""))
        return self._map_context(
            kind,
            str(arguments.get("query") or ""),
            int(arguments.get("limit", 20)),
            int(arguments.get("offset", 0)),
        )

    def _function_context(self, identifier: str) -> Dict[str, Any]:
        record = self.catalog.resolve(identifier)
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
                message="kind=function requires a function or method symbol_id",
            )

        index_name = str(record.get("index_name") or record["qualified_name"])
        file_path = str(record.get("file") or "")
        before = self.snapshot_store.load_snapshot(index_name)
        snapshot: Optional[Dict[str, Any]] = None
        snapshot_status = "missing"
        rebuilt = False
        persisted = False
        warnings: List[str] = []
        missing: List[str] = []

        if self.resolver is not None:
            resolved = self.resolver(index_name, file_path or None)
            if resolved.get("success") and isinstance(resolved.get("data"), dict):
                snapshot = dict(resolved["data"])
                snapshot_status = "current"
                rebuilt = (
                    before is None or "generated" in str(resolved.get("message") or "").lower()
                )
                persisted = self.snapshot_store.load_snapshot(index_name) is not None
            else:
                reason = str(resolved.get("reason") or "snapshot_rebuild_failed")
                snapshot_status = "stale" if before is not None else "missing"
                warnings.append(str(resolved.get("error") or reason))
                missing.append(reason)
        else:
            try:
                context = build_semantic_model_input(
                    self.code_index,
                    index_name,
                    file_path=file_path,
                    include_context=False,
                )
                index_name = str(context.get("index_name") or index_name)
                snapshot = self.snapshot_store.load_snapshot(index_name)
                if snapshot is not None:
                    stale, _reason = self.snapshot_store.needs_refresh(
                        index_name, str(context.get("code") or ""), context
                    )
                    snapshot_status = "stale" if stale else "current"
                    if stale:
                        snapshot = None
                        missing.append("current_snapshot")
                else:
                    missing.append("snapshot")
            except SemanticModelInputError as exc:
                warnings.append(str(exc))
                missing.append(str(exc.reason))

        map_records, map_meta = self._load_map_records(record, index_name)
        if not map_meta:
            missing.append("security_semantic_map")
        snapshot_hash = (
            hashlib.sha256(
                json.dumps(snapshot, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            if snapshot is not None
            else None
        )
        data = {
            "kind": "function",
            "subject": public_symbol(record, include_macro=False),
            "snapshot": {
                "status": snapshot_status,
                "rebuilt": rebuilt,
                "persisted": persisted,
                "rebuild_available": self.resolver is not None,
                "data": snapshot,
            },
            "contract": self._contract(snapshot),
            "security_semantics": {
                "status": "current" if map_meta else "unavailable",
                "records": map_records,
            },
            "provenance": {
                "revision": map_meta.get("revision") if map_meta else None,
                "snapshot_hash": snapshot_hash,
                "map_fingerprint": map_meta.get("map_fingerprint") if map_meta else None,
            },
        }
        complete = snapshot is not None and snapshot_status == "current" and bool(map_meta)
        return tool_result(
            status="ok" if complete else "partial",
            data=data,
            providers=["snapshot_store"] + (["security_map"] if map_meta else []),
            missing=list(dict.fromkeys(missing)),
            warnings=warnings,
            next_actions=(["Use read_code for primary source evidence."] if not complete else []),
        )

    def _map_context(self, kind: str, query: str, limit: int, offset: int) -> Dict[str, Any]:
        map_kind = "unit" if kind == "audit_unit" else kind
        semantic_map = self.semantic_map._load_latest_map(project_id="", revision="")
        if semantic_map is None:
            return tool_result(
                status="unavailable",
                data={"kind": kind, "records": []},
                providers=[],
                missing=["security_semantic_map"],
            )
        if map_kind == "claim":
            records = [item.to_dict() for item in semantic_map.claims]
        elif map_kind == "unit":
            records = [item.to_dict() for item in semantic_map.audit_units]
        else:
            records = []
        if query:
            needle = query.lower()
            records = [
                item
                for item in records
                if needle in json.dumps(item, ensure_ascii=False, sort_keys=True).lower()
            ]
        total = len(records)
        selected = records[offset : offset + limit]
        data: Dict[str, Any] = {
            "kind": kind,
            "query": query,
            "records": selected,
            "provenance": {
                "revision": semantic_map.revision,
                "map_fingerprint": semantic_map.map_fingerprint,
            },
        }
        if kind == "summary":
            data["summary"] = {
                "schema_version": semantic_map.schema_version,
                "project_id": semantic_map.project_id,
                "profile": semantic_map.profile,
                "coverage": dict(semantic_map.coverage),
                "functions": len(semantic_map.functions),
                "claims": len(semantic_map.claims),
                "audit_units": len(semantic_map.audit_units),
            }
        return tool_result(
            data=data,
            providers=["security_map"],
            page=page_result(offset, limit, len(selected), total),
        )

    def _load_map_records(
        self, record: Dict[str, Any], index_name: str
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        semantic_map = self.semantic_map._load_latest_map(project_id="", revision="")
        if semantic_map is None:
            return [], {}
        file_path = str(record.get("file") or "")
        start_line = int(record.get("start_line") or 0)
        signature = str(record.get("signature") or "")
        records = [
            item.to_dict()
            for item in semantic_map.functions
            if item.index_name == index_name
            or (
                item.function_name
                in {str(record.get("qualified_name") or ""), str(record.get("name") or "")}
                and (not file_path or item.file_path == file_path)
                and (not start_line or item.start_line == start_line)
                and (not signature or not item.signature or item.signature == signature)
            )
        ]
        return records, {
            "revision": semantic_map.revision,
            "map_fingerprint": semantic_map.map_fingerprint,
        }

    @staticmethod
    def _contract(snapshot: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not snapshot:
            return {}
        for key in ("contract", "interface_contract", "api_contract"):
            if isinstance(snapshot.get(key), dict):
                return dict(snapshot[key])
        return {
            "interface_contracts": snapshot.get("interface_contracts") or [],
            "preconditions": snapshot.get("preconditions") or [],
            "postconditions": snapshot.get("postconditions") or [],
        }
