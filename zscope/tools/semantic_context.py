"""Bounded semantic snapshot and Security Semantic Map access."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..snapshots.modeling_input import SemanticModelInputError, build_semantic_model_input
from ..snapshots.readonly import ReadonlySnapshotStore
from ..common.readonly import ReadonlyStateError, readonly_database
from .source_access import ProjectSourceAccess
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

DESCRIPTION = """Read semantics or build_contexts/program_facts.
program_facts needs name/USR query+build_context_id; only function may rebuild.
cache_only never refreshes."""


SEMANTIC_CONTRACT = ToolContract(
    name="get_semantic_context",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "kind": {
                "type": "string",
                "enum": [
                    "function",
                    "claim",
                    "audit_unit",
                    "summary",
                    "build_contexts",
                    "program_facts",
                ],
            },
            "refresh_policy": {"type": "string", "enum": ["cache_only", "ensure_current"]},
            "symbol_id": {
                "type": ["string", "null"],
                "maxLength": 128,
            },
            "query": {"type": ["string", "null"], "maxLength": 256},
            "build_context_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
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
                    "enum": [
                        "function",
                        "claim",
                        "audit_unit",
                        "summary",
                        "build_contexts",
                        "program_facts",
                    ],
                },
                "subject": SYMBOL_SCHEMA,
                "snapshot": object_schema(
                    {
                        "status": {
                            "type": "string",
                            "enum": [
                                "current",
                                "missing",
                                "stale",
                                "corrupt",
                                "unverifiable",
                                "unavailable",
                            ],
                        },
                        "reason": {"type": "string"},
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
        *,
        cache_only: bool = False,
        candidate_blind: bool = False,
    ) -> None:
        contract = (
            replace(
                SEMANTIC_CONTRACT,
                annotations={
                    **SEMANTIC_CONTRACT.annotations,
                    "readOnlyHint": True,
                    "openWorldHint": False,
                },
            )
            if cache_only
            else SEMANTIC_CONTRACT
        )
        super().__init__(contract)
        self.cache_only = cache_only
        self.candidate_blind = candidate_blind
        self.snapshot_store = snapshot_store
        self.code_index = code_index
        self.catalog = catalog
        self.resolver = resolver
        self.semantic_map = GetSecuritySemanticsTool(
            Path(getattr(snapshot_store, "snapshot_dir", ".zscope_snapshots")) / "security_map.db"
        )

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if arguments.get("kind") == "program_facts" and (
            not arguments.get("query") or not arguments.get("build_context_id")
        ):
            return invalid_request(
                code="missing_build_identity",
                path="build_context_id",
                message="program_facts requires an exact function query and build_context_id.",
            )
        if arguments.get("build_context_id") and arguments.get("kind") != "program_facts":
            return invalid_request(
                code="unexpected_build_identity",
                path="build_context_id",
                message="build_context_id is only valid for program_facts.",
            )
        if self.cache_only and arguments.get("refresh_policy") == "ensure_current":
            return tool_result(
                status="forbidden",
                data=None,
                error={
                    "code": "refresh_forbidden",
                    "path": "refresh_policy",
                    "message": "This context only permits cache_only semantics.",
                    "retryable": False,
                },
            )
        if (
            arguments.get("kind") != "function"
            and arguments.get("refresh_policy") == "ensure_current"
        ):
            return invalid_request(
                code="unexpected_refresh_policy",
                path="refresh_policy",
                message="ensure_current is only supported for kind=function.",
            )
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
        # Enforce here too: direct Python callers must not bypass the profile.
        error = self.validate_cross_fields(arguments)
        if error:
            return error
        kind = str(arguments["kind"])
        if kind in {"build_contexts", "program_facts"}:
            return self._compilation_context(arguments)
        if self.cache_only or arguments.get("refresh_policy") == "cache_only":
            return (
                self._cached_function(str(arguments.get("symbol_id") or ""))
                if kind == "function"
                else self._cached_map(arguments)
            )
        if kind == "function":
            return self._function_context(str(arguments.get("symbol_id") or ""))
        return self._map_context(
            kind,
            str(arguments.get("query") or ""),
            int(arguments.get("limit", 20)),
            int(arguments.get("offset", 0)),
        )

    def _compilation_context(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Only query already initialized facts; never invoke the model resolver."""
        kind = str(arguments["kind"])
        getter = getattr(self.code_index, "get_build_contexts", None)
        if not callable(getter):
            return tool_result(
                status="unavailable",
                data={"kind": kind, "records": []},
                missing=["persisted_compilation_instances"],
            )
        contexts = getter()
        if kind == "build_contexts":
            query = str(arguments.get("query") or "")
            rows = [
                self._build_context_summary(context)
                for context in contexts
                if not query or query in context["source"]
            ]
            summary = {"cross_tu_complete": False, "link_target_status": "unverified"}
            missing = [] if rows else ["persisted_compilation_instances"]
        else:
            context_id = str(arguments["build_context_id"])
            context = next(
                (item for item in contexts if item["build_context_id"] == context_id), None
            )
            if context is None:
                return tool_result(
                    status="not_found",
                    data={"kind": kind, "records": []},
                    missing=["current_build_context"],
                    next_actions=[
                        "List build_contexts again; identities change with build inputs."
                    ],
                )
            from ..retrieval.build_context import context_input_status

            freshness = context_input_status(context)
            if freshness != "current":
                return tool_result(
                    status="partial",
                    data={
                        "kind": kind,
                        "records": [],
                        "summary": {"build_context_id": context_id, "freshness": freshness},
                    },
                    missing=[freshness],
                    next_actions=["Refresh the code index before requesting current proof facts."],
                )
            facts_getter = getattr(self.code_index, "get_function_program_facts", None)
            if not callable(facts_getter):
                return tool_result(
                    status="unavailable",
                    data={"kind": kind, "records": []},
                    missing=["compiler_program_facts"],
                )
            facts = facts_getter(str(arguments["query"]), build_context_id=context_id)
            # Choices are navigation metadata, not combined proof events; use
            # the ordinary page envelope even for large overload sets.
            rows = [
                {"kind": "function_choice", **choice}
                for choice in facts.get("function_choices", [])
            ]
            for body in facts.get("functions", []):
                rows.append(
                    {
                        key: value
                        for key, value in body.items()
                        if key not in {"events", "cfg_edges"}
                    }
                )
                rows.extend(
                    {"kind": "program_event", "owner": body.get("owner"), **event}
                    for event in body.get("events", [])
                )
                rows.extend(
                    {"kind": "program_cfg_edge", "owner": body.get("owner"), **edge}
                    for edge in body.get("cfg_edges", [])
                )
            rows.extend(facts.get("accesses", []))
            summary = {
                key: value
                for key, value in facts.items()
                if key
                not in {"functions", "accesses", "events", "build_context", "function_choices"}
            }
            summary["build_context"] = self._build_context_summary(context)
            missing = (
                []
                if facts.get("complete")
                else [str(facts.get("reason") or "complete_program_facts")]
            )
        offset, limit = int(arguments.get("offset", 0)), int(arguments.get("limit", 20))
        selected = rows[offset : offset + limit]
        return tool_result(
            status="partial" if missing else "ok",
            data={"kind": kind, "records": selected, "summary": summary},
            providers=["clang_compilation_instances"],
            missing=missing,
            coverage_details={"scope": "compilation_instance", "cross_tu_complete": False},
            page=page_result(offset, limit, len(selected), len(rows)),
        )

    @staticmethod
    def _build_context_summary(context: Dict[str, Any]) -> Dict[str, Any]:
        # Full input receipts remain in KnowledgeDB. They are unnecessary for
        # choosing an instance and must not crowd out pageable program facts.
        return {
            key: context.get(key)
            for key in (
                "build_context_id",
                "command_id",
                "source",
                "status",
                "dependencies_complete",
                "target",
                "link_target",
            )
        }

    def _cached_function(self, identifier: str) -> Dict[str, Any]:
        record = self.catalog.resolve_cached(identifier)
        if record is None:
            return tool_result(
                status="unavailable",
                data=None,
                missing=["cached_symbol_identity"],
                next_actions=["Search existing symbols; this query cannot initialize an index."],
            )
        if record["kind"] not in {"function", "method"}:
            return invalid_request(
                code="invalid_symbol_kind",
                path="symbol_id",
                message="kind=function requires a function or method symbol_id",
            )
        source_access = ProjectSourceAccess.for_index(self.code_index)
        store = ReadonlySnapshotStore(
            Path(getattr(self.snapshot_store, "snapshot_dir", ".zscope_snapshots")),
            project_root=source_access.root if source_access is not None else None,
        )
        cached = store.inspect(
            str(record.get("index_name") or record["qualified_name"]),
            source_access,
        )
        return tool_result(
            status=(
                "unavailable"
                if cached["status"] in {"missing", "corrupt", "unavailable"}
                else "partial"
            ),
            data={
                "kind": "function",
                "subject": public_symbol(record, include_macro=False),
                "snapshot": {
                    "status": cached["status"],
                    "reason": cached["reason"],
                    "rebuilt": False,
                    "persisted": False,
                    "rebuild_available": False,
                    "data": None if self.candidate_blind else cached["data"],
                },
                "contract": {},
                "security_semantics": {"status": "unavailable", "records": []},
                "provenance": {"snapshot_hash": cached["hash"]},
            },
            providers=["snapshot_store"],
            missing=[cached["reason"]],
            warnings=[
                "Cached content is historical/advisory; complete input freshness has not been verified."
            ],
            next_actions=[
                "Use read_code for current source. Refresh only in a separate authorized normal session."
            ],
        )

    def _cached_map(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        kind = str(arguments["kind"])
        try:
            source_access = ProjectSourceAccess.for_index(self.code_index)
            root = (
                source_access.root
                if source_access is not None
                else self.semantic_map.db_path.parent
            )
            relative = self.semantic_map.db_path.absolute().relative_to(root.absolute()).as_posix()
            with readonly_database(root, relative) as conn:
                row = conn.execute(
                    "SELECT CASE WHEN length(payload_json) <= 16777216 THEN payload_json ELSE NULL END FROM security_maps ORDER BY updated_at DESC LIMIT 1"
                ).fetchone()
                payload = json.loads(row[0]) if row else None
            if not isinstance(payload, dict) or any(
                not isinstance(payload.get(k, []), list)
                for k in ("claims", "audit_units", "functions")
            ):
                raise ValueError("no map")
        except (OSError, sqlite3.Error, ReadonlyStateError, ValueError, TypeError):
            return tool_result(
                status="unavailable",
                data={"kind": kind, "records": []},
                missing=["security_semantic_map"],
            )
        key = "claims" if kind == "claim" else "audit_units"
        records = (
            [x for x in payload.get(key, []) if isinstance(x, dict)] if kind != "summary" else []
        )
        if self.candidate_blind:

            def typed_record(item: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
                result: dict[str, Any] = {}
                for field in fields:
                    value = item.get(field)
                    if isinstance(value, str):
                        result[field] = value
                    elif isinstance(value, list) and all(isinstance(x, str) for x in value):
                        result[field] = list(value)
                return result

            if kind == "claim":
                records = [
                    typed_record(item, ("claim_id", "origin", "evidence_refs"))
                    for item in records
                    if item.get("origin") in {"program", "user"}
                ]
            else:
                records = [
                    typed_record(
                        item,
                        ("unit_id", "unit_kind", "member_functions", "event_refs", "unknown_refs"),
                    )
                    for item in records
                ]
        query = str(arguments.get("query") or "")
        if query:
            records = [
                r for r in records if query.lower() in json.dumps(r, ensure_ascii=False).lower()
            ]
        offset, limit = int(arguments.get("offset", 0)), int(arguments.get("limit", 20))
        selected = records[offset : offset + limit]
        data: Dict[str, Any] = {
            "kind": kind,
            "query": query,
            "records": selected,
            "provenance": {
                k: payload[k]
                for k in ("revision", "map_fingerprint")
                if isinstance(payload.get(k), str)
            },
        }
        if kind == "summary":
            data["summary"] = {
                "functions": len(payload.get("functions", [])),
                "audit_units": len(payload.get("audit_units", [])),
            }
        return tool_result(
            status="partial",
            data=data,
            providers=["security_map"],
            missing=["map_freshness_unverified"],
            page=page_result(offset, limit, len(selected), len(records)),
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
