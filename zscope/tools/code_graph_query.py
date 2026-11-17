"""Typed graph queries around exact symbols."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .contracts import (
    ContractTool,
    ToolContract,
    invalid_request,
    object_schema,
    output_schema,
    page_result,
    tool_result,
)
from .symbols import (
    SYMBOL_REF_SCHEMA,
    SYMBOL_SCHEMA,
    SymbolCatalog,
    normalize_project_path,
    public_symbol,
    valid_symbol_id,
)

DESCRIPTION = """Query call/reference/callback/indirect-call edges by symbol_id, with sites,
provenance, coverage and pagination. Use trace_data_flow for values;
partial coverage cannot prove absence."""


GRAPH_CONTRACT = ToolContract(
    name="query_code_graph",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "symbol_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
            },
            "relation": {
                "type": "string",
                "enum": ["call", "reference", "callback", "indirect_call"],
            },
            "direction": {
                "type": "string",
                "enum": ["incoming", "outgoing", "both"],
            },
            "depth": {"type": "integer", "minimum": 1, "maximum": 5},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
        },
        required=["symbol_id", "relation"],
    ),
    output_schema=output_schema(
        object_schema(
            {
                "subject": SYMBOL_SCHEMA,
                "relation": {"type": "string"},
                "direction": {"type": "string"},
                "depth": {"type": "integer"},
                "edges": {
                    "type": "array",
                    "items": object_schema(
                        {
                            "edge_id": {"type": "string"},
                            "relation": {
                                "type": "string",
                                "enum": ["call", "reference", "callback", "indirect_call"],
                            },
                            "distance": {"type": "integer", "minimum": 1},
                            "source": SYMBOL_REF_SCHEMA,
                            "target": SYMBOL_REF_SCHEMA,
                            "site": object_schema(
                                {
                                    "file": {"type": ["string", "null"]},
                                    "line": {"type": ["integer", "null"], "minimum": 1},
                                    "column": {"type": ["integer", "null"], "minimum": 1},
                                },
                                required=["file", "line", "column"],
                            ),
                            "dispatch": {"type": "string"},
                            "guard": {"type": "string"},
                            "evidence": object_schema(
                                {
                                    "provider": {"type": "string"},
                                    "confidence": {
                                        "type": "number",
                                        "minimum": 0,
                                        "maximum": 1,
                                    },
                                    "completeness": {
                                        "type": "string",
                                        "enum": ["complete", "partial"],
                                    },
                                    "callsite_id": {"type": ["string", "integer"]},
                                    "pointer_symbol": {"type": "string"},
                                    "svf_group": {"type": "string"},
                                    "svf_groups": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                },
                                required=["provider", "confidence", "completeness"],
                            ),
                        },
                        required=[
                            "edge_id",
                            "relation",
                            "distance",
                            "source",
                            "target",
                            "site",
                            "dispatch",
                            "guard",
                            "evidence",
                        ],
                    ),
                },
            },
            required=["subject", "relation", "direction", "depth", "edges"],
        )
    ),
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
)


class QueryCodeGraphTool(ContractTool):
    def __init__(self, code_index: Any, catalog: SymbolCatalog) -> None:
        super().__init__(GRAPH_CONTRACT)
        self.code_index = code_index
        self.catalog = catalog

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not valid_symbol_id(arguments.get("symbol_id")):
            return invalid_request(
                code="invalid_symbol_id",
                path="symbol_id",
                message="symbol_id must be passed unchanged from search_code",
            )
        if (
            arguments.get("relation") in {"reference", "callback"}
            and int(arguments.get("depth", 1)) != 1
        ):
            return invalid_request(
                code="unsupported_depth",
                path="depth",
                message="reference and callback relations require depth=1",
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
        relation = str(arguments["relation"])
        direction = str(arguments.get("direction") or "both")
        depth = int(arguments.get("depth", 1))
        limit = int(arguments.get("limit", 30))
        offset = int(arguments.get("offset", 0))

        if relation in {"call", "indirect_call"} and record["kind"] not in {
            "function",
            "method",
        }:
            return tool_result(
                status="unsupported",
                data={
                    "subject": public_symbol(record, include_macro=False),
                    "relation": relation,
                    "direction": direction,
                    "depth": depth,
                    "edges": [],
                },
                providers=[],
                missing=["callable_symbol"],
                coverage_details={"symbol_kind": record["kind"]},
                page=page_result(offset, limit, 0, 0),
            )

        if relation == "reference":
            edges, providers, complete = self._reference_edges(record, direction)
        elif relation == "callback":
            edges, providers, complete = self._callback_edges(record, direction)
        else:
            edges, providers, complete = self._call_edges(
                record,
                relation,
                direction,
                depth,
                edge_budget=offset + limit + 1,
            )
        edges.sort(key=self._edge_sort_key)
        selected = edges[offset : offset + limit]
        status = "ok" if complete else "partial"
        return tool_result(
            status=status,
            data={
                "subject": public_symbol(record, include_macro=False),
                "relation": relation,
                "direction": direction,
                "depth": depth,
                "edges": selected,
            },
            providers=sorted(providers),
            missing=[] if complete else [f"complete_{relation}_coverage"],
            coverage_details={"relation": relation, "direction": direction, "depth": depth},
            page=page_result(offset, limit, len(selected), len(edges)),
        )

    def _call_edges(
        self,
        root: Dict[str, Any],
        relation: str,
        direction: str,
        max_depth: int,
        *,
        edge_budget: int,
    ) -> Tuple[List[Dict[str, Any]], set[str], bool]:
        if root["kind"] not in {"function", "method"}:
            return [], set(), False
        providers: set[str] = set()
        edges: List[Dict[str, Any]] = []
        seen_edges: set[str] = set()
        expanded: set[Tuple[str, str]] = set()
        truncated = False
        frontier = [root]
        distance = 0
        while frontier and distance < max_depth and len(edges) < edge_budget:
            level_edges: List[Dict[str, Any]] = []
            next_frontier: Dict[str, Dict[str, Any]] = {}
            for current in sorted(
                frontier,
                key=lambda item: str(item.get("symbol_id") or item.get("qualified_name") or ""),
            ):
                for current_direction in self._directions(direction):
                    expansion_key = (str(current.get("symbol_id")), current_direction)
                    if expansion_key in expanded:
                        continue
                    expanded.add(expansion_key)
                    rows = self._call_rows(
                        current,
                        relation,
                        current_direction,
                        limit=edge_budget,
                    )
                    truncated |= len(rows) >= edge_budget
                    rows.sort(
                        key=lambda row: (
                            normalize_project_path(
                                row.get("call_file")
                                or row.get("filename")
                                or row.get("caller_file")
                                or row.get("callee_file")
                            ),
                            int(
                                row.get("call_line")
                                or row.get("lineNumber")
                                or row.get("line")
                                or 0
                            ),
                            str(
                                row.get("name")
                                or row.get("callee_name")
                                or row.get("caller_name")
                                or ""
                            ),
                        )
                    )
                    for row in rows:
                        if relation == "call" and (
                            "callback" in str(row.get("source") or "").lower()
                            or row.get("registration_kind")
                        ):
                            continue
                        provider = str(
                            row.get("source")
                            or row.get("provider")
                            or current.get("origin")
                            or "index"
                        )
                        providers.add(provider)
                        other_name = str(
                            row.get("name")
                            or row.get("callee_name")
                            or row.get("caller_name")
                            or ""
                        )
                        other_file = normalize_project_path(
                            row.get("filename")
                            or row.get(
                                "callee_file" if current_direction == "outgoing" else "caller_file"
                            )
                        )
                        other = self._resolve_name(
                            other_name,
                            other_file,
                            signature=str(
                                row.get(
                                    "callee_signature"
                                    if current_direction == "outgoing"
                                    else "caller_signature"
                                )
                                or ""
                            ),
                        )
                        current_ref = self._symbol_ref(current)
                        other_ref = self._symbol_ref(other)
                        if current_direction == "outgoing":
                            source, target = current_ref, other_ref
                        else:
                            source, target = other_ref, current_ref
                        site_file = normalize_project_path(
                            row.get("call_file")
                            or (
                                current.get("file")
                                if current_direction == "outgoing"
                                else row.get("filename") or row.get("caller_file")
                            )
                        )
                        site_line = int(
                            row.get("call_line") or row.get("lineNumber") or row.get("line") or 0
                        )
                        dispatch = (
                            "svf_resolved"
                            if relation == "indirect_call" or provider.lower() in {"svf", "saber"}
                            else str(row.get("call_type") or "direct")
                        )
                        edge = self._edge(
                            relation="call" if relation == "call" else "indirect_call",
                            distance=distance + 1,
                            source=source,
                            target=target,
                            file_path=site_file,
                            line=site_line,
                            column=int(row.get("column") or 0),
                            dispatch=dispatch,
                            guard=str(row.get("guard") or ""),
                            provider=provider,
                            confidence=float(
                                row["confidence"]
                                if row.get("confidence") is not None
                                else (1.0 if dispatch == "direct" else 0.5)
                            ),
                            completeness="partial" if dispatch != "direct" else "complete",
                            extra={
                                key: row[key]
                                for key in (
                                    "callsite_id",
                                    "pointer_symbol",
                                    "svf_group",
                                    "svf_groups",
                                )
                                if row.get(key) not in (None, "", [])
                            },
                        )
                        if edge["edge_id"] not in seen_edges:
                            seen_edges.add(edge["edge_id"])
                            level_edges.append(edge)
                        if other.get("symbol_id"):
                            next_frontier.setdefault(str(other["symbol_id"]), other)
            level_edges.sort(key=self._edge_sort_key)
            remaining = edge_budget - len(edges)
            edges.extend(level_edges[:remaining])
            if len(level_edges) > remaining:
                truncated = True
                break
            frontier = list(next_frontier.values())
            distance += 1
        backend = getattr(self.code_index, "_backend", None)
        if not providers and backend is not None:
            providers.add(str(getattr(self.code_index, "backend_name", "index") or "index"))
        complete = backend is not None and self._capability_complete("index")
        if relation == "indirect_call":
            complete = bool(self._database()) and self._capability_complete("svf")
        return edges, providers, complete and not truncated

    def _call_rows(
        self,
        current: Dict[str, Any],
        relation: str,
        direction: str,
        *,
        limit: int,
    ) -> List[Dict[str, Any]]:
        name = str(current.get("index_name") or current["qualified_name"])
        file_path = str(current.get("file") or "")
        db = self._database()
        if relation == "indirect_call" and db is not None:
            if direction == "outgoing":
                getter = getattr(db, "get_indirect_call_records", None)
                if callable(getter):
                    return list(
                        getter(name.split("@", 1)[0], caller_file=file_path, limit=limit) or []
                    )
                fallback = getattr(db, "get_indirect_callees", None)
                return (
                    list(fallback(name.split("@", 1)[0], limit=limit) or [])
                    if callable(fallback)
                    else []
                )
            getter = getattr(db, "get_indirect_callers", None)
            return (
                list(getter(name.split("@", 1)[0], limit=limit) or []) if callable(getter) else []
            )
        rows = (
            self.code_index.get_callees(name, limit=limit)
            if direction == "outgoing"
            else self.code_index.get_callers(name, limit=limit, callee_file=file_path)
        )
        return list(rows or [])

    def _reference_edges(
        self, root: Dict[str, Any], direction: str
    ) -> Tuple[List[Dict[str, Any]], set[str], bool]:
        db = self._database()
        getter = getattr(db, "query_symbol_references", None) if db is not None else None
        if not callable(getter):
            return [], set(), False
        rows: List[Dict[str, Any]] = []
        if root["kind"] in {"function", "method"} and direction in {"outgoing", "both"}:
            rows.extend(
                getter(
                    function_name=str(root["qualified_name"]),
                    function_file=str(root.get("file") or ""),
                )
            )
        if root["kind"] in {"global", "macro", "type", "function", "method"} and direction in {
            "incoming",
            "both",
        }:
            rows.extend(
                getter(
                    symbol_name=str(root["name"]),
                    symbol_kind=(
                        "function" if root["kind"] in {"function", "method"} else str(root["kind"])
                    ),
                    symbol_file=str(root.get("file") or ""),
                )
            )
        edges: List[Dict[str, Any]] = []
        for row in rows:
            source = self._resolve_name(
                str(row.get("function_name") or ""), str(row.get("function_file") or "")
            )
            target = self._resolve_name(
                str(row.get("symbol_name") or ""),
                str(row.get("symbol_file") or ""),
                preferred_kind=str(row.get("symbol_kind") or ""),
            )
            edges.append(
                self._edge(
                    relation="reference",
                    distance=1,
                    source=self._symbol_ref(source),
                    target=self._symbol_ref(target),
                    file_path=str(row.get("function_file") or ""),
                    line=int(row.get("reference_line") or 0),
                    column=0,
                    dispatch=str(row.get("access_kind") or "reference"),
                    guard="",
                    provider="knowledge_db",
                    confidence=1.0,
                    completeness="complete",
                )
            )
        return self._dedupe(edges), {"knowledge_db"}, self._capability_complete("index")

    def _callback_edges(
        self, root: Dict[str, Any], direction: str
    ) -> Tuple[List[Dict[str, Any]], set[str], bool]:
        getter = getattr(self.code_index, "callback_registrations", None)
        if not callable(getter):
            return [], set(), False
        registrations = list(getter() or [])
        edges: List[Dict[str, Any]] = []
        for row in registrations:
            caller = self._resolve_name(
                str(row.get("caller_name") or ""), str(row.get("caller_file") or "")
            )
            callee = self._resolve_name(
                str(row.get("callee_name") or ""), str(row.get("callee_file") or "")
            )
            root_id = root.get("symbol_id")
            if direction == "outgoing" and caller.get("symbol_id") != root_id:
                continue
            if direction == "incoming" and callee.get("symbol_id") != root_id:
                continue
            if direction == "both" and root_id not in {
                caller.get("symbol_id"),
                callee.get("symbol_id"),
            }:
                continue
            edges.append(
                self._edge(
                    relation="callback",
                    distance=1,
                    source=self._symbol_ref(caller),
                    target=self._symbol_ref(callee),
                    file_path=str(row.get("file") or row.get("caller_file") or ""),
                    line=int(row.get("line") or row.get("call_line") or 0),
                    column=int(row.get("column") or 0),
                    dispatch="callback_registration",
                    guard=str(row.get("guard") or ""),
                    provider=str(row.get("source") or "callback_registry"),
                    confidence=float(
                        row["confidence"] if row.get("confidence") is not None else 1.0
                    ),
                    completeness="partial",
                )
            )
        return (
            self._dedupe(edges),
            {"callback_registry"},
            self._capability_complete("index"),
        )

    def _resolve_name(
        self,
        name: str,
        file_path: str = "",
        preferred_kind: str = "",
        signature: str = "",
    ) -> Dict[str, Any]:
        kinds = (
            [preferred_kind]
            if preferred_kind in {"function", "method", "macro", "type", "global"}
            else []
        )
        if not kinds:
            kinds = ["function", "method", "macro", "type", "global"]
        candidates = self.catalog.search(name, kinds, "exact", None)
        normalized_file = self.catalog._file(file_path)
        if normalized_file:
            candidates = [
                item
                for item in candidates
                if normalize_project_path(item.get("file")) == normalized_file
            ]
        if signature:
            candidates = [
                item for item in candidates if str(item.get("signature") or "") == signature
            ]
        if len(candidates) == 1:
            # Keep the catalog record internally so deeper BFS levels retain
            # the exact index lookup name and defining file.  Edge payloads
            # are converted to the public symbol shape at the boundary.
            return candidates[0]
        return {
            "symbol_id": None,
            "kind": preferred_kind or "external",
            "name": name,
            "qualified_name": name,
            "signature": None,
            "location": {"file": normalized_file or None, "start_line": None, "end_line": None},
            "origin": "unresolved",
        }

    @staticmethod
    def _symbol_ref(record: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(record.get("location"), dict):
            return {
                key: record.get(key)
                for key in (
                    "symbol_id",
                    "kind",
                    "name",
                    "qualified_name",
                    "signature",
                    "location",
                    "origin",
                )
            }
        return public_symbol(record, include_macro=False)

    def _database(self) -> Any:
        backend = getattr(self.code_index, "_backend", None)
        db = getattr(backend, "db", None)
        if db is not None:
            return db
        return getattr(getattr(backend, "_clang", None), "db", None)

    def _capability_complete(self, name: str) -> bool:
        getter = getattr(self.code_index, "capability_status", None)
        if not callable(getter):
            # Small embedded/fake indexes predate capability telemetry. Their
            # attached backend remains the best available readiness signal.
            return getattr(self.code_index, "_backend", None) is not None
        try:
            details = (getter() or {}).get(name) or {}
        except Exception:
            return False
        if str(details.get("status") or "").lower() != "complete":
            return False
        if name == "index" and details.get("ready") is False:
            return False
        if name == "svf" and details.get("active") is False:
            return False
        return True

    @staticmethod
    def _directions(direction: str) -> Iterable[str]:
        return ("incoming", "outgoing") if direction == "both" else (direction,)

    @staticmethod
    def _edge_sort_key(item: Dict[str, Any]) -> Tuple[Any, ...]:
        return (
            int(item.get("distance") or 0),
            str((item.get("site") or {}).get("file") or ""),
            int((item.get("site") or {}).get("line") or 0),
            str((item.get("source") or {}).get("symbol_id") or ""),
            str((item.get("target") or {}).get("symbol_id") or ""),
            str(item.get("edge_id") or ""),
        )

    @staticmethod
    def _edge(
        *,
        relation: str,
        distance: int,
        source: Dict[str, Any],
        target: Dict[str, Any],
        file_path: str,
        line: int,
        column: int,
        dispatch: str,
        guard: str,
        provider: str,
        confidence: float,
        completeness: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        identity = "\x1f".join(
            (
                relation,
                str(source.get("symbol_id") or source.get("name") or ""),
                str(target.get("symbol_id") or target.get("name") or ""),
                normalize_project_path(file_path),
                str(line),
                str(column),
                dispatch,
            )
        )
        evidence = {
            "provider": provider,
            "confidence": max(0.0, min(1.0, confidence)),
            "completeness": completeness,
        }
        evidence.update(extra or {})
        return {
            "edge_id": "edge:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24],
            "relation": relation,
            "distance": distance,
            "source": source,
            "target": target,
            "site": {
                "file": normalize_project_path(file_path) or None,
                "line": line if line > 0 else None,
                "column": column if column > 0 else None,
            },
            "dispatch": dispatch,
            "guard": guard,
            "evidence": evidence,
        }

    @staticmethod
    def _dedupe(edges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return list({edge["edge_id"]: edge for edge in edges}.values())
