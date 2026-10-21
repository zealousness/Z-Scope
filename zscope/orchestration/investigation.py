"""Process-local registration of bounded investigation observations.

Only this program-owned session creates evidence references. Persisted manifests
are audit data, never capabilities, and registration never grants proof authority.
The executor must be an already restricted ToolsRuntime, not an arbitrary agent.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping

from ..reporting.immutable_evidence import ImmutableEvidencePool
from ..semantics.security_map import AuditUnit
from ..tools.source_access import ProjectSourceAccess, SourceAccessError


class InvestigationError(ValueError):
    """A stable, source-free error safe to return to a blind investigator."""


def _digest(value: Any) -> str:
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise InvestigationError("invalid_evidence_object") from None
    if len(raw.encode("utf-8")) > 2 * 1024 * 1024:
        raise InvestigationError("evidence_byte_budget")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class InvestigationIdentity:
    project_id: str
    revision: str
    build_context: str | None
    tool_version: str
    rule_version: str
    prompt_version: str
    model_identity: str
    tool_policy: str

    def __post_init__(self) -> None:
        if any(not value for key, value in asdict(self).items() if key != "build_context"):
            raise InvestigationError("incomplete_investigation_identity")


@dataclass(frozen=True)
class SourceScope:
    """A program-resolved function/range, including its exact TU when known."""

    function_uid: str
    file_path: str
    start_line: int
    end_line: int
    source_revision: str
    build_context: str | None = None
    symbol_id: str | None = None


@dataclass(frozen=True)
class InvestigationRequest:
    tool: str
    function_uid: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class InvestigationResult:
    """Internal runner result; intentionally has no from_dict capability loader."""

    report: Any
    session: InvestigationSession


_TOOLS = frozenset(
    {"search_code", "read_code", "get_semantic_context", "query_code_graph", "trace_data_flow"}
)


class InvestigationSession:
    def __init__(
        self,
        *,
        identity: InvestigationIdentity,
        current_identity: Callable[[], InvestigationIdentity],
        unit: AuditUnit,
        projection: Mapping[str, Any],
        source_access: ProjectSourceAccess,
        scopes: tuple[SourceScope, ...],
        execute_tool: Callable[[str, dict[str, Any]], Mapping[str, Any]],
        authorize_scope: Callable[[str], SourceScope | None] | None = None,
        allowed_tools: frozenset[str] = _TOOLS,
        max_extensions: int = 4,
        max_evidence: int = 32,
    ) -> None:
        if max_extensions < 0 or max_evidence < 1 or not allowed_tools <= _TOOLS:
            raise InvestigationError("invalid_investigation_policy")
        self.identity = identity
        self.unit_id = unit.unit_id
        self.unit_fingerprint = unit.fingerprint
        self._initial_members = frozenset(unit.member_functions)
        self._projection_hash = _digest(projection)
        self._current_identity = current_identity
        self._source = source_access
        self._execute = execute_tool
        self._authorize_scope = authorize_scope
        self._allowed_tools = allowed_tools
        self._max_extensions = max_extensions
        self._max_evidence = max_evidence
        self._extensions = 0
        self._scopes: dict[str, SourceScope] = {}
        self._entries: dict[str, dict[str, Any]] = {}
        self._artifacts: dict[str, Any] = {}
        self._pool = ImmutableEvidencePool()
        self._nonce = secrets.token_hex(16)
        self._closed = False
        if (
            projection.get("project_id") != identity.project_id
            or projection.get("revision") != identity.revision
        ):
            raise InvestigationError("project_revision_mismatch")
        initial = {
            item.get("function_uid"): item
            for item in projection.get("functions", [])
            if isinstance(item, Mapping)
        }
        for scope in scopes:
            record = initial.get(scope.function_uid, {})
            if (
                scope.function_uid not in self._initial_members
                or record.get("file_path") != scope.file_path
                or record.get("start_line") != scope.start_line
                or record.get("end_line") != scope.end_line
            ):
                raise InvestigationError("initial_scope_mismatch")
            self._add_scope(scope)
        self.validate_current()

    def _add_scope(self, scope: SourceScope) -> None:
        if (
            not scope.function_uid
            or scope.start_line < 1
            or scope.end_line < scope.start_line
            or scope.build_context != self.identity.build_context
            or not self._source.allowed(scope.file_path)
        ):
            raise InvestigationError("scope_identity_mismatch")
        try:
            _text, revision, _stat = self._source.read(scope.file_path)
        except SourceAccessError:
            raise InvestigationError("scope_source_unavailable") from None
        if revision != scope.source_revision:
            raise InvestigationError("scope_source_changed")
        previous = self._scopes.get(scope.function_uid)
        if previous is not None and previous != scope:
            raise InvestigationError("scope_identity_mismatch")
        self._scopes[scope.function_uid] = scope

    def extend_scope(self, function_uid: str) -> SourceScope:
        """The model names intent; a program resolver grants the actual range."""
        self.validate_current()
        if function_uid in self._scopes:
            return self._scopes[function_uid]
        if self._authorize_scope is None or self._extensions >= self._max_extensions:
            raise InvestigationError("scope_expansion_denied")
        try:
            scope = self._authorize_scope(function_uid)
        except Exception:
            raise InvestigationError("scope_expansion_unavailable") from None
        if not isinstance(scope, SourceScope) or scope.function_uid != function_uid:
            raise InvestigationError("scope_expansion_denied")
        self._add_scope(scope)
        self._extensions += 1
        return scope

    def validate_current(self) -> None:
        if self._closed:
            raise InvestigationError("investigation_closed")
        try:
            identity = self._current_identity()
        except Exception:
            raise InvestigationError("identity_unavailable") from None
        if identity != self.identity:
            raise InvestigationError("investigation_identity_changed")
        for scope in self._scopes.values():
            try:
                _text, revision, _stat = self._source.read(scope.file_path)
            except SourceAccessError:
                raise InvestigationError("scope_source_unavailable") from None
            if revision != scope.source_revision:
                raise InvestigationError("scope_source_changed")
        for ref, item in self._entries.items():
            artifact = self._artifacts.get(item["artifact_ref"])
            if artifact is None or _digest(artifact) != item["artifact_sha256"]:
                raise InvestigationError("artifact_identity_mismatch")
            if ref != item["evidence_ref"]:
                raise InvestigationError("evidence_identity_mismatch")

    def validate_report_binding(self, unit: AuditUnit, projection: Mapping[str, Any]) -> None:
        self.validate_current()
        if (
            self.unit_id != unit.unit_id
            or self.unit_fingerprint != unit.fingerprint
            or self._projection_hash != _digest(projection)
        ):
            raise InvestigationError("investigation_unit_mismatch")

    def validate_hypothesis_location(self, function_uid: str, location: str) -> None:
        scope = self._scopes.get(function_uid)
        if scope is None or not location.startswith(scope.file_path + ":"):
            raise InvestigationError("hypothesis_scope_mismatch")
        coordinates = location[len(scope.file_path) + 1 :].split(":")
        if (
            len(coordinates) not in {1, 2}
            or any(not value.isdecimal() or int(value) < 1 for value in coordinates)
            or not scope.start_line <= int(coordinates[0]) <= scope.end_line
        ):
            raise InvestigationError("hypothesis_scope_mismatch")

    @property
    def evidence_refs(self) -> frozenset[str]:
        self.validate_current()
        return frozenset(self._entries)

    @property
    def member_functions(self) -> frozenset[str]:
        self.validate_current()
        return self._initial_members | self._scopes.keys()

    def query(self, request: InvestigationRequest) -> dict[str, Any]:
        self.validate_current()
        if request.tool not in self._allowed_tools:
            raise InvestigationError("investigation_tool_denied")
        if len(self._entries) >= self._max_evidence:
            raise InvestigationError("investigation_evidence_budget")
        scope = self._scopes.get(request.function_uid)
        if scope is None:
            raise InvestigationError("unregistered_scope")
        arguments = self._pool.clone(dict(request.arguments))
        self._validate_arguments(request.tool, arguments, scope)
        _digest(arguments)
        try:
            raw = self._execute(request.tool, arguments)
        except Exception:
            raise InvestigationError("investigation_tool_failed") from None
        # Recheck all earlier observations too: two source versions never form
        # one supposedly closed hypothesis.
        self.validate_current()
        if not isinstance(raw, Mapping) or raw.get("status") not in {"ok", "partial"}:
            raise InvestigationError("investigation_tool_unavailable")
        raw = dict(raw)
        raw_hash = _digest(raw)
        kind, data = self._project(request.tool, raw, scope, arguments)
        self.validate_current()
        raw_coverage = raw.get("coverage")
        coverage = raw_coverage if isinstance(raw_coverage, dict) else {}
        # Completeness is local to this query, never the audit unit or program.
        level = (
            "partial"
            if raw.get("status") == "partial"
            or coverage.get("level") != "complete"
            or kind in {"compiler_structure", "static_flow", "semantic_advisory"}
            else "complete"
        )
        ref = "investigation:" + self._nonce + ":" + str(len(self._entries) + 1)
        artifact_ref = "artifact:" + self._nonce + ":" + raw_hash
        item = {
            "evidence_ref": ref,
            "artifact_ref": artifact_ref,
            "artifact_sha256": raw_hash,
            "artifact_retention": "session_only",
            "identity": asdict(self.identity),
            "scope": asdict(scope),
            "tool": request.tool,
            "arguments": arguments,
            "kind": kind,
            "strength": "may" if kind in {"static_flow", "compiler_structure"} else "observation",
            "proof_authority": False,
            "coverage": level,
            "data": data,
        }
        self._artifacts[artifact_ref] = self._pool.clone(raw)
        self._entries[ref] = self._pool.clone(item)
        return dict(self._pool.clone(item))

    def _validate_arguments(self, tool: str, args: dict[str, Any], scope: SourceScope) -> None:
        if tool == "read_code":
            start, end = args.get("start_line"), args.get("end_line")
            if (
                set(args) - {"file_path", "start_line", "end_line"}
                or args.get("file_path") != scope.file_path
                or type(start) is not int
                or type(end) is not int
                or not scope.start_line <= start <= end <= scope.end_line
            ):
                raise InvestigationError("query_scope_mismatch")
        elif tool == "search_code":
            if (
                args.get("scope") not in {"text", "files"}
                or not isinstance(args.get("query"), str)
                or not args["query"]
                or args.get("path_prefix") != scope.file_path
                or set(args)
                - {"scope", "query", "path_prefix", "limit", "offset", "view_id", "match_mode"}
                or args.get("match_mode", "substring") != "substring"
            ):
                raise InvestigationError("query_scope_mismatch")
        else:
            if not scope.symbol_id or args.get("symbol_id") != scope.symbol_id:
                raise InvestigationError("query_symbol_mismatch")
            if tool == "get_semantic_context":
                if (
                    set(args) - {"kind", "symbol_id", "refresh_policy"}
                    or args.get("kind") != "function"
                    or args.get("refresh_policy") != "cache_only"
                ):
                    raise InvestigationError("semantic_refresh_denied")
            elif not self.identity.build_context:
                raise InvestigationError("build_identity_unavailable")
            elif tool == "query_code_graph" and set(args) - {
                "symbol_id",
                "relation",
                "direction",
                "depth",
                "limit",
                "offset",
            }:
                raise InvestigationError("query_scope_mismatch")
            if tool == "trace_data_flow":
                if set(args) - {
                    "symbol_id",
                    "source",
                    "sink",
                    "max_call_depth",
                    "include_may_alias",
                    "limit",
                    "offset",
                }:
                    raise InvestigationError("query_scope_mismatch")
                for name in ("source", "sink"):
                    value = args.get(name)
                    if not isinstance(value, dict):
                        raise InvestigationError("query_scope_mismatch")
                    if value.get("file_path") not in {None, scope.file_path}:
                        raise InvestigationError("query_scope_mismatch")
                    if value.get("line") is not None and (
                        type(value["line"]) is not int
                        or not scope.start_line <= value["line"] <= scope.end_line
                    ):
                        raise InvestigationError("query_scope_mismatch")

    def _project(
        self, tool: str, raw: dict[str, Any], scope: SourceScope, args: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        data = raw.get("data")
        if not isinstance(data, dict):
            raise InvestigationError("invalid_tool_payload")
        if tool == "read_code":
            source = data.get("source")
            if (
                not isinstance(source, dict)
                or source.get("file") != scope.file_path
                or source.get("revision") != scope.source_revision
            ):
                raise InvestigationError("tool_source_identity_mismatch")
            start, end = source.get("start_line"), source.get("end_line")
            if (
                type(start) is not int
                or type(end) is not int
                or not args["start_line"] <= start <= end <= args["end_line"]
            ):
                raise InvestigationError("tool_source_scope_mismatch")
            # Read from the same locked corpus, not an output's arbitrary code
            # string. A forged tool payload cannot insert private metadata.
            expected = self._source.snippet(scope.file_path, start, end, end - start + 1)
            if (
                expected is None
                or expected["revision"] != scope.source_revision
                or source.get("code") != expected["code"]
            ):
                raise InvestigationError("tool_source_content_mismatch")
            return "source_text", {
                key: expected[key] for key in ("file", "start_line", "end_line", "code", "revision")
            }
        if tool == "search_code":
            matches = []
            source_text, _revision, _stat = self._source.read(scope.file_path)
            if _revision != scope.source_revision:
                raise InvestigationError("tool_source_identity_mismatch")
            lines = source_text.splitlines()
            for item in data.get("matches", []):
                if (
                    not isinstance(item, dict)
                    or item.get("file") != scope.file_path
                    or item.get("revision") != scope.source_revision
                ):
                    raise InvestigationError("tool_source_identity_mismatch")
                line = item.get("line")
                if line is not None and (
                    type(line) is not int or not scope.start_line <= line <= scope.end_line
                ):
                    continue
                if args["scope"] == "files":
                    if line is not None or args["query"] not in scope.file_path:
                        raise InvestigationError("tool_source_content_mismatch")
                    text, column = scope.file_path, None
                else:
                    if type(line) is not int or not 1 <= line <= len(lines):
                        raise InvestigationError("tool_source_content_mismatch")
                    column = lines[line - 1].find(args["query"])
                    if column < 0 or item.get("column") != column + 1:
                        raise InvestigationError("tool_source_content_mismatch")
                    begin = max(0, column - 100)
                    text = lines[line - 1][begin : begin + 512]
                    column += 1
                if item.get("text") != text:
                    raise InvestigationError("tool_source_content_mismatch")
                matches.append(
                    {
                        "file": scope.file_path,
                        "line": line,
                        "column": column,
                        "text": text,
                        "revision": scope.source_revision,
                    }
                )
            return "text_location", {"matches": matches}
        subject = data.get("subject")
        if not isinstance(subject, dict) or subject.get("symbol_id") != scope.symbol_id:
            raise InvestigationError("tool_symbol_identity_mismatch")
        if tool == "get_semantic_context":
            raw_snapshot = data.get("snapshot")
            snapshot = raw_snapshot if isinstance(raw_snapshot, dict) else {}
            # Legacy current-looking snapshots have no independently verified
            # receipt. They can signal a gap, never import contracts or hints.
            status = snapshot.get("status")
            return "semantic_advisory", {
                "status": (
                    status
                    if status in {"missing", "stale", "corrupt", "unverifiable", "unavailable"}
                    else "unverifiable"
                )
            }
        if tool == "query_code_graph":
            edges = []
            permitted = {s.symbol_id for s in self._scopes.values() if s.symbol_id}
            for edge in data.get("edges", []):
                if not isinstance(edge, dict):
                    raise InvestigationError("invalid_tool_payload")
                source, target = edge.get("source"), edge.get("target")
                if not isinstance(source, dict) or not isinstance(target, dict):
                    raise InvestigationError("invalid_tool_payload")
                if (
                    source.get("symbol_id") not in permitted
                    or target.get("symbol_id") not in permitted
                ):
                    continue
                edges.append(
                    {
                        "source": source["symbol_id"],
                        "target": target["symbol_id"],
                        "relation": args.get("relation"),
                        "strength": "may",
                    }
                )
            return "compiler_structure", {"edges": edges}
        paths = []
        for path in data.get("paths", []):
            if not isinstance(path, dict):
                raise InvestigationError("invalid_tool_payload")
            nodes = []
            for node in path.get("nodes", []):
                if not isinstance(node, dict) or not isinstance(node.get("location"), dict):
                    raise InvestigationError("invalid_tool_payload")
                loc = node["location"]
                line = loc.get("line")
                if (
                    loc.get("file") != scope.file_path
                    or type(line) is not int
                    or not scope.start_line <= line <= scope.end_line
                ):
                    raise InvestigationError("tool_flow_scope_mismatch")
                # Locations are permitted facts; arbitrary expression/evidence
                # dictionaries and claimed must strength are not imported.
                nodes.append({"file": scope.file_path, "line": line})
            paths.append({"classification": "may", "nodes": nodes, "truncated": True})
        return "static_flow", {"paths": paths}

    def manifest(self) -> dict[str, Any]:
        self.validate_current()
        payload = {
            "schema_version": "zscope.investigation-evidence.v1",
            "identity": asdict(self.identity),
            "unit_id": self.unit_id,
            "unit_fingerprint": self.unit_fingerprint,
            "projection_hash": self._projection_hash,
            "effective_policy": {
                "allowed_tools": sorted(self._allowed_tools),
                "max_extensions": self._max_extensions,
                "max_evidence": self._max_evidence,
            },
            "scopes": [asdict(item) for item in self._scopes.values()],
            "entries": list(self._entries.values()),
            "proof_authority": False,
            "raw_artifact_retention": "session_only",
            "replayable": False,
        }
        payload["cache_identity"] = _digest(payload)
        return dict(self._pool.clone(payload))

    def close(self) -> None:
        self._closed = True
        self._artifacts.clear()
