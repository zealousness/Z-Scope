"""Bounded read-only access to the Security Semantic Map sidecar."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List

from ..framework.base import BaseTool
from ..semantics.security_map import SecuritySemanticMap


class GetSecuritySemanticsTool(BaseTool):
    """Query current function, claim, or audit-unit semantic records."""

    MAX_RESULTS = 50

    def __init__(self, db_path: Path):
        super().__init__(
            name="get_security_semantics",
            description=(
                "Read a bounded projection of the persisted Security Semantic Map by "
                "function, claim, audit unit, or summary. This tool never edits state."
            ),
        )
        self.db_path = Path(db_path)

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        kind = str(arguments.get("kind") or "summary").strip().lower()
        if kind not in {"summary", "function", "claim", "unit"}:
            return {"success": False, "error": "kind must be summary, function, claim, or unit"}
        query = str(arguments.get("query") or "").strip().lower()
        try:
            limit = int(arguments.get("limit", 20))
        except (TypeError, ValueError):
            return {"success": False, "error": "limit must be an integer"}
        if limit < 1 or limit > self.MAX_RESULTS:
            return {
                "success": False,
                "error": f"limit must be between 1 and {self.MAX_RESULTS}",
            }
        if not self.db_path.is_file():
            return {
                "success": True,
                "data": None,
                "status": "missing",
                "message": "No Security Semantic Map sidecar exists for this scan profile.",
            }
        semantic_map = self._load_latest_map(
            project_id=str(arguments.get("project_id") or ""),
            revision=str(arguments.get("revision") or ""),
        )
        if semantic_map is None:
            return {
                "success": True,
                "data": None,
                "status": "missing",
                "message": "No matching Security Semantic Map was found.",
            }

        records: List[Dict[str, Any]]
        if kind == "function":
            records = [
                item.to_dict()
                for item in semantic_map.functions
                if self._matches(
                    query,
                    item.function_uid,
                    item.index_name,
                    item.function_name,
                    item.file_path,
                )
            ]
        elif kind == "claim":
            records = [
                item.to_dict()
                for item in semantic_map.claims
                if self._matches(query, item.claim_id, item.subject_uid, item.kind)
            ]
        elif kind == "unit":
            records = [
                item.to_dict()
                for item in semantic_map.audit_units
                if self._matches(
                    query,
                    item.unit_id,
                    item.unit_kind,
                    *item.member_functions,
                    *item.skill_families,
                )
            ]
        else:
            records = []
        total_matches = len(records)
        return {
            "success": True,
            "status": "current",
            "data": {
                "schema_version": semantic_map.schema_version,
                "project_id": semantic_map.project_id,
                "revision": semantic_map.revision,
                "profile": semantic_map.profile,
                "map_fingerprint": semantic_map.map_fingerprint,
                "coverage": dict(semantic_map.coverage),
                "kind": kind,
                "query": query,
                "total_matches": total_matches,
                "truncated": total_matches > limit,
                "records": records[:limit],
            },
        }

    @staticmethod
    def _matches(query: str, *values: Any) -> bool:
        if not query:
            return True
        return any(query in str(value or "").lower() for value in values)

    def _load_latest_map(
        self,
        *,
        project_id: str,
        revision: str,
    ) -> Any:
        clauses: List[str] = []
        values: List[str] = []
        if project_id:
            clauses.append("project_id = ?")
            values.append(project_id)
        if revision:
            clauses.append("revision = ?")
            values.append(revision)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        uri = self.db_path.resolve().as_uri() + "?mode=ro"
        try:
            with sqlite3.connect(uri, uri=True, timeout=5) as conn:
                row = conn.execute(
                    "SELECT payload_json FROM security_maps"
                    + where
                    + " ORDER BY updated_at DESC LIMIT 1",
                    tuple(values),
                ).fetchone()
        except (sqlite3.Error, OSError, ValueError):
            return None
        if not row:
            return None
        try:
            return SecuritySemanticMap.from_dict(json.loads(str(row[0])))
        except (json.JSONDecodeError, TypeError, ValueError):
            return None

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "kind": {
                            "type": "string",
                            "enum": ["summary", "function", "claim", "unit"],
                        },
                        "query": {"type": "string"},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
                        "project_id": {"type": "string"},
                        "revision": {"type": "string"},
                    },
                    "required": ["kind"],
                },
            },
        }
