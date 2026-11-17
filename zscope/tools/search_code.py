"""Unified lightweight symbol search."""

from __future__ import annotations

from typing import Any, Dict

import regex

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
    SEARCHABLE_KINDS,
    SYMBOL_SCHEMA,
    SymbolCatalog,
    project_relative_path_error,
    public_symbol,
)
from .source_access import ProjectSourceAccess

DESCRIPTION = """Find symbols (default), literal text, or file paths; preserve symbol_id.
Text/files locate code for read_code, not flow evidence."""


SEARCH_CONTRACT = ToolContract(
    name="search_code",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "query": {"type": "string", "minLength": 1, "maxLength": 256},
            "scope": {"type": "string", "enum": ["symbols", "text", "files"]},
            "view_id": {
                "type": ["string", "null"],
                "maxLength": 64,
                "description": "Text/files only: omit or JSON null initially; then copy the returned ID. Never use 'null'.",
            },
            "kinds": {
                "type": "array",
                "items": {"type": "string", "enum": list(SEARCHABLE_KINDS)},
                "maxItems": 5,
                "uniqueItems": True,
                "description": "Symbols only; omit or [] for text/files, including literal macro-source searches.",
            },
            "match_mode": {
                "type": "string",
                "enum": ["exact", "prefix", "substring", "regex"],
                "description": "Text/files require substring. Other modes apply only to symbols.",
            },
            "path_prefix": {"type": ["string", "null"], "maxLength": 1024},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "offset": {"type": "integer", "minimum": 0, "maximum": 100000},
        },
        required=["query"],
    ),
    output_schema=output_schema(
        object_schema(
            {
                "symbols": {"type": "array", "items": SYMBOL_SCHEMA},
                "scope": {"type": "string", "enum": ["text", "files"]},
                "view_id": {"type": "string"},
                "matches": {
                    "type": "array",
                    "items": object_schema(
                        {
                            "file": {"type": "string"},
                            "line": {"type": ["integer", "null"], "minimum": 1},
                            "column": {"type": ["integer", "null"], "minimum": 1},
                            "text": {"type": "string"},
                            "revision": {"type": "string"},
                        },
                        required=["file", "line", "column", "text", "revision"],
                    ),
                },
            },
            required=["symbols"],
        )
    ),
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
)


class SearchCodeTool(ContractTool):
    def __init__(
        self, catalog: SymbolCatalog, source_access: ProjectSourceAccess | None = None
    ) -> None:
        super().__init__(SEARCH_CONTRACT)
        self.catalog = catalog
        self.source_access = source_access or ProjectSourceAccess.for_index(catalog.code_index)

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Dict[str, Any] | None:
        scope = arguments.get("scope", "symbols")
        if scope != "symbols":
            for key in ("kinds", "match_mode"):
                if (key == "kinds" and arguments.get(key)) or (
                    key == "match_mode" and key in arguments and arguments[key] != "substring"
                ):
                    return invalid_request(
                        code="unsupported_search_option",
                        path=key,
                        message="For scope=text/files, use match_mode='substring' and omit kinds (or use []). Keep the query literal; exact/prefix/regex and nonempty kinds are only supported for scope=symbols.",
                    )
        elif arguments.get("view_id"):
            return invalid_request(
                code="unexpected_search_view",
                path="view_id",
                message="For scope=symbols omit view_id or use JSON null. Only text/files pagination accepts a returned view_id; never send the string 'null'.",
            )
        if arguments.get("path_prefix"):
            path_error = project_relative_path_error(arguments["path_prefix"])
            if path_error:
                return invalid_request(
                    code="invalid_project_path",
                    path="path_prefix",
                    message=path_error,
                )
        if arguments.get("match_mode", "substring") != "regex":
            return None
        query = str(arguments.get("query") or "")
        try:
            regex.compile(query, regex.VERSION0)
        except (regex.error, OverflowError) as exc:
            return invalid_request(
                code="invalid_regex", path="query", message=str(exc), retryable=True
            )
        return None

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if arguments.get("scope", "symbols") != "symbols":
            if self.source_access is None:
                return tool_result(status="unavailable", data=None, missing=["project_source_root"])
            return self.source_access.search(arguments)
        if getattr(self.catalog.code_index, "pinned_build_context_id", ""):
            # The navigation catalog reads project-wide stores, which the
            # instance facade deliberately blocks. Do not call those stores
            # or mistake their absence for an empty current-build symbol set.
            return tool_result(
                status="unavailable",
                data=None,
                missing=["build_scoped_symbol_catalog"],
                next_actions=[
                    "Use scope=text with a literal query, or read_code with a known file/line. "
                    "Text hits are navigation only, not current-build call edges."
                ],
            )
        query = str(arguments["query"])
        kinds = arguments.get("kinds") or list(SEARCHABLE_KINDS)
        match_mode = str(arguments.get("match_mode") or "substring")
        limit = int(arguments.get("limit", 20))
        offset = int(arguments.get("offset", 0))
        try:
            matches = self.catalog.search(query, kinds, match_mode, arguments.get("path_prefix"))
        except TimeoutError:
            return invalid_request(
                code="regex_query_timeout",
                path="query",
                message="Symbol regex search exceeded its time budget; simplify the pattern or narrow path_prefix.",
            )
        selected = matches[offset : offset + limit]
        status = "ok" if matches else "not_found"
        actions = [] if matches else ["Broaden query or use substring matching."]
        return tool_result(
            status=status,
            data={"symbols": [public_symbol(item) for item in selected]},
            providers=list(self.catalog.snapshot().providers),
            page=page_result(offset, limit, len(selected), len(matches)),
            next_actions=actions,
        )
