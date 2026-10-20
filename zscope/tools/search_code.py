"""Unified lightweight symbol search."""

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
from .symbols import (
    SEARCHABLE_KINDS,
    SYMBOL_SCHEMA,
    SymbolCatalog,
    project_relative_path_error,
    public_symbol,
)
from .source_access import ProjectSourceAccess

DESCRIPTION = """Search symbols (default; preserve symbol_id), literal text, or file paths.
Text/files return read_code locations; page with view_id. Hits are not flow evidence."""


SEARCH_CONTRACT = ToolContract(
    name="search_code",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "query": {"type": "string", "minLength": 1, "maxLength": 256},
            "scope": {"type": "string", "enum": ["symbols", "text", "files"]},
            "view_id": {"type": ["string", "null"], "maxLength": 64},
            "kinds": {
                "type": "array",
                "items": {"type": "string", "enum": list(SEARCHABLE_KINDS)},
                "maxItems": 5,
                "uniqueItems": True,
            },
            "match_mode": {
                "type": "string",
                "enum": ["exact", "prefix", "substring", "regex"],
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


def _unsafe_regex_reason(pattern: str) -> str:
    if re.search(r"\\[1-9]", pattern):
        return "backreferences are not allowed"
    if re.search(r"\(\?(?:[=!<]|P[=<])", pattern):
        return "lookaround and named backreferences are not allowed"
    stack: list[dict[str, bool]] = []
    closed_group: Optional[dict[str, bool]] = None
    in_class = False
    escaped = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if escaped:
            escaped = False
            closed_group = None
            index += 1
            continue
        if char == "\\":
            escaped = True
            closed_group = None
            index += 1
            continue
        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
            closed_group = None
            index += 1
            continue
        if char == "(":
            stack.append({"repeat": False, "alternate": False})
            closed_group = None
            index += 1
            continue
        if char == ")":
            closed_group = stack.pop() if stack else {"repeat": False, "alternate": False}
            index += 1
            continue
        if char == "|":
            for group in stack:
                group["alternate"] = True
            closed_group = None
            index += 1
            continue
        quantifier = char in {"*", "+", "?"} and not (
            char == "?" and index > 0 and pattern[index - 1] == "("
        )
        if char == "{":
            end = pattern.find("}", index + 1)
            quantifier = end > index and bool(
                re.fullmatch(r"\d+(?:,\d*)?", pattern[index + 1 : end])
            )
            if quantifier:
                index = end
        if quantifier:
            if closed_group and (closed_group["repeat"] or closed_group["alternate"]):
                return "nested or ambiguous group repetition is not allowed"
            for group in stack:
                group["repeat"] = True
            closed_group = None
        elif not char.isspace():
            closed_group = None
        index += 1
    if re.search(r"(?:\.\*|\.\+){2,}", pattern):
        return "repeated wildcard repetition is not allowed"
    return ""


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
                if key in arguments and (key == "kinds" or arguments[key] != "substring"):
                    return invalid_request(
                        code="unsupported_search_option",
                        path=key,
                        message="text/files support only literal substring matching, without kinds.",
                    )
        elif arguments.get("view_id"):
            return invalid_request(
                code="unexpected_search_view",
                path="view_id",
                message="view_id is only valid for text/files.",
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
        reason = _unsafe_regex_reason(query)
        if reason:
            return invalid_request(
                code="unsafe_regex", path="query", message=reason, retryable=True
            )
        try:
            re.compile(query)
        except re.error as exc:
            return invalid_request(
                code="invalid_regex", path="query", message=str(exc), retryable=True
            )
        return None

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if arguments.get("scope", "symbols") != "symbols":
            if self.source_access is None:
                return tool_result(status="unavailable", data=None, missing=["project_source_root"])
            return self.source_access.search(arguments)
        query = str(arguments["query"])
        kinds = arguments.get("kinds") or list(SEARCHABLE_KINDS)
        match_mode = str(arguments.get("match_mode") or "substring")
        limit = int(arguments.get("limit", 20))
        offset = int(arguments.get("offset", 0))
        matches = self.catalog.search(
            query,
            kinds,
            match_mode,
            arguments.get("path_prefix"),
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
