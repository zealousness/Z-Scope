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

DESCRIPTION = """Find project symbols before reading code: functions, methods, macros
(including object-like numeric macros), types, globals, and external functions.
Returns ranked symbol_id candidates; pass IDs unchanged. Does not return source,
graph, or data-flow evidence."""


SEARCH_CONTRACT = ToolContract(
    name="search_code",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "query": {"type": "string", "minLength": 1, "maxLength": 256},
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
            {"symbols": {"type": "array", "items": SYMBOL_SCHEMA}},
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
    def __init__(self, catalog: SymbolCatalog) -> None:
        super().__init__(SEARCH_CONTRACT)
        self.catalog = catalog

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Dict[str, Any] | None:
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
