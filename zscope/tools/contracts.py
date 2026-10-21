"""Shared contracts and result envelopes for LLM-facing analysis tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from copy import deepcopy
from typing import Any, Dict, Mapping, Optional

from ..framework.base import BaseTool, validate_function_arguments

TOOL_STATUSES = {
    "ok",
    "not_found",
    "partial",
    "unsupported",
    "unavailable",
    "invalid_request",
    "forbidden",
    "internal_error",
}


@dataclass(frozen=True)
class ToolContract:
    """Single source of truth for Agent and MCP tool descriptions."""

    name: str
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    annotations: Dict[str, bool] = field(default_factory=dict)

    def openai_schema(self, *, strict: bool = False) -> Dict[str, Any]:
        function: Dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "parameters": self.input_schema,
        }
        if strict:
            function["strict"] = True
        return {"type": "function", "function": function}

    def mcp_schema(self, name: str, *, include_output: bool = True) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "name": name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": dict(self.annotations),
        }
        if include_output:
            result["outputSchema"] = self.output_schema
        return result


def object_schema(
    properties: Mapping[str, Any],
    *,
    required: Optional[list[str]] = None,
) -> Dict[str, Any]:
    return {
        "type": "object",
        "properties": dict(properties),
        "required": list(required or []),
        "additionalProperties": False,
    }


COVERAGE_SCHEMA = object_schema(
    {
        "level": {
            "type": "string",
            "enum": ["complete", "partial", "unsupported", "unavailable"],
        },
        "providers": {"type": "array", "items": {"type": "string"}},
        "missing": {"type": "array", "items": {"type": "string"}},
        "details": {"type": "object"},
    },
    required=["level", "providers", "missing", "details"],
)

PAGE_SCHEMA = {
    "type": ["object", "null"],
    "properties": {
        "offset": {"type": "integer", "minimum": 0},
        "limit": {"type": "integer", "minimum": 1},
        "returned": {"type": "integer", "minimum": 0},
        "total": {"type": "integer", "minimum": 0},
        "has_more": {"type": "boolean"},
        "next_offset": {"type": ["integer", "null"], "minimum": 0},
    },
    "required": ["offset", "limit", "returned", "total", "has_more", "next_offset"],
    "additionalProperties": False,
}

ERROR_SCHEMA = {
    "type": ["object", "null"],
    "properties": {
        "code": {"type": "string"},
        "path": {"type": ["string", "null"]},
        "message": {"type": "string"},
        "retryable": {"type": "boolean"},
    },
    "required": ["code", "path", "message", "retryable"],
    "additionalProperties": False,
}

OUTPUT_SCHEMA = object_schema(
    {
        "success": {"type": "boolean"},
        "status": {"type": "string", "enum": sorted(TOOL_STATUSES)},
        "data": {},
        "coverage": COVERAGE_SCHEMA,
        "page": PAGE_SCHEMA,
        "warnings": {"type": "array", "items": {"type": "string"}},
        "next_actions": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 3,
        },
        "error": ERROR_SCHEMA,
    },
    required=[
        "success",
        "status",
        "data",
        "coverage",
        "page",
        "warnings",
        "next_actions",
        "error",
    ],
)


def output_schema(data_schema: Dict[str, Any]) -> Dict[str, Any]:
    """Return the common envelope with a tool-specific nullable ``data`` body."""
    schema = deepcopy(OUTPUT_SCHEMA)
    schema["properties"]["data"] = {"anyOf": [deepcopy(data_schema), {"type": "null"}]}
    return schema


def page_result(offset: int, limit: int, returned: int, total: int) -> Dict[str, Any]:
    next_offset = offset + returned if offset + returned < total else None
    return {
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "total": total,
        "has_more": next_offset is not None,
        "next_offset": next_offset,
    }


def tool_result(
    *,
    status: str = "ok",
    data: Any = None,
    providers: Optional[list[str]] = None,
    coverage_level: Optional[str] = None,
    missing: Optional[list[str]] = None,
    coverage_details: Optional[Dict[str, Any]] = None,
    page: Optional[Dict[str, Any]] = None,
    warnings: Optional[list[str]] = None,
    next_actions: Optional[list[str]] = None,
    error: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    if status not in TOOL_STATUSES:
        raise ValueError(f"Unknown tool status: {status}")
    success = status not in {"invalid_request", "forbidden", "internal_error"}
    level = coverage_level or (
        status if status in {"partial", "unsupported", "unavailable"} else "complete"
    )
    return {
        "success": success,
        "status": status,
        "data": data,
        "coverage": {
            "level": level,
            "providers": list(providers or []),
            "missing": list(missing or []),
            "details": dict(coverage_details or {}),
        },
        "page": page,
        "warnings": list(warnings or []),
        "next_actions": list(next_actions or [])[:3],
        "error": error,
    }


def invalid_request(
    *, code: str, path: Optional[str], message: str, retryable: bool = True
) -> Dict[str, Any]:
    return tool_result(
        status="invalid_request",
        data=None,
        coverage_level="unsupported",
        error={
            "code": code,
            "path": path,
            "message": message,
            "retryable": retryable,
        },
    )


class ContractTool(BaseTool):
    """Base class for tools generated from one reusable :class:`ToolContract`."""

    contract: ToolContract

    def __init__(self, contract: ToolContract) -> None:
        self.contract = contract
        super().__init__(contract.name, contract.description)

    def get_contract(self) -> ToolContract:
        return self.contract

    def get_schema(self) -> Dict[str, Any]:
        return self.contract.openai_schema()

    def get_output_schema(self) -> Dict[str, Any]:
        return self.contract.output_schema

    def get_annotations(self) -> Dict[str, bool]:
        return dict(self.contract.annotations)

    def validate_arguments(self, arguments: Any) -> Optional[Dict[str, Any]]:
        error = validate_function_arguments(self.get_schema(), arguments, reject_unknown=True)
        if not error:
            return self.validate_cross_fields(arguments)
        path, _, message = error.partition(": ")
        if error == "Tool arguments must be a JSON object":
            path, message = "$", error
        return invalid_request(
            code="schema_validation_failed",
            path=path or None,
            message=message or error,
        )

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None

    def validate_result(self, result: Any) -> Optional[str]:
        """Validate the structured result before it crosses an Agent/MCP boundary."""
        return validate_function_arguments(self.contract.output_schema, result)
