"""Exact source retrieval by symbol ID or explicit line range."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .contracts import (
    ContractTool,
    ToolContract,
    invalid_request,
    object_schema,
    output_schema,
    tool_result,
)
from .symbols import (
    MACRO_SCHEMA,
    SYMBOL_SCHEMA,
    SymbolCatalog,
    project_relative_path_error,
    public_symbol,
    valid_symbol_id,
)

DESCRIPTION = """Read exact source by symbol_id from search_code or by project-relative line
range. Returns numbered source, symbol metadata, and continuation/truncation
fields. Prefer symbol_id; this tool does not infer calls or data flow."""


READ_CONTRACT = ToolContract(
    name="read_code",
    description=DESCRIPTION,
    input_schema=object_schema(
        {
            "symbol_id": {
                "type": ["string", "null"],
                "maxLength": 128,
            },
            "file_path": {"type": ["string", "null"], "maxLength": 1024},
            "start_line": {"type": ["integer", "null"], "minimum": 1},
            "end_line": {"type": ["integer", "null"], "minimum": 1},
            "max_lines": {"type": "integer", "minimum": 1, "maximum": 500},
        }
    ),
    output_schema=output_schema(
        object_schema(
            {
                "symbol": {"anyOf": [SYMBOL_SCHEMA, {"type": "null"}]},
                "source": {
                    "anyOf": [
                        object_schema(
                            {
                                "file": {"type": "string"},
                                "start_line": {"type": "integer", "minimum": 1},
                                "end_line": {"type": "integer", "minimum": 1},
                                "code": {"type": "string"},
                                "definition_end_line": {
                                    "type": ["integer", "null"],
                                    "minimum": 1,
                                },
                                "total_file_lines": {
                                    "type": ["integer", "null"],
                                    "minimum": 0,
                                },
                                "truncated": {"type": "boolean"},
                                "next_start_line": {
                                    "type": ["integer", "null"],
                                    "minimum": 1,
                                },
                            },
                            required=[
                                "file",
                                "start_line",
                                "end_line",
                                "code",
                                "definition_end_line",
                                "total_file_lines",
                                "truncated",
                                "next_start_line",
                            ],
                        ),
                        {"type": "null"},
                    ]
                },
                "definition": object_schema(
                    {
                        "complete": {"type": "boolean"},
                        "origin": {"type": "string"},
                        "contract": {"type": "object"},
                    },
                    required=["complete", "origin"],
                ),
                "macro": MACRO_SCHEMA,
                "members": {"type": "array", "items": {"type": "object"}},
            },
            required=["symbol", "source", "definition"],
        )
    ),
    annotations={
        "readOnlyHint": True,
        "idempotentHint": True,
        "destructiveHint": False,
        "openWorldHint": False,
    },
)


class ReadCodeTool(ContractTool):
    def __init__(self, code_index: Any, catalog: SymbolCatalog) -> None:
        super().__init__(READ_CONTRACT)
        self.code_index = code_index
        self.catalog = catalog

    def validate_cross_fields(self, arguments: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        symbol_id = arguments.get("symbol_id")
        file_path = arguments.get("file_path")
        if symbol_id and not valid_symbol_id(symbol_id):
            return invalid_request(
                code="invalid_symbol_id",
                path="symbol_id",
                message="symbol_id must be passed unchanged from search_code",
            )
        if bool(symbol_id) == bool(file_path):
            return invalid_request(
                code="exclusive_source_required",
                path="symbol_id",
                message="exactly one of symbol_id or file_path is required",
            )
        if file_path and arguments.get("start_line") is None:
            return invalid_request(
                code="missing_file_range",
                path="start_line",
                message="start_line is required when file_path is provided",
            )
        if file_path:
            path_error = project_relative_path_error(file_path)
            if path_error:
                return invalid_request(
                    code="invalid_project_path",
                    path="file_path",
                    message=path_error,
                )
        start = arguments.get("start_line")
        end = arguments.get("end_line")
        if start is not None and end is not None and end < start:
            return invalid_request(
                code="invalid_line_range",
                path="end_line",
                message="end_line must be greater than or equal to start_line",
            )
        return None

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        max_lines = int(arguments.get("max_lines", 200))
        if arguments.get("file_path"):
            return self._read_file(
                str(arguments["file_path"]),
                int(arguments["start_line"]),
                arguments.get("end_line"),
                max_lines,
                symbol=None,
                definition_end=None,
                origin="source",
            )

        identifier = str(arguments.get("symbol_id") or "")
        record = self.catalog.resolve(identifier)
        if record is None:
            return tool_result(
                status="not_found",
                data=None,
                providers=list(self.catalog.snapshot().providers),
                next_actions=["Run search_code again and pass the returned symbol_id unchanged."],
                warnings=["The symbol ID may belong to an older index revision."],
            )
        if record["kind"] == "external":
            return tool_result(
                data={
                    "symbol": public_symbol(record),
                    "source": None,
                    "definition": {
                        "complete": False,
                        "origin": "user_config",
                        "contract": dict(record.get("raw") or {}),
                    },
                },
                providers=["user_config"],
                coverage_level="partial",
                missing=["source"],
            )

        definition_start = int(record.get("start_line") or 1)
        definition_end = int(record.get("end_line") or definition_start)
        if record["kind"] == "global" and definition_end <= definition_start:
            definition_end, complete = self._scan_global_end(
                str(record.get("file") or ""), definition_start
            )
        else:
            complete = definition_end >= definition_start
        start = int(arguments.get("start_line") or definition_start)
        if start < definition_start or start > definition_end:
            return invalid_request(
                code="line_outside_symbol",
                path="start_line",
                message=(
                    f"start_line must be within the symbol definition "
                    f"({definition_start}-{definition_end})"
                ),
            )
        requested_end = arguments.get("end_line")
        if requested_end is None:
            requested_end = definition_end
        elif int(requested_end) > definition_end:
            return invalid_request(
                code="line_outside_symbol",
                path="end_line",
                message=f"end_line must not exceed definition end line {definition_end}",
            )
        result = self._read_file(
            str(record.get("file") or ""),
            start,
            int(requested_end),
            max_lines,
            symbol=public_symbol(record),
            definition_end=definition_end,
            origin=str(record.get("origin") or "unknown"),
            definition_complete=complete,
        )
        if (
            result.get("success")
            and record["kind"] == "macro"
            and isinstance(result.get("data"), dict)
        ):
            result["data"]["macro"] = record.get("macro")
        if (
            result.get("success")
            and record["kind"] == "type"
            and isinstance(result.get("data"), dict)
        ):
            details = None
            finder = getattr(self.code_index, "find_type_infos", None)
            if callable(finder):
                type_name = str(record.get("qualified_name") or record["name"])
                matches = list(finder(type_name, file_path=str(record.get("file") or "")) or [])
                if not matches and type_name != record["name"]:
                    matches = list(
                        finder(record["name"], file_path=str(record.get("file") or "")) or []
                    )
                exact = [
                    item
                    for item in matches
                    if int(item.get("start_line") or item.get("lineNumber") or 0)
                    == int(record.get("start_line") or 0)
                ]
                if len(exact) == 1:
                    details = exact[0]
            if details is None:
                details = self.code_index.get_type_info(
                    str(record.get("qualified_name") or record["name"])
                )
                if details is None and record.get("qualified_name") != record["name"]:
                    details = self.code_index.get_type_info(record["name"])
            if isinstance(details, dict):
                result["data"]["members"] = details.get("members") or []
        return result

    def _read_file(
        self,
        file_path: str,
        start_line: int,
        end_line: Optional[int],
        max_lines: int,
        *,
        symbol: Optional[Dict[str, Any]],
        definition_end: Optional[int],
        origin: str,
        definition_complete: bool = True,
    ) -> Dict[str, Any]:
        requested_end = end_line
        if requested_end is None and definition_end is None:
            # File-range mode without an explicit end means "read forward".
            # Ask CodeIndex for the real EOF target so its max_lines bound can
            # report an honest continuation rather than a seemingly complete
            # fixed-size window.
            requested_end = 2_147_483_647
        snippet = self.code_index.get_file_snippet(
            file_path,
            start_line,
            requested_end,
            max_lines=max_lines,
            default_max_lines=max_lines,
        )
        if not snippet:
            return tool_result(
                status="not_found",
                data=None,
                providers=[origin],
                next_actions=["Verify the project-relative path or run search_code again."],
            )
        truncated = bool(snippet.get("truncated")) or (
            definition_end is not None and int(snippet.get("end_line") or 0) < definition_end
        )
        source = {
            "file": snippet.get("file"),
            "start_line": snippet.get("start_line"),
            "end_line": snippet.get("end_line"),
            "code": snippet.get("code") or "",
            "definition_end_line": definition_end,
            "total_file_lines": snippet.get("total_lines"),
            "truncated": truncated,
            "next_start_line": int(snippet.get("end_line") or 0) + 1 if truncated else None,
        }
        data: Dict[str, Any] = {
            "symbol": symbol,
            "source": source,
            "definition": {
                "complete": bool(definition_complete and not truncated),
                "origin": origin,
            },
        }
        return tool_result(
            status="partial" if truncated or not definition_complete else "ok",
            data=data,
            providers=[origin],
            missing=["definition_end"] if not definition_complete else [],
            next_actions=(
                [
                    f"Continue with start_line={source['next_start_line']} and the same symbol_id or file_path."
                ]
                if truncated
                else []
            ),
        )

    def _scan_global_end(self, file_path: str, start_line: int) -> Tuple[int, bool]:
        resolved = self.code_index.resolve_existing_file(file_path)
        if resolved is None:
            return start_line, False
        lines = self.code_index._read_file_lines(resolved)
        quote = ""
        escaped = False
        block_comment = False
        for line_number in range(start_line, min(len(lines), start_line + 499) + 1):
            line = lines[line_number - 1]
            index = 0
            while index < len(line):
                char = line[index]
                nxt = line[index + 1] if index + 1 < len(line) else ""
                if block_comment:
                    if char == "*" and nxt == "/":
                        block_comment = False
                        index += 2
                        continue
                elif quote:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == quote:
                        quote = ""
                elif char == "/" and nxt == "*":
                    block_comment = True
                    index += 2
                    continue
                elif char == "/" and nxt == "/":
                    break
                elif char in {"'", '"'}:
                    quote = char
                elif char == ";":
                    return line_number, True
                index += 1
        return min(len(lines), start_line + 499), False
