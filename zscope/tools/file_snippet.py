from typing import Any, Dict, Optional, TYPE_CHECKING

from ..framework.base import BaseTool
from .source_access import ProjectSourceAccess, SourceAccessError, source_lines

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class GetFileSnippetTool(BaseTool):
    """Tool to retrieve file snippets."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_file_snippet",
            description=(
                "Read an inclusive 1-based line range from a source file for exact "
                "evidence. Use this only when the existing entry code, function "
                "snapshot, or an earlier snippet does not already contain the needed "
                "lines. Do not repeat the same or covered line range; use the prior "
                "tool result directly. If more context is needed, request one wider "
                "range instead of several overlapping ranges. A valid end_line returns "
                "up to 500 lines; an end_line past the end of the file reads to the "
                "end of the file (up to 500 lines); an omitted or invalid end_line "
                "returns up to 50 lines. The result reports total_lines and truncated "
                "so you always know whether the file continues past end_line."
            ),
        )
        self.code_index = code_index
        self.source_access = ProjectSourceAccess.for_index(code_index)

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = str(arguments.get("file_path") or "")
        start = arguments.get("start_line")
        end = arguments.get("end_line")
        if self.source_access is not None:
            if start is None:
                return {"success": False, "error": "start_line must be an integer"}
            try:
                start = int(start)
            except (TypeError, ValueError, OverflowError):
                return {"success": False, "error": "start_line must be an integer"}
            if start < 1:
                return {"success": False, "error": "start_line must be positive"}
            # Read through the pinned project boundary, not a check-then-index read.
            try:
                text, _, _ = self.source_access.read(file_path)
            except SourceAccessError as exc:
                return {
                    "success": False,
                    "error": "Source file is unavailable",
                    "reason": exc.reason,
                }
            lines = source_lines(text)
            total = len(lines)
            try:
                end = int(end) if end is not None else None
            except (TypeError, ValueError, OverflowError):
                end = None
            if start > max(1, total):
                return {"success": False, "error": "start_line is outside this source file"}
            desired_end = start + 49 if end is None or end < start else min(end, total)
            stop = min(desired_end, start + 499, total)
            return {
                "success": True,
                "data": {
                    "file": file_path.replace("\\", "/"),
                    "start_line": start,
                    "end_line": stop,
                    "code": "".join(
                        f"{number} | {line}"
                        for number, line in enumerate(lines[start - 1 : stop], start)
                    ),
                    "total_lines": total,
                    "truncated": bool(total and stop < desired_end),
                },
            }
        result = self.code_index.get_file_snippet(file_path, start, end)
        if result is None:
            return {"success": False, "error": "Failed to read file"}
        return {"success": True, "data": result}

    def validate_arguments(self, arguments: Any) -> Optional[Dict[str, Any]]:
        error = super().validate_arguments(arguments)
        if error:
            return error
        if self.source_access is not None:
            try:
                self.source_access.identity(arguments["file_path"])
            except SourceAccessError as exc:
                return {
                    "success": False,
                    "error": "Source file is unavailable",
                    "reason": exc.reason,
                }
            return None
        file_path = str(arguments.get("file_path") or "")
        resolved = self.code_index.resolve_existing_file(file_path)
        if not resolved:
            return {
                "success": False,
                "error": (
                    "get_file_snippet requires an existing file path. "
                    f"'{file_path}' was not found; please correct the path and retry."
                ),
            }
        start_line = int(arguments["start_line"])
        total_lines = self.code_index.get_file_line_count(resolved)
        if total_lines is None:
            return {
                "success": False,
                "error": f"Failed to determine line count for '{file_path}'.",
            }
        if start_line < 1 or start_line > max(1, total_lines):
            return {
                "success": False,
                "error": (
                    f"'start_line' {start_line} is out of range for '{file_path}'. "
                    "Please correct the line range and retry."
                ),
            }
        return None

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Project-relative source path, for example src/main.c.",
                        },
                        "start_line": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Inclusive 1-based first line to read.",
                        },
                        "end_line": {
                            "type": "integer",
                            "description": (
                                "Optional inclusive 1-based last line to read. "
                                "A valid range returns up to 500 lines; an end_line "
                                "past the end of the file reads to the end of the "
                                "file (up to 500 lines); an omitted or invalid "
                                "end_line returns up to 50 lines."
                            ),
                        },
                    },
                    "required": ["file_path", "start_line"],
                },
            },
        }
