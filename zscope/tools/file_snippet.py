from typing import Any, Dict, Optional, TYPE_CHECKING

from ..framework.base import BaseTool

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

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        file_path = str(arguments.get("file_path") or "")
        start = arguments.get("start_line")
        end = arguments.get("end_line")
        result = self.code_index.get_file_snippet(file_path, start, end)
        if result is None:
            return {"success": False, "error": "Failed to read file"}
        return {"success": True, "data": result}

    def validate_arguments(self, arguments: Any) -> Optional[Dict[str, Any]]:
        error = super().validate_arguments(arguments)
        if error:
            return error
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
        if start_line < 1 or start_line > total_lines:
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
