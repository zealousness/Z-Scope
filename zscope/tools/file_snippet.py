from typing import Any, Dict, TYPE_CHECKING

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
                "range instead of several overlapping ranges."
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
                                "Inclusive 1-based last line to read. If omitted or "
                                "before start_line, the tool returns up to 200 lines."
                            ),
                        },
                    },
                    "required": [],
                },
            },
        }
