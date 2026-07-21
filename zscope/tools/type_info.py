from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class GetTypeInfoTool(BaseTool):
    """Tool to retrieve source-backed type definitions."""

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_type_info",
            description=(
                "Retrieve every matching struct, union, enum, typedef, or class source "
                "definition. Use file_path to disambiguate same-name types when the "
                "declaration file is known."
            ),
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        type_name = str(arguments.get("type_name") or "").strip()
        if not type_name:
            return {"success": False, "error": "Type name is empty"}

        file_path = arguments.get("file_path") or ""
        if not isinstance(file_path, str):
            return {"success": False, "error": "file_path must be a string"}

        raw_matches = self.code_index.find_type_infos(
            type_name,
            file_path=file_path,
        )
        matches = []
        for raw_match in raw_matches:
            if not isinstance(raw_match, dict):
                continue
            match = dict(raw_match)
            match.pop("id", None)
            match.pop("tu_id", None)
            match.pop("members", None)
            matches.append(match)
        if not matches:
            return {"success": False, "error": f"Type '{type_name}' not found"}
        return {
            "success": True,
            "data": {
                "match_count": len(matches),
                "matches": matches,
            },
        }

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "type_name": {
                            "type": "string",
                            "description": "Struct, union, enum, typedef, class, or qualified type name.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": "Optional source or header path used to disambiguate same-name types.",
                        },
                    },
                    "required": ["type_name"],
                },
            },
        }
