from copy import deepcopy
from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..config.user_config_store import UserConfigStore
    from ..retrieval.code_index import CodeIndex


class GetFunctionInfoTool(BaseTool):
    """Tool to retrieve structured function identity and call metadata."""

    _OMITTED_MATCH_FIELDS = frozenset(
        {
            "referenced_globals",
            "referenced_macros",
            "referenced_types",
            "referenced_globals_truncation",
            "referenced_macros_truncation",
            "referenced_types_truncation",
            "unresolved_referenced_types",
        }
    )

    def __init__(
        self,
        code_index: "CodeIndex",
        user_config: "UserConfigStore | None" = None,
    ):
        super().__init__(
            name="get_function_info",
            description=(
                "Retrieve function identity and project/external callee metadata by name, "
                "optionally scoped by file path. Function-like macro matches additionally "
                "return complete definition code. The result does not include referenced "
                "globals, macros, types, or their truncation metadata. If a supplied file_path "
                "has no matches, the tool retries once without file_path, returns all unscoped "
                "matches, and reports file_path_fallback."
            ),
        )
        self.code_index = code_index
        self.user_config = user_config

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = str(arguments.get("func_name") or "").strip()
        if not func_name:
            return {"success": False, "error": "Function name is empty"}

        file_path = arguments.get("file_path") or ""
        if not isinstance(file_path, str):
            return {"success": False, "error": "file_path must be a string"}

        find_metadata = getattr(self.code_index, "find_function_metadata", None)
        if find_metadata is None:
            find_metadata = self.code_index.find_function_infos
        matches = find_metadata(
            func_name,
            file_path=file_path,
        )
        file_path_fallback = None
        if not matches and file_path:
            matches = find_metadata(func_name, file_path="")
            if matches:
                file_path_fallback = {
                    "reason": "file_path_not_matched",
                    "requested_file_path": file_path,
                    "message": (
                        "The supplied file_path did not match the requested function. "
                        "The following matches are results from a query without file_path."
                    ),
                }
        if not matches:
            external_name = self.code_index.fallback_function_name(func_name) or func_name
            if self.user_config:
                ext = self.user_config.get_external_function(external_name)
                if ext:
                    matches = [
                        {
                            "function_name": external_name,
                            "file_path": "[external]",
                            "start_line": 0,
                            "end_line": 0,
                            "signature": f"{external_name}(...)",
                            "code": (
                                f"/* 外部函数 (来自 {ext.get('library', '未知库')})\n"
                                f" * 描述: {ext['description']}\n"
                                f" * 内存行为: {ext.get('memory_behavior', '{}')}\n"
                                f" * 并发行为: {ext.get('concurrency_behavior', '{}')}\n"
                                f" * 返回语义: {ext.get('return_semantics', '')}\n"
                                " */"
                            ),
                            "project_callees": [],
                            "external_callees": [],
                            "referenced_globals": [],
                            "referenced_macros": [],
                            "referenced_types": [],
                            "is_external": True,
                        }
                    ]
                else:
                    self.user_config.add_config_warning(
                        "missing_external_func",
                        external_name,
                        f"函数 '{external_name}' 的实现未找到，且无用户提供的外部函数描述。",
                    )
            if not matches:
                return {
                    "success": False,
                    "error": f"Function '{external_name}' not found",
                }

        public_matches = [
            {
                key: deepcopy(value)
                for key, value in match.items()
                if key not in self._OMITTED_MATCH_FIELDS
            }
            for match in matches
        ]
        result = {
            "success": True,
            "data": {
                "match_count": len(public_matches),
                "matches": public_matches,
            },
        }
        if file_path_fallback is not None:
            result["file_path_fallback"] = file_path_fallback
        return result

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "func_name": {
                            "type": "string",
                            "description": "Function name, qualified name, or index_name for exact match.",
                        },
                        "file_path": {
                            "type": "string",
                            "description": (
                                "Optional source file path used to disambiguate same-name functions. "
                                "If it has no matches, the tool retries once without this filter."
                            ),
                        },
                    },
                    "required": ["func_name"],
                },
            },
        }
