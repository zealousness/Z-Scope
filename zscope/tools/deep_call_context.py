from typing import Any, Dict, TYPE_CHECKING

from ..framework.base import BaseTool

if TYPE_CHECKING:
    from ..retrieval.code_index import CodeIndex


class GetDeepCallContextTool(BaseTool):
    """Tool returning a compact aggregate of calls, indirect calls, and taint hints."""

    CALLERS_LIMIT = 20
    CALLEES_LIMIT = 30
    INDIRECT_LIMIT = 20
    TAINT_LIMIT = 20

    def __init__(self, code_index: "CodeIndex"):
        super().__init__(
            name="get_deep_call_context",
            description=(
                "Get callers, callees, indirect callees, taint hints, and method info "
                "in one call. Taint hints are a project-wide sample, not filtered "
                "to this function. Each section is capped at a fixed row limit; when a "
                "section is cut short the result sets truncated=true and lists the "
                "affected truncated_sections."
            ),
        )
        self.code_index = code_index

    def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        func_name = arguments.get("func_name", "")
        backend = getattr(self.code_index, "backend", None)
        # Fetch one extra row per section so hitting the cap is detectable and
        # reported instead of silently dropping rows beyond the cap.
        probe = 1
        raw_callers = self.code_index.get_callers(func_name, limit=self.CALLERS_LIMIT + probe)
        raw_callees = self.code_index.get_callees(func_name, limit=self.CALLEES_LIMIT + probe)
        raw_indirect = (
            backend.get_indirect_callees(func_name, limit=self.INDIRECT_LIMIT + probe)
            if backend and hasattr(backend, "get_indirect_callees")
            else []
        )
        raw_taint = (
            backend.get_taint_bugs(limit=self.TAINT_LIMIT + probe)
            if backend and hasattr(backend, "get_taint_bugs")
            else []
        )
        method = (
            backend.get_method(func_name) if backend and hasattr(backend, "get_method") else None
        )
        sections = {
            "callers": raw_callers[: self.CALLERS_LIMIT],
            "callees": raw_callees[: self.CALLEES_LIMIT],
            "indirect_callees": raw_indirect[: self.INDIRECT_LIMIT],
            "taint_bugs": raw_taint[: self.TAINT_LIMIT],
        }
        data: Dict[str, Any] = {
            "function": func_name,
            "method_info": method,
            "taint_scope": "project",
            **sections,
        }
        unavailable = [
            section
            for section, method_name in (
                ("indirect_callees", "get_indirect_callees"),
                ("taint_bugs", "get_taint_bugs"),
                ("method_info", "get_method"),
            )
            if backend is None or not hasattr(backend, method_name)
        ]
        if unavailable:
            data["unavailable_sections"] = unavailable
        truncated_sections = sorted(
            section
            for section, rows in (
                ("callers", raw_callers),
                ("callees", raw_callees),
                ("indirect_callees", raw_indirect),
                ("taint_bugs", raw_taint),
            )
            if len(rows) > len(sections[section])
        )
        if truncated_sections:
            data["truncated"] = True
            data["truncated_sections"] = truncated_sections
            data["note"] = (
                "These sections were cut at their row limits: "
                + ", ".join(truncated_sections)
                + ". These are bounded samples; omitted rows are not evidence of absence."
            )
        return {"success": True, "data": data}

    def get_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {"func_name": {"type": "string"}},
                    "required": ["func_name"],
                },
            },
        }
